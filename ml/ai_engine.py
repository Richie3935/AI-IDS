"""
ml/ai_engine.py - AI Prediction Engine for AI-IDS v7
=====================================================
Loads the trained Random Forest model bundle (ml/model.pkl) produced by
ml/train_model.py and provides real-time attack classification for
completed flow records emitted by the FlowGenerator.

The engine is intentionally kept stateless between predictions so it is
safe to call from multiple threads simultaneously.

Author : AI-IDS Project — Version 7
Python : 3.11+
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

import joblib
import numpy as np

logger = logging.getLogger(__name__)

# Default model path relative to the project root
_DEFAULT_MODEL_PATH = Path(__file__).resolve().parent / "model.pkl"

# Minimum confidence below which results are flagged as uncertain
_LOW_CONFIDENCE_THRESHOLD = 0.60


@dataclass(frozen=True)
class Prediction:
    """
    Result of one flow classification.

    Attributes
    ----------
    attack_type : str
        Human-readable class label — ``"BENIGN"``, ``"PortScan"``, or ``"DoS"``.
    confidence : float
        Probability of the predicted class in [0.0, 1.0].
    is_attack : bool
        ``True`` for any label other than ``"BENIGN"``.
    low_confidence : bool
        ``True`` when the confidence is below the uncertainty threshold.
    raw_probabilities : dict[str, float]
        Per-class probabilities for all known labels.
    """

    attack_type: str
    confidence: float
    is_attack: bool
    low_confidence: bool
    raw_probabilities: dict[str, float]

    def __str__(self) -> str:
        flag = "⚠ LOW-CONF" if self.low_confidence else ""
        return (
            f"Prediction(type={self.attack_type!r}, "
            f"confidence={self.confidence:.1%}{' ' + flag if flag else ''})"
        )


class AIEngine:
    """
    Thread-safe wrapper around the trained Random Forest model.

    The model bundle stored in *model_path* is a dict produced by
    :func:`ml.train_model.save_model` and contains:

    * ``model`` — fitted ``RandomForestClassifier``
    * ``encoder`` — fitted ``LabelEncoder`` mapping integers → class names
    * ``feature_order`` — list of five feature key names matching
      :class:`~ml.flow_generator.FlowRecord` attribute names

    Parameters
    ----------
    model_path : Path | str | None
        Path to the ``model.pkl`` bundle.  Defaults to ``ml/model.pkl``
        relative to this file.

    Raises
    ------
    FileNotFoundError
        If the model file does not exist.
    ValueError
        If the bundle is missing required keys.
    """

    def __init__(self, model_path: Path | str | None = None) -> None:
        resolved = Path(model_path) if model_path else _DEFAULT_MODEL_PATH
        self._model_path = resolved
        self._model = None
        self._encoder = None
        self._feature_order: list[str] = []
        self._class_names: list[str] = []
        self._available = False
        self._load_model()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def available(self) -> bool:
        """Return True if the model loaded successfully and is ready."""
        return self._available

    @property
    def class_names(self) -> list[str]:
        """Return the ordered list of class names the model was trained on."""
        return list(self._class_names)

    def predict_flow(self, flow_record) -> Prediction | None:
        """
        Classify a single completed flow record.

        Parameters
        ----------
        flow_record : FlowRecord or any object with the five flow attributes.
            Accepted attribute names (all five are required):
            ``flow_duration``, ``packet_count``, ``byte_count``,
            ``packets_per_second``, ``bytes_per_second``.

        Returns
        -------
        Prediction or None
            ``None`` when the engine is unavailable or feature extraction fails.
        """
        if not self._available:
            return None

        features = self._extract_features(flow_record)
        if features is None:
            return None

        return self._classify(features)

    def predict_batch(self, flow_records: Sequence) -> list[Prediction | None]:
        """
        Classify a batch of flow records efficiently.

        Parameters
        ----------
        flow_records : sequence of FlowRecord-like objects.

        Returns
        -------
        List of Prediction objects (or None for records that fail extraction).
        """
        if not self._available or not flow_records:
            return [None] * len(flow_records)

        rows: list[np.ndarray | None] = [
            self._extract_features(rec) for rec in flow_records
        ]

        # Build the matrix from valid rows; keep track of positions
        valid_indices = [i for i, r in enumerate(rows) if r is not None]
        if not valid_indices:
            return [None] * len(flow_records)

        matrix = np.vstack([rows[i] for i in valid_indices])
        predictions = self._classify_matrix(matrix)

        results: list[Prediction | None] = [None] * len(flow_records)
        for pred_idx, orig_idx in enumerate(valid_indices):
            results[orig_idx] = predictions[pred_idx]

        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_model(self) -> None:
        """Load the model bundle from disk."""
        if not self._model_path.exists():
            logger.warning(
                "Model file not found at %s. "
                "Run 'python ml/train_model.py' to train and save the model. "
                "The ML engine will be disabled until the model is available.",
                self._model_path,
            )
            return

        try:
            bundle = joblib.load(self._model_path)
        except Exception as exc:
            logger.error("Failed to load model bundle from %s: %s", self._model_path, exc)
            return

        required_keys = {"model", "encoder", "feature_order"}
        missing = required_keys - bundle.keys()
        if missing:
            logger.error(
                "Model bundle at %s is missing required keys: %s",
                self._model_path,
                missing,
            )
            return

        self._model = bundle["model"]
        self._encoder = bundle["encoder"]
        self._feature_order = bundle["feature_order"]
        self._class_names = list(self._encoder.classes_)
        self._available = True

        logger.info(
            "AI engine loaded model from %s — classes: %s — features: %s",
            self._model_path,
            self._class_names,
            self._feature_order,
        )

    def _extract_features(self, flow_record) -> np.ndarray | None:
        """
        Pull the five required numeric features from a flow record.

        Returns a (1, 5) float32 array, or None on any extraction failure.
        """
        try:
            values = [
                float(getattr(flow_record, feat))
                for feat in self._feature_order
            ]
        except (AttributeError, TypeError, ValueError) as exc:
            logger.debug("Feature extraction failed for flow record: %s", exc)
            return None

        arr = np.array(values, dtype=np.float32).reshape(1, -1)

        # Replace any NaN / inf with zero to prevent sklearn warnings
        arr = np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)
        return arr

    def _classify(self, features: np.ndarray) -> Prediction:
        """Run inference on a single (1, n_features) array."""
        return self._classify_matrix(features)[0]

    def _classify_matrix(self, matrix: np.ndarray) -> list[Prediction]:
        """Run batch inference on an (n, n_features) array."""
        try:
            proba_matrix: np.ndarray = self._model.predict_proba(matrix)
        except Exception as exc:
            logger.error("Model prediction failed: %s", exc)
            # Return BENIGN with zero confidence as a safe fallback
            return [
                Prediction(
                    attack_type="BENIGN",
                    confidence=0.0,
                    is_attack=False,
                    low_confidence=True,
                    raw_probabilities={c: 0.0 for c in self._class_names},
                )
                for _ in range(len(matrix))
            ]

        predictions: list[Prediction] = []
        for row_proba in proba_matrix:
            best_idx = int(np.argmax(row_proba))
            best_label = self._class_names[best_idx]
            confidence = float(row_proba[best_idx])
            raw = {self._class_names[i]: float(p) for i, p in enumerate(row_proba)}

            predictions.append(
                Prediction(
                    attack_type=best_label,
                    confidence=confidence,
                    is_attack=(best_label != "BENIGN"),
                    low_confidence=(confidence < _LOW_CONFIDENCE_THRESHOLD),
                    raw_probabilities=raw,
                )
            )

        return predictions