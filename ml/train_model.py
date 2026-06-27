"""
ml/train_model.py - Model Training Pipeline for AI-IDS v7
==========================================================
Loads the CICIDS2017 MachineLearningCSV dataset, filters to the three
target classes, extracts the five flow features used by the live
FlowGenerator, trains a Random Forest classifier with cross-validation,
and saves the trained model to ml/model.pkl.

Usage
-----
    python ml/train_model.py
    python ml/train_model.py --dataset-dir datasets/ --output ml/model.pkl
    python ml/train_model.py --n-estimators 200 --max-depth 20

Author : AI-IDS Project — Version 7
Python : 3.11+
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.preprocessing import LabelEncoder

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Dataset constants
# ---------------------------------------------------------------------------

# CICIDS2017 CSV column names — strip leading/trailing whitespace on load
_LABEL_COLUMN = "Label"

# The five features produced by ml/flow_generator.py  →  matching CICIDS2017 columns
FEATURE_MAP: dict[str, str] = {
    "flow_duration":       "Flow Duration",
    "packet_count":        "Total Fwd Packets",      # forward packets used as proxy
    "byte_count":          "Total Length of Fwd Packets",
    "packets_per_second":  "Flow Packets/s",
    "bytes_per_second":    "Flow Bytes/s",
}

# Keep only these three broad class groups
_CLASS_MAP: dict[str, str] = {
    "BENIGN":             "BENIGN",
    "PortScan":           "PortScan",
    "DoS Hulk":           "DoS",
    "DoS GoldenEye":      "DoS",
    "DoS Slowloris":      "DoS",
    "DoS SlowHTTPTest":   "DoS",
}

FEATURE_COLUMNS = list(FEATURE_MAP.values())   # CICIDS2017 column names used during training
MODEL_FEATURE_ORDER = list(FEATURE_MAP.keys())  # order expected by AIEngine at inference time


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_dataset(dataset_dir: Path) -> pd.DataFrame:
    """
    Load and concatenate all CICIDS2017 CSV files from *dataset_dir*.

    Strips whitespace from column names (the CICIDS2017 dataset ships with
    leading spaces on many column headers) and filters rows to the three
    target label groups defined in ``_CLASS_MAP``.

    Parameters
    ----------
    dataset_dir : Path
        Directory containing the eight CICIDS2017 CSV files.

    Returns
    -------
    pd.DataFrame
        Combined, filtered dataframe with a clean ``Label`` column.
    """
    csv_files = sorted(dataset_dir.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in {dataset_dir}. "
            "Download the CICIDS2017 MachineLearningCSV dataset and place it there."
        )

    logger.info("Found %d CSV file(s) in %s", len(csv_files), dataset_dir)

    frames: list[pd.DataFrame] = []
    for csv_path in csv_files:
        logger.info("Loading %s …", csv_path.name)
        try:
            df = pd.read_csv(csv_path, low_memory=False)
        except Exception as exc:
            logger.warning("Skipping %s — read error: %s", csv_path.name, exc)
            continue

        # Normalise column names (strip surrounding whitespace)
        df.columns = [col.strip() for col in df.columns]

        if _LABEL_COLUMN not in df.columns:
            logger.warning("Skipping %s — '%s' column not found", csv_path.name, _LABEL_COLUMN)
            continue

        df[_LABEL_COLUMN] = df[_LABEL_COLUMN].astype(str).str.strip()
        frames.append(df)

    if not frames:
        raise ValueError("No valid CSV files could be loaded from the dataset directory.")

    combined = pd.concat(frames, ignore_index=True)
    logger.info("Total rows loaded (all labels): %d", len(combined))

    # Map raw labels to the three target classes; drop everything else
    combined["label_mapped"] = combined[_LABEL_COLUMN].map(_CLASS_MAP)
    combined = combined[combined["label_mapped"].notna()].copy()
    logger.info("Rows after class filtering: %d", len(combined))

    label_counts = combined["label_mapped"].value_counts()
    for label, count in label_counts.items():
        logger.info("  %-12s  %d rows", label, count)

    return combined


# ---------------------------------------------------------------------------
# Preprocessing
# ---------------------------------------------------------------------------

def preprocess(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, LabelEncoder]:
    """
    Extract features and encode labels.

    Replaces infinite values with NaN, fills remaining NaN with column
    medians, and clips extreme outliers at the 99.9th percentile to keep
    the Random Forest robust to the noise common in network captures.

    Parameters
    ----------
    df : pd.DataFrame
        Combined filtered dataframe from :func:`load_dataset`.

    Returns
    -------
    X : np.ndarray  shape (n_samples, 5)
    y : np.ndarray  shape (n_samples,)   — integer-encoded labels
    encoder : LabelEncoder               — fitted encoder for class names
    """
    missing = [col for col in FEATURE_COLUMNS if col not in df.columns]
    if missing:
        raise KeyError(
            f"Dataset is missing required columns: {missing}. "
            "Check that the CICIDS2017 MachineLearningCSV dataset is being used."
        )

    X_raw = df[FEATURE_COLUMNS].copy()

    # Replace ±inf with NaN then fill with column medians
    X_raw.replace([np.inf, -np.inf], np.nan, inplace=True)
    X_raw.fillna(X_raw.median(numeric_only=True), inplace=True)

    # Clip extreme outliers (preserves the distribution shape)
    for col in FEATURE_COLUMNS:
        upper = X_raw[col].quantile(0.999)
        X_raw[col] = X_raw[col].clip(upper=upper)

    X = X_raw.to_numpy(dtype=np.float32)

    encoder = LabelEncoder()
    y = encoder.fit_transform(df["label_mapped"].to_numpy())

    logger.info(
        "Feature matrix: %s | Classes: %s",
        X.shape,
        list(encoder.classes_),
    )
    return X, y, encoder


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def train(
    X: np.ndarray,
    y: np.ndarray,
    n_estimators: int = 100,
    max_depth: int | None = None,
    random_state: int = 42,
    cv_folds: int = 5,
) -> tuple[RandomForestClassifier, dict[str, float]]:
    """
    Train a Random Forest classifier with stratified cross-validation.

    The dataset is first split 80/20 for train/test evaluation. Cross-
    validation runs on the training split only so the held-out test set
    remains a true unbiased estimate of generalisation performance.

    Parameters
    ----------
    X, y : feature matrix and label array from :func:`preprocess`.
    n_estimators : number of trees in the forest.
    max_depth : maximum tree depth (``None`` = unlimited).
    random_state : seed for reproducibility.
    cv_folds : number of stratified k-folds for cross-validation.

    Returns
    -------
    model : fitted RandomForestClassifier
    metrics : dict with accuracy, precision, recall, f1_weighted
    """
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=random_state, stratify=y
    )
    logger.info(
        "Train/test split — train: %d  test: %d", len(X_train), len(X_test)
    )

    model = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        n_jobs=-1,
        random_state=random_state,
        class_weight="balanced",
    )

    # Cross-validation on training data
    logger.info("Running %d-fold stratified cross-validation …", cv_folds)
    skf = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=random_state)
    cv_scores = cross_val_score(model, X_train, y_train, cv=skf, scoring="f1_weighted", n_jobs=-1)
    logger.info(
        "CV F1-weighted: %.4f ± %.4f (per fold: %s)",
        cv_scores.mean(),
        cv_scores.std(),
        " ".join(f"{s:.4f}" for s in cv_scores),
    )

    # Final fit on full training split
    logger.info("Fitting final model on full training split …")
    t0 = time.perf_counter()
    model.fit(X_train, y_train)
    elapsed = time.perf_counter() - t0
    logger.info("Training complete in %.1f s", elapsed)

    # Evaluate on held-out test set
    y_pred = model.predict(X_test)
    metrics = {
        "accuracy":  accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred, average="weighted", zero_division=0),
        "recall":    recall_score(y_test, y_pred, average="weighted", zero_division=0),
        "f1":        f1_score(y_test, y_pred, average="weighted", zero_division=0),
        "cv_f1_mean": float(cv_scores.mean()),
        "cv_f1_std":  float(cv_scores.std()),
    }

    logger.info("Test set results:")
    logger.info("  Accuracy : %.4f", metrics["accuracy"])
    logger.info("  Precision: %.4f", metrics["precision"])
    logger.info("  Recall   : %.4f", metrics["recall"])
    logger.info("  F1       : %.4f", metrics["f1"])

    return model, metrics, X_test, y_test


def _print_report(
    model: RandomForestClassifier,
    X_test: np.ndarray,
    y_test: np.ndarray,
    encoder: LabelEncoder,
    metrics: dict[str, float],
) -> None:
    """Print a formatted evaluation report to stdout."""
    y_pred = model.predict(X_test)
    target_names = list(encoder.classes_)

    separator = "═" * 62
    print(f"\n{separator}")
    print("  AI-IDS v7 — Model Training Report")
    print(separator)
    print(f"  Accuracy  : {metrics['accuracy']:.4f}")
    print(f"  Precision : {metrics['precision']:.4f}  (weighted)")
    print(f"  Recall    : {metrics['recall']:.4f}  (weighted)")
    print(f"  F1 Score  : {metrics['f1']:.4f}  (weighted)")
    print(f"  CV F1     : {metrics['cv_f1_mean']:.4f} ± {metrics['cv_f1_std']:.4f}")
    print(separator)
    print("\nClassification Report:\n")
    print(classification_report(y_test, y_pred, target_names=target_names, zero_division=0))
    print("Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    header = "  ".join(f"{n:>10}" for n in target_names)
    print(f"{'':>12}  {header}")
    for i, row in enumerate(cm):
        row_str = "  ".join(f"{v:>10}" for v in row)
        print(f"{target_names[i]:>12}  {row_str}")
    print(f"\n{separator}\n")


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save_model(
    model: RandomForestClassifier,
    encoder: LabelEncoder,
    output_path: Path,
) -> None:
    """
    Persist model and label encoder together as a single joblib artifact.

    The bundle dictionary keeps the encoder alongside the model so
    :class:`~ml.ai_engine.AIEngine` can decode integer predictions back
    to human-readable class names without any external state.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    bundle = {
        "model": model,
        "encoder": encoder,
        "feature_order": MODEL_FEATURE_ORDER,
        "feature_columns": FEATURE_COLUMNS,
        "class_map": _CLASS_MAP,
    }
    joblib.dump(bundle, output_path)
    logger.info("Model bundle saved to %s", output_path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="train_model",
        description="Train the AI-IDS v7 Random Forest classifier on CICIDS2017 data.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ml/train_model.py
  python ml/train_model.py --dataset-dir datasets/ --output ml/model.pkl
  python ml/train_model.py --n-estimators 200 --max-depth 20 --cv-folds 10
""",
    )
    parser.add_argument(
        "--dataset-dir",
        default="datasets/",
        metavar="DIR",
        help="Directory containing CICIDS2017 CSV files (default: datasets/)",
    )
    parser.add_argument(
        "--output",
        default="ml/model.pkl",
        metavar="PATH",
        help="Output path for the trained model bundle (default: ml/model.pkl)",
    )
    parser.add_argument(
        "--n-estimators",
        type=int,
        default=100,
        metavar="N",
        help="Number of trees in the Random Forest (default: 100)",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=None,
        metavar="N",
        help="Maximum tree depth — None for unlimited (default: None)",
    )
    parser.add_argument(
        "--cv-folds",
        type=int,
        default=5,
        metavar="K",
        help="Number of stratified k-fold CV splits (default: 5)",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        metavar="SEED",
        help="Random seed for reproducibility (default: 42)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    """Entry point for the training pipeline."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )

    dataset_dir = Path(args.dataset_dir)
    output_path = Path(args.output)

    logger.info("=== AI-IDS v7 Model Training Pipeline ===")
    logger.info("Dataset dir : %s", dataset_dir.resolve())
    logger.info("Output path : %s", output_path.resolve())

    # --- Load ---------------------------------------------------------------
    df = load_dataset(dataset_dir)

    # --- Preprocess ---------------------------------------------------------
    X, y, encoder = preprocess(df)

    # --- Train --------------------------------------------------------------
    model, metrics, X_test, y_test = train(
        X,
        y,
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        random_state=args.random_state,
        cv_folds=args.cv_folds,
    )

    # --- Report -------------------------------------------------------------
    _print_report(model, X_test, y_test, encoder, metrics)

    # --- Save ---------------------------------------------------------------
    save_model(model, encoder, output_path)
    print(f"[✔] Model saved to {output_path.resolve()}")


if __name__ == "__main__":
    main()