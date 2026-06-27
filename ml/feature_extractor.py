"""
feature_extractor.py - ML Feature Extraction
============================================
Small adapter layer that turns completed flow records into feature rows.
Keeping this separate from the flow generator lets future ML code add
normalization, encoding, or labels without touching packet processing.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable

from .flow_generator import FlowGenerator, FlowRecord

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """Prepare flow records for CSV export or model inference."""

    def __init__(self, flow_generator: FlowGenerator | None = None) -> None:
        self.flow_generator = flow_generator or FlowGenerator(auto_cleanup=False)

    def extract_from_records(
        self,
        records: Iterable[FlowRecord],
    ) -> list[dict[str, int | float | str]]:
        """Convert completed flow records into plain ML feature rows."""
        features = [record.as_dict() for record in records]
        logger.debug("Extracted %d flow feature rows", len(features))
        return features

    def extract_completed(self, consume: bool = False) -> list[dict[str, int | float | str]]:
        """
        Extract features from completed flows.

        Set ``consume=True`` for batch inference pipelines that should clear
        already-read records after handing them to the model.
        """
        records = (
            self.flow_generator.pop_completed_flows()
            if consume
            else self.flow_generator.get_completed_flows()
        )
        return self.extract_from_records(records)

    def export_completed_to_csv(self, path: str | Path, consume: bool = False) -> int:
        """Export completed flows through the shared CSV schema."""
        records = (
            self.flow_generator.pop_completed_flows()
            if consume
            else self.flow_generator.get_completed_flows()
        )
        return self.flow_generator.export_csv(path, flows=records)
