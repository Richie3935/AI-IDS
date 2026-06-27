"""
Machine-learning preparation utilities for AI-IDS.

The package currently exposes flow generation and feature extraction.
Raw packet metadata enters through ``FlowGenerator.process_packet()`` and
completed flows leave as plain dictionaries that can be written to CSV or
passed directly to a future ML model.
"""

from .feature_extractor import FeatureExtractor
from .flow_generator import Flow, FlowGenerator, FlowKey, FlowRecord

__all__ = [
    "FeatureExtractor",
    "Flow",
    "FlowGenerator",
    "FlowKey",
    "FlowRecord",
]
