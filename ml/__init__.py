"""
Machine-learning preparation utilities for AI-IDS.

The package currently exposes flow generation, feature extraction, and the
AI prediction engine introduced in Version 7.

Raw packet metadata enters through ``FlowGenerator.process_packet()`` and
completed flows leave as plain dictionaries that can be written to CSV or
passed directly to the AI engine for real-time classification.
"""

from .ai_engine import AIEngine, Prediction
from .feature_extractor import FeatureExtractor
from .flow_generator import Flow, FlowGenerator, FlowKey, FlowRecord

__all__ = [
    "AIEngine",
    "FeatureExtractor",
    "Flow",
    "FlowGenerator",
    "FlowKey",
    "FlowRecord",
    "Prediction",
]