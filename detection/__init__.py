"""Rule-based detection package for AI-IDS."""

from detection.config import DetectionConfig
from detection.rule_engine import Alert, RuleEngine

__all__ = ["Alert", "DetectionConfig", "RuleEngine"]
