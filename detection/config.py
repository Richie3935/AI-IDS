"""
detection.config - Rule engine thresholds for AI-IDS.

Keep operational thresholds in this module so detection behavior can be
tuned without touching the rule implementation.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class DetectionConfig:
    """Configuration values for rule-based intrusion detection."""

    port_scan_window_seconds: int = 60
    port_scan_unique_ports: int = 10
    port_scan_alert_cooldown_seconds: int = 60

    syn_flood_window_seconds: int = 10
    syn_flood_packet_threshold: int = 100
    syn_flood_alert_cooldown_seconds: int = 30

    icmp_flood_window_seconds: int = 10
    icmp_flood_packet_threshold: int = 50
    icmp_flood_alert_cooldown_seconds: int = 30

    default_alert_severity: str = "MEDIUM"
    port_scan_severity: str = "HIGH"
    syn_flood_severity: str = "CRITICAL"
    icmp_flood_severity: str = "HIGH"

    def __post_init__(self) -> None:
        """Validate thresholds early so the IDS fails fast on bad config."""
        positive_int_fields = {
            "port_scan_window_seconds": self.port_scan_window_seconds,
            "port_scan_unique_ports": self.port_scan_unique_ports,
            "port_scan_alert_cooldown_seconds": self.port_scan_alert_cooldown_seconds,
            "syn_flood_window_seconds": self.syn_flood_window_seconds,
            "syn_flood_packet_threshold": self.syn_flood_packet_threshold,
            "syn_flood_alert_cooldown_seconds": self.syn_flood_alert_cooldown_seconds,
            "icmp_flood_window_seconds": self.icmp_flood_window_seconds,
            "icmp_flood_packet_threshold": self.icmp_flood_packet_threshold,
            "icmp_flood_alert_cooldown_seconds": self.icmp_flood_alert_cooldown_seconds,
        }

        for field_name, value in positive_int_fields.items():
            if not isinstance(value, int) or value < 1:
                raise ValueError(f"{field_name} must be a positive integer")

        severity_fields = {
            "default_alert_severity": self.default_alert_severity,
            "port_scan_severity": self.port_scan_severity,
            "syn_flood_severity": self.syn_flood_severity,
            "icmp_flood_severity": self.icmp_flood_severity,
        }

        for field_name, value in severity_fields.items():
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")
