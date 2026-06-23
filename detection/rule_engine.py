"""
detection.rule_engine - Rule-based intrusion detection for AI-IDS.

The engine consumes PacketInfo objects from packet_capture.py and applies
sliding-window rules for port scans, TCP SYN floods, and ICMP floods.
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from time import monotonic
from typing import Deque

from detection.config import DetectionConfig

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Alert:
    """Immutable alert emitted by the rule engine."""

    timestamp: str
    source_ip: str
    attack_type: str
    severity: str
    details: str


class RuleEngine:
    """
    Thread-safe rule engine for signature and threshold-based detection.

    The instance is callable, so it can be registered directly with
    PacketCapture.register_callback().
    """

    def __init__(self, config: DetectionConfig | None = None) -> None:
        self._config = config or DetectionConfig()
        self._lock = threading.Lock()

        self._port_attempts: dict[str, Deque[tuple[float, int]]] = defaultdict(deque)
        self._syn_attempts: dict[str, Deque[float]] = defaultdict(deque)
        self._icmp_packets: dict[str, Deque[float]] = defaultdict(deque)
        self._last_alert_at: dict[tuple[str, str], float] = {}

        logger.info("RuleEngine initialised with config: %s", self._config)

    def __call__(self, packet_info) -> None:
        """Evaluate a packet. Exceptions are contained to protect capture."""
        try:
            self.evaluate(packet_info)
        except Exception as exc:  # pragma: no cover - defensive boundary
            logger.exception("Rule evaluation failed: %s", exc)

    def evaluate(self, packet_info) -> list[Alert]:
        """
        Evaluate one packet and return any alerts generated for it.

        PacketInfo is intentionally duck-typed to keep the engine decoupled
        from the capture module and easier to unit test.
        """
        src_ip = getattr(packet_info, "src_ip", None)
        if not src_ip:
            return []

        now = monotonic()
        alerts: list[Alert] = []

        with self._lock:
            protocol = str(getattr(packet_info, "protocol", "")).upper()

            if protocol == "TCP":
                port_scan_alert = self._detect_port_scan(packet_info, src_ip, now)
                if port_scan_alert:
                    alerts.append(port_scan_alert)

                syn_flood_alert = self._detect_syn_flood(packet_info, src_ip, now)
                if syn_flood_alert:
                    alerts.append(syn_flood_alert)

            elif protocol == "ICMP":
                icmp_alert = self._detect_icmp_flood(src_ip, now)
                if icmp_alert:
                    alerts.append(icmp_alert)

        for alert in alerts:
            self._emit_alert(alert)

        return alerts

    def _detect_port_scan(self, packet_info, src_ip: str, now: float) -> Alert | None:
        dport = getattr(packet_info, "dport", None)
        if dport is None:
            return None

        attempts = self._port_attempts[src_ip]
        attempts.append((now, int(dport)))
        self._trim_port_window(attempts, now)

        unique_ports = {port for _, port in attempts}
        if len(unique_ports) < self._config.port_scan_unique_ports:
            return None

        return self._build_alert_if_allowed(
            source_ip=src_ip,
            attack_type="Port Scan",
            severity=self._config.port_scan_severity,
            cooldown_seconds=self._config.port_scan_alert_cooldown_seconds,
            now=now,
            details=(
                f"{len(unique_ports)} unique destination ports contacted "
                f"within {self._config.port_scan_window_seconds}s"
            ),
        )

    def _detect_syn_flood(self, packet_info, src_ip: str, now: float) -> Alert | None:
        flags = str(getattr(packet_info, "flags", "") or "")
        if "S" not in flags or "A" in flags:
            return None

        attempts = self._syn_attempts[src_ip]
        attempts.append(now)
        self._trim_time_window(attempts, now, self._config.syn_flood_window_seconds)

        if len(attempts) < self._config.syn_flood_packet_threshold:
            return None

        return self._build_alert_if_allowed(
            source_ip=src_ip,
            attack_type="SYN Flood",
            severity=self._config.syn_flood_severity,
            cooldown_seconds=self._config.syn_flood_alert_cooldown_seconds,
            now=now,
            details=(
                f"{len(attempts)} TCP SYN packets observed within "
                f"{self._config.syn_flood_window_seconds}s"
            ),
        )

    def _detect_icmp_flood(self, src_ip: str, now: float) -> Alert | None:
        packets = self._icmp_packets[src_ip]
        packets.append(now)
        self._trim_time_window(packets, now, self._config.icmp_flood_window_seconds)

        if len(packets) < self._config.icmp_flood_packet_threshold:
            return None

        return self._build_alert_if_allowed(
            source_ip=src_ip,
            attack_type="ICMP Flood",
            severity=self._config.icmp_flood_severity,
            cooldown_seconds=self._config.icmp_flood_alert_cooldown_seconds,
            now=now,
            details=(
                f"{len(packets)} ICMP packets observed within "
                f"{self._config.icmp_flood_window_seconds}s"
            ),
        )

    def _build_alert_if_allowed(
        self,
        source_ip: str,
        attack_type: str,
        severity: str,
        cooldown_seconds: int,
        now: float,
        details: str,
    ) -> Alert | None:
        alert_key = (source_ip, attack_type)
        last_alert = self._last_alert_at.get(alert_key)
        if last_alert is not None and now - last_alert < cooldown_seconds:
            return None

        self._last_alert_at[alert_key] = now
        return Alert(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            source_ip=source_ip,
            attack_type=attack_type,
            severity=severity or self._config.default_alert_severity,
            details=details,
        )

    def _trim_port_window(self, attempts: Deque[tuple[float, int]], now: float) -> None:
        cutoff = now - self._config.port_scan_window_seconds
        while attempts and attempts[0][0] < cutoff:
            attempts.popleft()

    @staticmethod
    def _trim_time_window(events: Deque[float], now: float, window_seconds: int) -> None:
        cutoff = now - window_seconds
        while events and events[0] < cutoff:
            events.popleft()

    def _emit_alert(self, alert: Alert) -> None:
        message = (
            f"[ALERT] {alert.timestamp} | Source={alert.source_ip} | "
            f"Type={alert.attack_type} | Severity={alert.severity} | {alert.details}"
        )
        print(message)
        logger.warning(
            "Rule alert generated: source=%s attack_type=%s severity=%s details=%s",
            alert.source_ip,
            alert.attack_type,
            alert.severity,
            alert.details,
        )
