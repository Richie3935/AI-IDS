"""
flow_generator.py - Network Flow Generator
==========================================
Converts packet-level IDS metadata into bidirectional-looking network flow
records keyed by the standard 5-tuple:

    source IP, destination IP, source port, destination port, protocol

The resulting records are intentionally plain and numeric so they can be
written to CSV now and fed into machine-learning models later.
"""

from __future__ import annotations

import csv
import logging
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class FlowKey:
    """Hashable 5-tuple that uniquely identifies one unidirectional flow."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str


@dataclass(slots=True)
class Flow:
    """
    Mutable in-memory state for an active flow.

    Only active flows live in this object. Completed flows are compacted into
    ``FlowRecord`` objects to avoid keeping unnecessary mutable state around.
    """

    key: FlowKey
    start_time: float
    last_seen: float
    packet_count: int = 0
    byte_count: int = 0

    def update(self, packet_size: int, timestamp: float) -> None:
        """Add one packet to this flow."""
        if packet_size < 0:
            raise ValueError("packet_size must be non-negative")

        self.packet_count += 1
        self.byte_count += packet_size
        self.last_seen = max(self.last_seen, timestamp)

    def close(self, closed_at: float | None = None) -> "FlowRecord":
        """Freeze the current flow state into an ML/CSV-ready record."""
        end_time = self.last_seen if closed_at is None else max(self.last_seen, closed_at)
        duration = max(end_time - self.start_time, 0.0)
        safe_duration = duration if duration > 0 else 1e-9

        return FlowRecord(
            src_ip=self.key.src_ip,
            dst_ip=self.key.dst_ip,
            src_port=self.key.src_port,
            dst_port=self.key.dst_port,
            protocol=self.key.protocol,
            packet_count=self.packet_count,
            byte_count=self.byte_count,
            flow_duration=duration,
            packets_per_second=self.packet_count / safe_duration,
            bytes_per_second=self.byte_count / safe_duration,
            start_time=self.start_time,
            end_time=end_time,
        )


@dataclass(frozen=True, slots=True)
class FlowRecord:
    """Completed flow features suitable for CSV export and ML pipelines."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_count: int
    byte_count: int
    flow_duration: float
    packets_per_second: float
    bytes_per_second: float
    start_time: float
    end_time: float

    CSV_FIELDS = (
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "packet_count",
        "byte_count",
        "flow_duration",
        "packets_per_second",
        "bytes_per_second",
        "start_time",
        "end_time",
    )

    def as_dict(self) -> dict[str, int | float | str]:
        """Return a plain feature dictionary with stable column names."""
        return asdict(self)


class FlowGenerator:
    """
    Convert packet metadata into completed flow records.

    The class is callable, so an instance can be registered directly with
    ``PacketCapture.register_callback(flow_generator)``. Expiration happens
    on every packet and, when enabled, in a lightweight background timer so
    quiet flows close automatically even after traffic stops.
    """

    def __init__(
        self,
        flow_timeout: float = 60.0,
        cleanup_interval: float = 10.0,
        max_completed_flows: int = 100_000,
        auto_cleanup: bool = True,
    ) -> None:
        if flow_timeout <= 0:
            raise ValueError("flow_timeout must be greater than zero")
        if cleanup_interval <= 0:
            raise ValueError("cleanup_interval must be greater than zero")
        if max_completed_flows <= 0:
            raise ValueError("max_completed_flows must be greater than zero")

        self.flow_timeout = float(flow_timeout)
        self.cleanup_interval = float(cleanup_interval)
        self._active_flows: dict[FlowKey, Flow] = {}
        self._completed_flows: deque[FlowRecord] = deque(maxlen=max_completed_flows)
        self._lock = threading.RLock()
        self._timer: threading.Timer | None = None
        self._running = False

        if auto_cleanup:
            self.start()

        logger.info(
            "FlowGenerator initialized - timeout=%.2fs cleanup=%.2fs max_completed=%d",
            self.flow_timeout,
            self.cleanup_interval,
            max_completed_flows,
        )

    def __call__(self, packet_info) -> None:
        """Allow direct registration as a PacketCapture callback."""
        self.process_packet(packet_info)

    def start(self) -> None:
        """Start automatic inactive-flow cleanup."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._schedule_cleanup_locked()

    def stop(self, close_active: bool = True) -> None:
        """Stop cleanup and optionally close every active flow."""
        with self._lock:
            self._running = False
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
            if close_active:
                self.close_all()

    def process_packet(self, packet_info, timestamp: float | None = None) -> None:
        """
        Add one packet to the correct flow.

        Non-IP packets are ignored because they cannot produce the required
        flow key. ICMP and other non-port protocols use port ``0``.
        """
        now = time.time() if timestamp is None else float(timestamp)

        try:
            key = self._build_flow_key(packet_info)
            packet_size = int(getattr(packet_info, "pkt_len"))
        except (AttributeError, TypeError, ValueError) as exc:
            logger.debug("Skipping packet that cannot form a flow: %s", exc)
            return

        with self._lock:
            self._expire_inactive_locked(now)
            flow = self._active_flows.get(key)
            if flow is None:
                flow = Flow(key=key, start_time=now, last_seen=now)
                self._active_flows[key] = flow
            flow.update(packet_size, now)

    def close_all(self) -> list[FlowRecord]:
        """Close all active flows and return the records that were created."""
        now = time.time()
        closed: list[FlowRecord] = []
        with self._lock:
            for key, flow in list(self._active_flows.items()):
                record = flow.close(now)
                self._completed_flows.append(record)
                closed.append(record)
                del self._active_flows[key]
        logger.info("Closed %d active flows", len(closed))
        return closed

    def expire_inactive(self) -> list[FlowRecord]:
        """Close flows that have exceeded the inactivity timeout."""
        with self._lock:
            return self._expire_inactive_locked(time.time())

    def get_completed_flows(self) -> list[FlowRecord]:
        """Return a snapshot of completed flows without mutating storage."""
        with self._lock:
            return list(self._completed_flows)

    def pop_completed_flows(self) -> list[FlowRecord]:
        """Return and clear completed flows for batch ML ingestion."""
        with self._lock:
            records = list(self._completed_flows)
            self._completed_flows.clear()
            return records

    def get_active_flow_count(self) -> int:
        """Return the number of flows currently held in memory."""
        with self._lock:
            return len(self._active_flows)

    def export_csv(
        self,
        path: str | Path,
        flows: Iterable[FlowRecord] | None = None,
        append: bool = False,
    ) -> int:
        """
        Export completed flow records to CSV.

        Returns the number of rows written. Existing files receive a header
        only when they are created from scratch.
        """
        csv_path = Path(path)
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        records = list(self.get_completed_flows() if flows is None else flows)
        mode = "a" if append else "w"
        write_header = not append or not csv_path.exists() or csv_path.stat().st_size == 0

        try:
            with csv_path.open(mode, newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=FlowRecord.CSV_FIELDS)
                if write_header:
                    writer.writeheader()
                for record in records:
                    writer.writerow(record.as_dict())
        except OSError as exc:
            logger.error("Failed to export flows to CSV %s: %s", csv_path, exc)
            raise

        logger.info("Exported %d flow records to %s", len(records), csv_path)
        return len(records)

    def _build_flow_key(self, packet_info) -> FlowKey:
        """Create the 5-tuple key from PacketInfo-like objects."""
        src_ip = getattr(packet_info, "src_ip", None)
        dst_ip = getattr(packet_info, "dst_ip", None)
        if not src_ip or not dst_ip:
            raise ValueError("source and destination IPs are required")

        protocol = str(getattr(packet_info, "protocol", "OTHER")).upper()
        src_port = getattr(packet_info, "sport", None)
        dst_port = getattr(packet_info, "dport", None)

        return FlowKey(
            src_ip=str(src_ip),
            dst_ip=str(dst_ip),
            src_port=int(src_port) if src_port is not None else 0,
            dst_port=int(dst_port) if dst_port is not None else 0,
            protocol=protocol,
        )

    def _expire_inactive_locked(self, now: float) -> list[FlowRecord]:
        """Close inactive flows. Caller must hold ``_lock``."""
        expired: list[FlowRecord] = []
        for key, flow in list(self._active_flows.items()):
            if now - flow.last_seen >= self.flow_timeout:
                record = flow.close(flow.last_seen)
                self._completed_flows.append(record)
                expired.append(record)
                del self._active_flows[key]

        if expired:
            logger.debug("Expired %d inactive flows", len(expired))
        return expired

    def _schedule_cleanup_locked(self) -> None:
        """Arm the next cleanup timer. Caller must hold ``_lock``."""
        if not self._running:
            return
        self._timer = threading.Timer(self.cleanup_interval, self._cleanup_tick)
        self._timer.daemon = True
        self._timer.start()

    def _cleanup_tick(self) -> None:
        """Timer callback that automatically closes inactive flows."""
        try:
            with self._lock:
                self._expire_inactive_locked(time.time())
                self._schedule_cleanup_locked()
        except Exception as exc:  # pragma: no cover
            logger.error("Flow cleanup failed: %s", exc, exc_info=True)
