"""
traffic_stats.py — Traffic Statistics Module
=============================================
Maintains real-time counters for network traffic and periodically
displays a formatted statistics report to the console.

Designed as a self-contained, thread-safe module that slots into the
larger Hybrid AI-Powered IDS architecture and can later feed a MySQL
logger, Flask dashboard, or ML detection pipeline.

Author : AI-IDS Project
Python : 3.11+
"""

import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

# ---------------------------------------------------------------------------
# Module-level logger — inherits the root handler configured in main.py
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data container
# ---------------------------------------------------------------------------

@dataclass
class TrafficCounters:
    """
    Immutable-ish snapshot of traffic counters at a point in time.

    Using a dataclass keeps field access explicit and makes it trivial
    to serialise to JSON later (for Flask / MySQL integration).
    """
    total_packets: int = 0
    tcp_packets:   int = 0
    udp_packets:   int = 0
    icmp_packets:  int = 0
    other_packets: int = 0
    total_bytes:   int = 0

    # Per-IP tallies — kept here so the snapshot is self-contained
    top_sources:       dict = field(default_factory=dict)
    top_destinations:  dict = field(default_factory=dict)

    snapshot_time: str = field(
        default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )


# ---------------------------------------------------------------------------
# Core statistics tracker
# ---------------------------------------------------------------------------

class TrafficStats:
    """
    Thread-safe, real-time traffic statistics tracker.

    Responsibilities
    ----------------
    * Receive packet metadata from the PacketCapture module and update
      internal counters atomically.
    * Spin up a background timer that prints a formatted report every
      ``report_interval`` seconds.
    * Expose a ``get_snapshot()`` method that returns a ``TrafficCounters``
      instance suitable for downstream consumers (DB logger, dashboard, ML).

    Extension points
    ----------------
    * ``_on_report()``  — override or monkey-patch to push stats elsewhere
                          instead of (or in addition to) printing them.
    * ``top_n``         — controls how many top-talker IPs are tracked;
                          kept small by default to prevent memory growth.
    """

    # Protocols we give explicit counters to; everything else → "other"
    TRACKED_PROTOCOLS = frozenset({"TCP", "UDP", "ICMP"})

    def __init__(
        self,
        report_interval: int = 10,
        top_n: int = 5,
    ) -> None:
        """
        Parameters
        ----------
        report_interval : int
            Seconds between automatic statistics reports (default 10).
        top_n : int
            Number of top source / destination IPs to track (default 5).
            Capped to avoid unbounded dict growth in long-running sessions.
        """
        if report_interval < 1:
            raise ValueError("report_interval must be >= 1 second")

        self._interval = report_interval
        self._top_n = top_n

        # --- counters (protected by _lock) ---------------------------------
        self._lock = threading.Lock()
        self._reset_counters()

        # --- background reporting timer ------------------------------------
        self._timer: threading.Timer | None = None
        self._running = False

        logger.info(
            "TrafficStats initialised — report interval: %ds, top-N IPs: %d",
            self._interval,
            self._top_n,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Begin the periodic statistics reporting loop."""
        if self._running:
            logger.warning("TrafficStats.start() called but already running")
            return
        self._running = True
        self._schedule_next_report()
        logger.info("TrafficStats reporting started")

    def stop(self) -> None:
        """Cancel the reporting timer and shut down cleanly."""
        self._running = False
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        logger.info("TrafficStats reporting stopped")

    def update(
        self,
        protocol: str,
        pkt_len: int,
        src_ip: str | None = None,
        dst_ip: str | None = None,
    ) -> None:
        """
        Update counters with data from one captured packet.

        Called by the PacketCapture module on the sniffer thread, so all
        mutations are protected by ``_lock`` to prevent data races.

        Parameters
        ----------
        protocol : str
            Normalised protocol string — "TCP", "UDP", "ICMP", or "OTHER".
        pkt_len : int
            Length of the captured packet in bytes.
        src_ip : str | None
            Source IP address (IPv4 or IPv6).  ``None`` for non-IP traffic.
        dst_ip : str | None
            Destination IP address.  ``None`` for non-IP traffic.
        """
        protocol = protocol.upper()

        with self._lock:
            self._total_packets += 1
            self._total_bytes  += pkt_len

            # Protocol-specific counters
            if protocol == "TCP":
                self._tcp_packets += 1
            elif protocol == "UDP":
                self._udp_packets += 1
            elif protocol == "ICMP":
                self._icmp_packets += 1
            else:
                self._other_packets += 1

            # Per-IP tallies — defaultdict avoids KeyError on first hit
            if src_ip:
                self._src_counts[src_ip] += 1
            if dst_ip:
                self._dst_counts[dst_ip] += 1

    def get_snapshot(self) -> TrafficCounters:
        """
        Return an atomic snapshot of current counters.

        The returned ``TrafficCounters`` is a plain dataclass — safe to pass
        to other threads or serialise without holding the lock.
        """
        with self._lock:
            top_src = self._top_talkers(self._src_counts)
            top_dst = self._top_talkers(self._dst_counts)

            return TrafficCounters(
                total_packets     = self._total_packets,
                tcp_packets       = self._tcp_packets,
                udp_packets       = self._udp_packets,
                icmp_packets      = self._icmp_packets,
                other_packets     = self._other_packets,
                total_bytes       = self._total_bytes,
                top_sources       = top_src,
                top_destinations  = top_dst,
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _reset_counters(self) -> None:
        """Initialise (or zero-out) all mutable counter fields."""
        self._total_packets  = 0
        self._tcp_packets    = 0
        self._udp_packets    = 0
        self._icmp_packets   = 0
        self._other_packets  = 0
        self._total_bytes    = 0

        # defaultdict(int) gives O(1) increments and no KeyError on new keys
        self._src_counts: defaultdict[str, int] = defaultdict(int)
        self._dst_counts: defaultdict[str, int] = defaultdict(int)

    def _top_talkers(self, counter: defaultdict) -> dict:
        """Return the top-N IPs by packet count as a plain sorted dict."""
        return dict(
            sorted(counter.items(), key=lambda kv: kv[1], reverse=True)[: self._top_n]
        )

    def _schedule_next_report(self) -> None:
        """Arm the one-shot timer for the next report cycle."""
        if not self._running:
            return
        self._timer = threading.Timer(self._interval, self._report_and_reschedule)
        self._timer.daemon = True   # won't block interpreter shutdown
        self._timer.start()

    def _report_and_reschedule(self) -> None:
        """Fire a report, then schedule the next one."""
        try:
            self._print_report()
        except Exception as exc:                            # pragma: no cover
            logger.error("Error during stats report: %s", exc, exc_info=True)
        finally:
            self._schedule_next_report()                   # always reschedule

    def _print_report(self) -> None:
        """
        Render a formatted statistics table to stdout / log.

        Override ``_on_report()`` to push data to additional sinks
        (e.g., MySQL, Flask event queue) without changing this method.
        """
        snap = self.get_snapshot()

        # Protect against division-by-zero on a quiet interface
        total = snap.total_packets or 1

        lines = [
            "",
            "╔══════════════════════════════════════════════════════╗",
            "║          REAL-TIME TRAFFIC STATISTICS                ║",
            f"║  Snapshot: {snap.snapshot_time}                  ║",
            "╠══════════════════════════════════════════════════════╣",
            f"║  Total Packets  : {snap.total_packets:<10}                    ║",
            f"║  Total Bytes    : {self._human_bytes(snap.total_bytes):<10}                    ║",
            "╠══════════════════════════════════════════════════════╣",
            f"║  TCP   Packets  : {snap.tcp_packets:<6} "
            f"({snap.tcp_packets / total * 100:5.1f}%)                   ║",
            f"║  UDP   Packets  : {snap.udp_packets:<6} "
            f"({snap.udp_packets / total * 100:5.1f}%)                   ║",
            f"║  ICMP  Packets  : {snap.icmp_packets:<6} "
            f"({snap.icmp_packets / total * 100:5.1f}%)                   ║",
            f"║  Other Packets  : {snap.other_packets:<6} "
            f"({snap.other_packets / total * 100:5.1f}%)                   ║",
        ]

        # Top sources
        if snap.top_sources:
            lines.append("╠══════════════════════════════════════════════════════╣")
            lines.append("║  Top Source IPs:                                     ║")
            for ip, cnt in snap.top_sources.items():
                lines.append(f"║    {ip:<20} {cnt:>6} pkts                    ║")

        # Top destinations
        if snap.top_destinations:
            lines.append("╠══════════════════════════════════════════════════════╣")
            lines.append("║  Top Destination IPs:                                ║")
            for ip, cnt in snap.top_destinations.items():
                lines.append(f"║    {ip:<20} {cnt:>6} pkts                    ║")

        lines.append("╚══════════════════════════════════════════════════════╝")

        report = "\n".join(lines)
        print(report)
        logger.info("Stats report — total=%d tcp=%d udp=%d icmp=%d",
                    snap.total_packets, snap.tcp_packets,
                    snap.udp_packets, snap.icmp_packets)

        # Extension point for subclasses / monkey-patching
        self._on_report(snap)

    # ------------------------------------------------------------------
    # Extension point
    # ------------------------------------------------------------------

    def _on_report(self, snapshot: TrafficCounters) -> None:
        """
        Hook called after every periodic report with the current snapshot.

        Override in a subclass or replace at runtime to push statistics to
        a MySQL logger, Flask SSE stream, ML feature extractor, etc.

        Example (MySQL logger stub)::

            def _on_report(self, snapshot):
                db.insert_stats(snapshot)   # your implementation

        Parameters
        ----------
        snapshot : TrafficCounters
            Immutable snapshot of traffic counters at report time.
        """
        # Default implementation is intentionally a no-op.
        pass

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def _human_bytes(num: int) -> str:
        """Convert raw byte count to a human-readable string (KB / MB / GB)."""
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if num < 1024:
                return f"{num:.1f} {unit}"
            num /= 1024
        return f"{num:.1f} PB"                             # pragma: no cover

    # ------------------------------------------------------------------
    # Context-manager support (used in tests and scripts)
    # ------------------------------------------------------------------

    def __enter__(self) -> "TrafficStats":
        self.start()
        return self

    def __exit__(self, *_) -> None:
        self.stop()

    def __repr__(self) -> str:
        return (
            f"TrafficStats(interval={self._interval}s, "
            f"packets={self._total_packets})"
        )