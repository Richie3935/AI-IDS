"""
packet_capture.py — Packet Capture Module
==========================================
Captures live network packets with Scapy, extracts key fields, displays
a clean per-packet summary to the console, and feeds the TrafficStats
module with real-time updates.

Designed as the "ingestion layer" of the Hybrid AI-Powered IDS.  Later
extensions (rule engine, flow generator, ML classifier) attach to the
``_on_packet()`` hook without touching this file.

Author : AI-IDS Project
Python : 3.11+
"""

import logging
import signal
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Callable

# ---------------------------------------------------------------------------
# Scapy import — suppress the "no route to host" IPv6 warning on import
# ---------------------------------------------------------------------------
import logging as _std_logging

_scapy_logger = _std_logging.getLogger("scapy.runtime")
_scapy_logger.setLevel(_std_logging.ERROR)          # silence runtime warnings

try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Raw
    from scapy.packet import Packet as ScapyPacket
except ImportError as exc:
    raise ImportError(
        "Scapy is required.  Install it with:  pip install scapy"
    ) from exc

# Module logger
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Packet metadata container
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PacketInfo:
    """
    Immutable snapshot of one captured packet's metadata.

    ``frozen=True`` ensures downstream consumers (rule engine, ML pipeline)
    can share instances across threads without accidental mutation.
    """
    timestamp:  str
    src_ip:     str | None
    dst_ip:     str | None
    protocol:   str           # "TCP" | "UDP" | "ICMP" | "OTHER"
    pkt_len:    int           # bytes, as reported by Scapy
    sport:      int | None    # source port (TCP/UDP only)
    dport:      int | None    # destination port (TCP/UDP only)
    flags:      str | None    # TCP flags string, e.g. "SA", "PA"
    ttl:        int | None    # IP Time-To-Live
    raw_summary: str          # Scapy's one-line packet summary (fallback)

    def as_dict(self) -> dict:
        """Return a plain dict for JSON serialisation or DB insertion."""
        return {
            "timestamp":   self.timestamp,
            "src_ip":      self.src_ip,
            "dst_ip":      self.dst_ip,
            "protocol":    self.protocol,
            "pkt_len":     self.pkt_len,
            "sport":       self.sport,
            "dport":       self.dport,
            "flags":       self.flags,
            "ttl":         self.ttl,
        }


# ---------------------------------------------------------------------------
# Packet Capture Engine
# ---------------------------------------------------------------------------

class PacketCapture:
    """
    Live packet capture engine built on top of Scapy's ``sniff()``.

    Responsibilities
    ----------------
    * Start / stop packet sniffing on a given network interface.
    * Parse every captured frame into a ``PacketInfo`` dataclass.
    * Display a clean, colour-free one-line summary per packet.
    * Push protocol / length / IP data to a ``TrafficStats`` instance.
    * Call ``_on_packet()`` so future modules (rules, ML, flow gen) can
      react without modifying this class.

    Thread model
    ------------
    Scapy's ``sniff(store=False)`` calls the callback on its own internal
    thread.  All state mutations go through ``TrafficStats._lock``, so this
    class itself has no mutable shared state.

    Parameters
    ----------
    stats : TrafficStats-like
        Any object with an ``update(protocol, pkt_len, src_ip, dst_ip)``
        method.  Injected to keep the two modules decoupled.
    interface : str | None
        Network interface to sniff on (e.g. ``"eth0"``, ``"en0"``).
        ``None`` lets Scapy pick the default interface.
    packet_filter : str
        BPF filter string passed to Scapy (default ``""`` = capture all).
    packet_count : int
        Maximum packets to capture; 0 means run indefinitely.
    display_packets : bool
        Print per-packet summaries to stdout (default True).
        Set to False in headless / high-throughput mode.
    """

    # Colour codes for protocol labels — easy to disable for log files
    _PROTO_COLOURS = {
        "TCP":   "\033[94m",   # blue
        "UDP":   "\033[92m",   # green
        "ICMP":  "\033[93m",   # yellow
        "OTHER": "\033[90m",   # grey
    }
    _RESET = "\033[0m"

    def __init__(
        self,
        stats,                              # TrafficStats instance
        interface:       str | None = None,
        packet_filter:   str = "",
        packet_count:    int = 0,
        display_packets: bool = True,
    ) -> None:
        self._stats          = stats
        self._interface      = interface
        self._filter         = packet_filter
        self._count          = packet_count
        self._display        = display_packets

        # Packet counter — read only from the main thread after stop()
        self._captured: int = 0

        # Optional extra callbacks registered by external modules
        self._extra_callbacks: list[Callable[[PacketInfo], None]] = []

        logger.info(
            "PacketCapture initialised — interface=%s filter=%r count=%s",
            interface or "default",
            packet_filter or "none",
            packet_count or "∞",
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """
        Begin blocking packet capture.

        This call blocks the calling thread until either ``packet_count``
        packets have been captured or a ``KeyboardInterrupt`` / SIGINT is
        received.  Run it inside a daemon thread if you need the main
        thread to stay responsive.
        """
        iface_label = self._interface or "default interface"
        logger.info("Starting packet capture on %s …", iface_label)
        print(f"\n[*] Capturing packets on {iface_label} "
              f"(filter: {self._filter or 'none'}) — Ctrl+C to stop\n")
        print(
            f"{'TIME':<12} {'SRC IP':<18} {'DST IP':<18} "
            f"{'PROTO':<6} {'LEN':>6}  {'SPORT':>6}  {'DPORT':>6}  FLAGS"
        )
        print("─" * 80)

        try:
            sniff(
                iface=self._interface,
                filter=self._filter,
                prn=self._process_packet,   # callback per packet
                count=self._count,          # 0 = infinite
                store=False,                # do NOT buffer packets in memory
            )
        except PermissionError:
            logger.critical(
                "Permission denied — run as root / Administrator "
                "or grant CAP_NET_RAW capability"
            )
            print(
                "\n[ERROR] Permission denied.\n"
                "  → Linux : sudo python main.py\n"
                "  → macOS : sudo python main.py\n"
                "  → Windows: run as Administrator\n"
            )
            sys.exit(1)
        except OSError as exc:
            logger.critical("Network interface error: %s", exc)
            print(f"\n[ERROR] Interface error: {exc}")
            sys.exit(1)

    def register_callback(self, fn: Callable[[PacketInfo], None]) -> None:
        """
        Register an external callback invoked for every captured packet.

        Use this to wire in the rule engine, flow generator, or ML
        classifier without subclassing PacketCapture.

        Parameters
        ----------
        fn : callable
            Function accepting a single ``PacketInfo`` argument.
        """
        if not callable(fn):
            raise TypeError(f"Callback must be callable, got {type(fn)}")
        self._extra_callbacks.append(fn)
        logger.debug("Registered packet callback: %s", fn.__name__)

    @property
    def captured_count(self) -> int:
        """Total number of packets processed since start()."""
        return self._captured

    # ------------------------------------------------------------------
    # Core packet processing (called on Scapy's sniffer thread)
    # ------------------------------------------------------------------

    def _process_packet(self, pkt: ScapyPacket) -> None:
        """
        Entry point for every packet received from Scapy.

        Steps
        -----
        1. Parse raw Scapy packet → ``PacketInfo``
        2. Display one-line summary (if enabled)
        3. Update TrafficStats
        4. Call any registered extension callbacks

        Malformed / unexpected packets are caught here and logged so
        the sniffer thread never dies on a bad frame.
        """
        try:
            info = self._parse_packet(pkt)
            self._captured += 1

            if self._display:
                self._print_packet(info)

            # Feed the statistics module
            self._stats.update(
                protocol=info.protocol,
                pkt_len=info.pkt_len,
                src_ip=info.src_ip,
                dst_ip=info.dst_ip,
            )

            # Extension hook — subclass or use register_callback()
            self._on_packet(info)

            # Fire any dynamically registered callbacks
            for cb in self._extra_callbacks:
                try:
                    cb(info)
                except Exception as cb_exc:             # pragma: no cover
                    logger.warning(
                        "Callback %s raised an exception: %s",
                        cb.__name__, cb_exc
                    )

        except Exception as exc:
            # Never let a single bad packet kill the sniffer loop
            logger.debug("Malformed packet skipped: %s", exc)

    def _parse_packet(self, pkt: ScapyPacket) -> PacketInfo:
        """
        Extract structured metadata from a raw Scapy packet.

        Handles IPv4, IPv6, TCP, UDP, and ICMP.  Falls back gracefully
        for non-IP frames (ARP, 802.1Q, etc.).

        Returns
        -------
        PacketInfo
            Immutable packet metadata container.
        """
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        pkt_len   = len(pkt)
        src_ip    = None
        dst_ip    = None
        protocol  = "OTHER"
        sport     = None
        dport     = None
        flags     = None
        ttl       = None

        # ── Layer 3: IP / IPv6 ──────────────────────────────────────────
        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            src_ip   = ip_layer.src
            dst_ip   = ip_layer.dst
            ttl      = ip_layer.ttl
        elif pkt.haslayer(IPv6):
            ip6_layer = pkt[IPv6]
            src_ip    = ip6_layer.src
            dst_ip    = ip6_layer.dst
            ttl       = ip6_layer.hlim   # IPv6 "hop limit" ≈ TTL

        # ── Layer 4: TCP / UDP / ICMP ───────────────────────────────────
        if pkt.haslayer(TCP):
            tcp      = pkt[TCP]
            protocol = "TCP"
            sport    = tcp.sport
            dport    = tcp.dport
            flags    = str(tcp.flags)   # e.g. "SA", "PA", "F"

        elif pkt.haslayer(UDP):
            udp      = pkt[UDP]
            protocol = "UDP"
            sport    = udp.sport
            dport    = udp.dport

        elif pkt.haslayer(ICMP):
            protocol = "ICMP"

        return PacketInfo(
            timestamp   = timestamp,
            src_ip      = src_ip,
            dst_ip      = dst_ip,
            protocol    = protocol,
            pkt_len     = pkt_len,
            sport       = sport,
            dport       = dport,
            flags       = flags,
            ttl         = ttl,
            raw_summary = pkt.summary(),
        )

    # ------------------------------------------------------------------
    # Display
    # ------------------------------------------------------------------

    def _print_packet(self, info: PacketInfo) -> None:
        """Render one packet as a fixed-width console line."""
        colour = self._PROTO_COLOURS.get(info.protocol, self._PROTO_COLOURS["OTHER"])
        proto_label = f"{colour}{info.protocol:<6}{self._RESET}"

        src  = info.src_ip  or "—"
        dst  = info.dst_ip  or "—"
        sp   = str(info.sport) if info.sport is not None else "—"
        dp   = str(info.dport) if info.dport is not None else "—"
        flg  = info.flags or "—"

        print(
            f"{info.timestamp:<12} {src:<18} {dst:<18} "
            f"{proto_label} {info.pkt_len:>6}B  {sp:>6}  {dp:>6}  {flg}"
        )

    # ------------------------------------------------------------------
    # Extension point
    # ------------------------------------------------------------------

    def _on_packet(self, info: PacketInfo) -> None:
        """
        Hook called for every successfully parsed packet.

        Override in a subclass to add rule-based detection, flow
        generation, or ML feature extraction without modifying this module.

        Example (rule engine stub)::

            class IDSCapture(PacketCapture):
                def _on_packet(self, info):
                    rule_engine.evaluate(info)

        Parameters
        ----------
        info : PacketInfo
            Immutable packet metadata snapshot.
        """
        # Default: no-op.  Logic lives in subclasses or callbacks.
        pass

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"PacketCapture(interface={self._interface!r}, "
            f"filter={self._filter!r}, captured={self._captured})"
        )