"""
main.py — AI-Powered Intrusion Detection System (IDS) Entry Point
=================================================================
Wires together the PacketCapture and TrafficStats modules and provides a
clean CLI for launching the IDS with custom options.

Architecture overview
---------------------
┌──────────────────────────────────────────────────────────┐
│                         main.py                          │
│  ┌─────────────────────┐   ┌──────────────────────────┐  │
│  │   PacketCapture     │──▶│      TrafficStats        │  │
│  │  (packet_capture.py)│   │   (traffic_stats.py)     │  │
│  └─────────────────────┘   └──────────────────────────┘  │
│         │                                                 │
│         ▼  (future extension points)                      │
│  ┌─────────────────────────────────────────────────┐     │
│  │  Rule Engine │ MySQL Logger │ Flask Dashboard    │     │
│  │  Flow Gen    │ ML Classifier                     │     │
│  └─────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────┘

Usage
-----
    sudo python main.py                          # capture on default NIC
    sudo python main.py -i eth0                  # specific interface
    sudo python main.py -i eth0 -f "tcp"         # BPF filter
    sudo python main.py -i eth0 -c 500           # stop after 500 packets
    sudo python main.py --interval 30            # report every 30 s
    sudo python main.py --no-display             # suppress per-packet lines

Author : AI-IDS Project
Python : 3.11+
"""

import argparse
import logging
import signal
import sys
import threading
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure the project root is on sys.path when running from a different cwd
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent))

from packet_capture import PacketCapture
from traffic_stats  import TrafficStats


# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------

def _configure_logging(log_level: str, log_file: str | None) -> None:
    """
    Set up root logger with a console handler and an optional file handler.

    Log levels: DEBUG < INFO < WARNING < ERROR < CRITICAL
    """
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        handlers.append(file_handler)

    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
    )

    # Keep Scapy's own loggers quiet unless we're in DEBUG mode
    if numeric_level > logging.DEBUG:
        logging.getLogger("scapy").setLevel(logging.ERROR)

    logging.getLogger(__name__).info(
        "Logging initialised — level=%s file=%s",
        log_level.upper(),
        log_file or "none",
    )


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------

def _build_arg_parser() -> argparse.ArgumentParser:
    """Define and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="AI-IDS",
        description=(
            "AI-Powered Intrusion Detection System — "
            "live packet capture + real-time traffic statistics"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python main.py
  sudo python main.py -i eth0
  sudo python main.py -i eth0 -f "tcp port 80"
  sudo python main.py -i eth0 -c 1000 --interval 30
  sudo python main.py --log-level DEBUG --log-file ids.log
""",
    )

    # Capture options
    cap = parser.add_argument_group("Capture options")
    cap.add_argument(
        "-i", "--interface",
        default=None,
        metavar="IFACE",
        help="Network interface to capture on (default: system default)",
    )
    cap.add_argument(
        "-f", "--filter",
        default="",
        metavar="BPF",
        help='BPF capture filter string (e.g., "tcp", "port 443")',
    )
    cap.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        metavar="N",
        help="Stop after N packets (default: 0 = run indefinitely)",
    )
    cap.add_argument(
        "--no-display",
        action="store_true",
        help="Suppress per-packet console output (stats still shown)",
    )

    # Statistics options
    stats = parser.add_argument_group("Statistics options")
    stats.add_argument(
        "--interval",
        type=int,
        default=10,
        metavar="SEC",
        help="Statistics report interval in seconds (default: 10)",
    )
    stats.add_argument(
        "--top-n",
        type=int,
        default=5,
        metavar="N",
        help="Number of top-talker IPs to display (default: 5)",
    )

    # Logging options
    log = parser.add_argument_group("Logging options")
    log.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging verbosity (default: INFO)",
    )
    log.add_argument(
        "--log-file",
        default=None,
        metavar="PATH",
        help="Write logs to this file in addition to stdout",
    )

    return parser


# ---------------------------------------------------------------------------
# IDS Application class
# ---------------------------------------------------------------------------

class AIIDS:
    """
    Top-level application class that owns and coordinates all IDS modules.

    Keeping this in a class (rather than a bare ``main()`` function) makes
    it straightforward to instantiate in tests, embed in a Flask app, or
    wrap in a systemd service.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed CLI arguments (or a compatible namespace from tests).
    """

    def __init__(self, args: argparse.Namespace) -> None:
        self._args = args
        self._logger = logging.getLogger(self.__class__.__name__)

        # Instantiate modules — PacketCapture receives a TrafficStats ref
        self._stats = TrafficStats(
            report_interval=args.interval,
            top_n=args.top_n,
        )
        self._capture = PacketCapture(
            stats=self._stats,
            interface=args.interface,
            packet_filter=args.filter,
            packet_count=args.count,
            display_packets=not args.no_display,
        )

        # Register graceful-shutdown handlers
        signal.signal(signal.SIGINT,  self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def run(self) -> None:
        """
        Start the IDS.

        1. Print the startup banner.
        2. Start the TrafficStats reporting timer.
        3. Block on PacketCapture.start() (runs until interrupted).
        4. On exit: print a final stats report and tear down cleanly.
        """
        self._print_banner()
        self._logger.info("AI-IDS starting …")

        # Start the background statistics reporter
        self._stats.start()

        try:
            # Blocking call — returns only when packet_count is reached
            # or a signal is received.
            self._capture.start()
        except SystemExit:
            # Raised by PacketCapture on permission / interface errors
            self._shutdown(exit_code=1)
        except Exception as exc:                        # pragma: no cover
            self._logger.critical("Unexpected error: %s", exc, exc_info=True)
            self._shutdown(exit_code=1)
        else:
            self._shutdown(exit_code=0)

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def _handle_shutdown(self, signum: int, frame) -> None:
        """Signal handler — triggers a clean shutdown on Ctrl+C / SIGTERM."""
        print("\n\n[*] Shutdown signal received — stopping capture …")
        self._logger.info("Received signal %d — initiating shutdown", signum)
        self._shutdown(exit_code=0)

    def _shutdown(self, exit_code: int = 0) -> None:
        """Stop all modules and exit."""
        self._logger.info("Shutting down AI-IDS …")

        # Stop the periodic stats timer
        self._stats.stop()

        # Print a final summary before exiting
        self._print_final_report()

        self._logger.info(
            "AI-IDS stopped — %d packets captured",
            self._capture.captured_count,
        )
        sys.exit(exit_code)

    # ------------------------------------------------------------------
    # Console output
    # ------------------------------------------------------------------

    def _print_banner(self) -> None:
        """Display the startup banner with active configuration."""
        iface  = self._args.interface or "system default"
        filt   = self._args.filter    or "none (capture all)"
        count  = self._args.count     or "unlimited"

        banner = f"""
╔══════════════════════════════════════════════════════════╗
║          AI-Powered Intrusion Detection System           ║
║                       v1.0.0                            ║
╠══════════════════════════════════════════════════════════╣
║  Interface  : {iface:<41}║
║  BPF Filter : {filt:<41}║
║  Pkt Limit  : {str(count):<41}║
║  Stats Every: {str(self._args.interval) + 's':<41}║
╠══════════════════════════════════════════════════════════╣
║  Modules Active:                                        ║
║    ✔ Packet Capture (Scapy)                             ║
║    ✔ Traffic Statistics                                 ║
║  Planned Extensions:                                    ║
║    ○ Rule-Based Detection                               ║
║    ○ MySQL Logging                                      ║
║    ○ Flask Dashboard                                    ║
║    ○ Flow Generation                                    ║
║    ○ ML-Based Detection                                 ║
╚══════════════════════════════════════════════════════════╝
"""
        print(banner)

    def _print_final_report(self) -> None:
        """Print a final traffic summary when the IDS exits."""
        snap = self._stats.get_snapshot()
        total = snap.total_packets or 1

        print(f"""
╔══════════════════════════════════════════════════════════╗
║                   FINAL SESSION REPORT                  ║
╠══════════════════════════════════════════════════════════╣
║  Total Packets  : {snap.total_packets:<38}║
║  Total Bytes    : {TrafficStats._human_bytes(snap.total_bytes):<38}║
║  TCP  Packets   : {snap.tcp_packets:<6} ({snap.tcp_packets / total * 100:5.1f}%)                        ║
║  UDP  Packets   : {snap.udp_packets:<6} ({snap.udp_packets / total * 100:5.1f}%)                        ║
║  ICMP Packets   : {snap.icmp_packets:<6} ({snap.icmp_packets / total * 100:5.1f}%)                        ║
║  Other Packets  : {snap.other_packets:<6} ({snap.other_packets / total * 100:5.1f}%)                        ║
╚══════════════════════════════════════════════════════════╝
""")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Parse CLI arguments, configure logging, and start the IDS."""
    parser = _build_arg_parser()
    args   = parser.parse_args()

    _configure_logging(args.log_level, args.log_file)

    ids = AIIDS(args)
    ids.run()


if __name__ == "__main__":
    main()