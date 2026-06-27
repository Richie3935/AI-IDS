"""
main.py — AI-Powered Intrusion Detection System (IDS) Entry Point
=================================================================
Wires together the PacketCapture, TrafficStats, RuleEngine, FlowGenerator,
and — from Version 7 — the AI prediction engine into a unified pipeline.

Architecture overview (Version 7)
----------------------------------
┌──────────────────────────────────────────────────────────────┐
│                           main.py                            │
│                                                              │
│  PacketCapture (Scapy)                                       │
│       │                                                      │
│       ├──▶ TrafficStats   (real-time counters / dashboard)   │
│       ├──▶ RuleEngine     (port scan / SYN flood / ICMP)     │
│       └──▶ FlowGenerator  (5-tuple flow aggregation)         │
│                │                                             │
│                └──▶ AIEngine  (Random Forest classifier)     │
│                          │                                   │
│                          └──▶ MySQLAlertRepository           │
│                                       │                      │
│                                       └──▶ Flask Dashboard   │
└──────────────────────────────────────────────────────────────┘

Usage
-----
    sudo python main.py
    sudo python main.py -i eth0
    sudo python main.py -i eth0 -f "tcp"
    sudo python main.py --model-path ml/model.pkl
    sudo python main.py --disable-ml
    sudo python main.py --ml-confidence-threshold 0.75

Author : AI-IDS Project
Python : 3.11+
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from detection import DetectionConfig, RuleEngine
from database import MySQLAlertRepository
from ml import AIEngine, FlowGenerator
from packet_capture import PacketCapture
from traffic_stats import TrafficStats


# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------

def _configure_logging(log_level: str, log_file: str | None) -> None:
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
    parser = argparse.ArgumentParser(
        prog="AI-IDS",
        description=(
            "AI-Powered Intrusion Detection System — "
            "live packet capture, traffic statistics, rule detection, and ML classification"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python main.py
  sudo python main.py -i eth0 -f "tcp"
  sudo python main.py --model-path ml/model.pkl
  sudo python main.py --disable-ml
  sudo python main.py --ml-confidence-threshold 0.75
""",
    )

    # Capture options
    cap = parser.add_argument_group("Capture options")
    cap.add_argument("-i", "--interface", default=None, metavar="IFACE",
                     help="Network interface to capture on (default: system default)")
    cap.add_argument("-f", "--filter", default="", metavar="BPF",
                     help='BPF capture filter string (e.g., "tcp", "port 443")')
    cap.add_argument("-c", "--count", type=int, default=0, metavar="N",
                     help="Stop after N packets (default: 0 = run indefinitely)")
    cap.add_argument("--no-display", action="store_true",
                     help="Suppress per-packet console output (stats still shown)")

    # Statistics options
    stats = parser.add_argument_group("Statistics options")
    stats.add_argument("--interval", type=int, default=10, metavar="SEC",
                       help="Statistics report interval in seconds (default: 10)")
    stats.add_argument("--top-n", type=int, default=5, metavar="N",
                       help="Number of top-talker IPs to display (default: 5)")
    stats.add_argument("--stats-snapshot-file",
                       default="dashboard/static/stats_snapshot.json", metavar="PATH",
                       help="Write latest traffic stats snapshot for the dashboard")

    # Flow generation options
    flows = parser.add_argument_group("Flow generation options")
    flows.add_argument("--flow-timeout", type=float, default=60.0, metavar="SEC",
                       help="Close flows after this many seconds of inactivity (default: 60)")
    flows.add_argument("--flow-cleanup-interval", type=float, default=10.0, metavar="SEC",
                       help="Inactive-flow cleanup interval in seconds (default: 10)")
    flows.add_argument("--flow-csv", default="ml/completed_flows.csv", metavar="PATH",
                       help="CSV path for completed flow export on shutdown")
    flows.add_argument("--disable-flow-export", action="store_true",
                       help="Do not write completed flows to CSV on shutdown")

    # Rule engine options
    rules = parser.add_argument_group("Rule engine options")
    rules.add_argument("--disable-rules", action="store_true",
                       help="Disable rule-based intrusion detection alerts")
    rules.add_argument("--port-scan-window", type=int,
                       default=DetectionConfig.port_scan_window_seconds, metavar="SEC")
    rules.add_argument("--port-scan-ports", type=int,
                       default=DetectionConfig.port_scan_unique_ports, metavar="N")
    rules.add_argument("--syn-window", type=int,
                       default=DetectionConfig.syn_flood_window_seconds, metavar="SEC")
    rules.add_argument("--syn-threshold", type=int,
                       default=DetectionConfig.syn_flood_packet_threshold, metavar="N")
    rules.add_argument("--icmp-window", type=int,
                       default=DetectionConfig.icmp_flood_window_seconds, metavar="SEC")
    rules.add_argument("--icmp-threshold", type=int,
                       default=DetectionConfig.icmp_flood_packet_threshold, metavar="N")

    # ML engine options (Version 7)
    ml = parser.add_argument_group("ML engine options (Version 7)")
    ml.add_argument("--disable-ml", action="store_true",
                    help="Disable the ML-based detection layer")
    ml.add_argument("--model-path", default="ml/model.pkl", metavar="PATH",
                    help="Path to trained model bundle (default: ml/model.pkl)")
    ml.add_argument("--ml-confidence-threshold", type=float, default=0.60, metavar="FLOAT",
                    help="Minimum ML confidence to emit an alert (default: 0.60)")

    # Logging options
    log = parser.add_argument_group("Logging options")
    log.add_argument("--log-level", default="INFO",
                     choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                     help="Logging verbosity (default: INFO)")
    log.add_argument("--log-file", default=None, metavar="PATH",
                     help="Write logs to this file in addition to stdout")

    return parser


# ---------------------------------------------------------------------------
# ML alert emitter
# ---------------------------------------------------------------------------

class MLAlertEmitter:
    """
    Bridge between the FlowGenerator and the AIEngine.

    Registered as a periodic callback on the ``TrafficStats._on_report``
    hook so completed flows are classified after each stats interval.
    This keeps the ML inference off the hot packet-processing path.

    Parameters
    ----------
    flow_generator : FlowGenerator
        Shared instance that accumulates completed flow records.
    ai_engine : AIEngine
        Loaded ML model wrapper.
    alert_repository : MySQLAlertRepository
        Database sink for ML-generated alerts.
    confidence_threshold : float
        Minimum predicted probability required to emit an alert.
    """

    _SEVERITY_MAP: dict[str, str] = {
        "DoS":      "CRITICAL",
        "PortScan": "HIGH",
        "BENIGN":   "INFO",
    }

    def __init__(
        self,
        flow_generator: FlowGenerator,
        ai_engine: AIEngine,
        alert_repository: MySQLAlertRepository,
        confidence_threshold: float = 0.60,
    ) -> None:
        self._flow_generator = flow_generator
        self._ai_engine = ai_engine
        self._repository = alert_repository
        self._threshold = confidence_threshold
        self._logger = logging.getLogger(self.__class__.__name__)
        self._lock = threading.Lock()

    def classify_completed_flows(self, _snapshot=None) -> None:
        """
        Drain completed flows, classify them, and persist attack predictions.

        Safe to call from any thread. The ``_snapshot`` parameter is accepted
        (and ignored) so this method can be wired directly to the
        ``TrafficStats._on_report`` hook.
        """
        if not self._ai_engine.available:
            return

        with self._lock:
            flows = self._flow_generator.pop_completed_flows()

        if not flows:
            return

        predictions = self._ai_engine.predict_batch(flows)

        alerts_emitted = 0
        for flow, prediction in zip(flows, predictions):
            if prediction is None:
                continue
            if not prediction.is_attack:
                continue
            if prediction.confidence < self._threshold:
                self._logger.debug(
                    "ML suppressed low-confidence alert: type=%s confidence=%.1f%%",
                    prediction.attack_type,
                    prediction.confidence * 100,
                )
                continue

            self._emit_alert(flow, prediction)
            alerts_emitted += 1

        if alerts_emitted:
            self._logger.info("ML engine emitted %d alert(s) from %d flows", alerts_emitted, len(flows))

    def _emit_alert(self, flow, prediction) -> None:
        """Build, log, and persist one ML-generated alert."""
        from detection.rule_engine import Alert  # local import to avoid circular deps

        severity = self._SEVERITY_MAP.get(prediction.attack_type, "MEDIUM")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        description = (
            f"ML detected {prediction.attack_type} "
            f"(confidence {prediction.confidence:.1%}) — "
            f"{flow.packet_count} packets, {flow.byte_count} bytes, "
            f"{flow.flow_duration:.2f}s duration"
        )

        alert = Alert(
            timestamp=timestamp,
            source_ip=flow.src_ip,
            destination_ip=flow.dst_ip,
            attack_type=prediction.attack_type,
            severity=severity,
            description=description,
        )

        message = (
            f"[ML ALERT] {timestamp} | Source={flow.src_ip} | "
            f"Type={prediction.attack_type} | Confidence={prediction.confidence:.1%} | "
            f"Severity={severity}"
        )
        print(message)
        self._logger.warning(
            "ML alert: source=%s attack_type=%s confidence=%.4f severity=%s",
            flow.src_ip,
            prediction.attack_type,
            prediction.confidence,
            severity,
        )

        if self._repository is not None:
            try:
                self._repository.insert_alert(
                    alert,
                    confidence=prediction.confidence,
                    ml_generated=True,
                )
            except Exception as exc:
                self._logger.error("ML alert persistence failed: %s", exc, exc_info=True)


# ---------------------------------------------------------------------------
# IDS Application class
# ---------------------------------------------------------------------------

class AIIDS:
    """
    Top-level application class that owns and coordinates all IDS modules.

    Version 7 adds the AIEngine and MLAlertEmitter layers. All existing
    modules (PacketCapture, TrafficStats, RuleEngine, FlowGenerator, MySQL)
    continue to operate exactly as in previous versions.
    """

    def __init__(self, args: argparse.Namespace) -> None:
        self._args = args
        self._logger = logging.getLogger(self.__class__.__name__)

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
        self._flow_generator = FlowGenerator(
            flow_timeout=args.flow_timeout,
            cleanup_interval=args.flow_cleanup_interval,
            auto_cleanup=True,
        )
        self._capture.register_callback(self._flow_generator)
        self._alert_repository = MySQLAlertRepository()

        # Rule engine (unchanged from v6)
        self._rule_engine: RuleEngine | None = None
        if not args.disable_rules:
            rule_config = DetectionConfig(
                port_scan_window_seconds=args.port_scan_window,
                port_scan_unique_ports=args.port_scan_ports,
                syn_flood_window_seconds=args.syn_window,
                syn_flood_packet_threshold=args.syn_threshold,
                icmp_flood_window_seconds=args.icmp_window,
                icmp_flood_packet_threshold=args.icmp_threshold,
            )
            self._rule_engine = RuleEngine(
                rule_config,
                alert_repository=self._alert_repository,
            )
            self._capture.register_callback(self._rule_engine)

        # ML engine (Version 7)
        self._ai_engine: AIEngine | None = None
        self._ml_emitter: MLAlertEmitter | None = None
        if not args.disable_ml:
            model_path = Path(args.model_path)
            if not model_path.is_absolute():
                model_path = Path(__file__).resolve().parent / model_path
            self._ai_engine = AIEngine(model_path=model_path)
            if self._ai_engine.available:
                self._ml_emitter = MLAlertEmitter(
                    flow_generator=self._flow_generator,
                    ai_engine=self._ai_engine,
                    alert_repository=self._alert_repository,
                    confidence_threshold=args.ml_confidence_threshold,
                )

        self._install_stats_snapshot_hook()
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def run(self) -> None:
        self._print_banner()
        self._logger.info("AI-IDS v7 starting …")
        self._stats.start()

        try:
            self._capture.start()
        except SystemExit:
            self._shutdown(exit_code=1)
        except Exception as exc:
            self._logger.critical("Unexpected error: %s", exc, exc_info=True)
            self._shutdown(exit_code=1)
        else:
            self._shutdown(exit_code=0)

    def _install_stats_snapshot_hook(self) -> None:
        """Publish TrafficStats snapshots and trigger ML classification."""
        snapshot_path = Path(self._args.stats_snapshot_file)
        if not snapshot_path.is_absolute():
            snapshot_path = Path(__file__).resolve().parent / snapshot_path

        ml_emitter = self._ml_emitter  # capture for closure

        def on_report(snapshot) -> None:
            # Write stats snapshot for the Flask dashboard
            try:
                snapshot_path.parent.mkdir(parents=True, exist_ok=True)
                snapshot_path.write_text(
                    json.dumps(snapshot.__dict__, indent=2),
                    encoding="utf-8",
                )
            except OSError as exc:
                self._logger.error("Failed to write stats snapshot: %s", exc)

            # Drain and classify completed flows from the ML engine
            if ml_emitter is not None:
                try:
                    ml_emitter.classify_completed_flows(snapshot)
                except Exception as exc:
                    self._logger.error("ML classification cycle failed: %s", exc, exc_info=True)

        self._stats._on_report = on_report

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def _handle_shutdown(self, signum: int, frame) -> None:
        print("\n\n[*] Shutdown signal received — stopping capture …")
        self._logger.info("Received signal %d — initiating shutdown", signum)
        self._shutdown(exit_code=0)

    def _shutdown(self, exit_code: int = 0) -> None:
        self._logger.info("Shutting down AI-IDS v7 …")
        self._stats.stop()

        # Final ML classification pass before closing flows
        if self._ml_emitter is not None:
            try:
                self._ml_emitter.classify_completed_flows()
            except Exception as exc:
                self._logger.error("Final ML pass failed: %s", exc)

        self._flow_generator.stop(close_active=True)

        # Second ML pass to catch flows closed during stop()
        if self._ml_emitter is not None:
            try:
                self._ml_emitter.classify_completed_flows()
            except Exception as exc:
                self._logger.error("Post-close ML pass failed: %s", exc)

        if not self._args.disable_flow_export:
            self._export_completed_flows()

        self._print_final_report()
        self._logger.info(
            "AI-IDS stopped — %d packets captured",
            self._capture.captured_count,
        )
        sys.exit(exit_code)

    def _export_completed_flows(self) -> None:
        flow_csv = Path(self._args.flow_csv)
        if not flow_csv.is_absolute():
            flow_csv = Path(__file__).resolve().parent / flow_csv
        try:
            rows = self._flow_generator.export_csv(flow_csv)
        except OSError:
            self._logger.error("Flow CSV export failed")
            return
        self._logger.info("Exported %d completed flows to %s", rows, flow_csv)
        print(f"[*] Exported {rows} completed flows to {flow_csv}")

    # ------------------------------------------------------------------
    # Console output
    # ------------------------------------------------------------------

    def _print_banner(self) -> None:
        iface = self._args.interface or "system default"
        filt  = self._args.filter    or "none (capture all)"
        count = self._args.count     or "unlimited"

        ml_status = "✔ ML Detection (AI Engine)" if (
            self._ai_engine and self._ai_engine.available
        ) else "✘ ML Detection (model not found — run ml/train_model.py)"

        banner = f"""
╔══════════════════════════════════════════════════════════╗
║        AI-Powered Intrusion Detection System v7          ║
╠══════════════════════════════════════════════════════════╣
║  Interface  : {iface:<41}║
║  BPF Filter : {filt:<41}║
║  Pkt Limit  : {str(count):<41}║
║  Stats Every: {str(self._args.interval) + 's':<41}║
╠══════════════════════════════════════════════════════════╣
║  Modules Active:                                        ║
║    ✔ Packet Capture (Scapy)                             ║
║    ✔ Traffic Statistics                                 ║
║    ✔ Rule-Based Detection                               ║
║    ✔ Flow Generator                                     ║
║    ✔ MySQL Alert Logging                                ║
║    ✔ Flask Dashboard Data Feed                          ║
║    {ml_status:<53}║
╚══════════════════════════════════════════════════════════╝
"""
        print(banner)

    def _print_final_report(self) -> None:
        snap = self._stats.get_snapshot()
        total = snap.total_packets or 1
        ml_alerts = self._alert_repository.count_ml_alerts() if self._alert_repository.available else "N/A"

        print(f"""
╔══════════════════════════════════════════════════════════╗
║                 FINAL SESSION REPORT (v7)               ║
╠══════════════════════════════════════════════════════════╣
║  Total Packets  : {snap.total_packets:<38}║
║  Total Bytes    : {TrafficStats._human_bytes(snap.total_bytes):<38}║
║  TCP  Packets   : {snap.tcp_packets:<6} ({snap.tcp_packets / total * 100:5.1f}%)                        ║
║  UDP  Packets   : {snap.udp_packets:<6} ({snap.udp_packets / total * 100:5.1f}%)                        ║
║  ICMP Packets   : {snap.icmp_packets:<6} ({snap.icmp_packets / total * 100:5.1f}%)                        ║
║  Other Packets  : {snap.other_packets:<6} ({snap.other_packets / total * 100:5.1f}%)                        ║
╠══════════════════════════════════════════════════════════╣
║  Total DB Alerts: {self._alert_repository.count_alerts() if self._alert_repository.available else 'N/A':<38}║
║  ML Alerts      : {str(ml_alerts):<38}║
╚══════════════════════════════════════════════════════════╝
""")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = _build_arg_parser()
    args   = parser.parse_args()
    _configure_logging(args.log_level, args.log_file)
    ids = AIIDS(args)
    ids.run()


if __name__ == "__main__":
    main()