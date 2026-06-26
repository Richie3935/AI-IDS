"""
dashboard.app - Flask monitoring dashboard for AI-IDS.

The dashboard reads alerts from MySQL and traffic counters from the snapshot
written by the existing TrafficStats module. It does not implement duplicate
detection or packet-processing logic.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

from flask import Flask, render_template, request

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from database import MySQLAlertRepository

logger = logging.getLogger(__name__)


def create_app() -> Flask:
    """Create and configure the Flask dashboard application."""
    app = Flask(__name__)
    repository = MySQLAlertRepository()
    stats_path = Path(
        os.getenv(
            "AI_IDS_STATS_FILE",
            PROJECT_ROOT / "dashboard" / "static" / "stats_snapshot.json",
        )
    )

    @app.route("/")
    def home():
        latest_alerts = repository.fetch_alerts(limit=5)
        stats = _load_stats_snapshot(stats_path)
        return render_template(
            "home.html",
            total_packets=stats.get("total_packets", 0),
            total_alerts=repository.count_alerts(),
            active_threats=repository.count_active_threats(),
            latest_alerts=latest_alerts,
            db_available=repository.available,
        )

    @app.route("/alerts")
    def alerts():
        search = request.args.get("search", "").strip()
        attack_type = request.args.get("attack_type", "").strip()
        severity = request.args.get("severity", "").strip()
        return render_template(
            "alerts.html",
            alerts=repository.fetch_alerts(
                search=search or None,
                attack_type=attack_type or None,
                severity=severity or None,
                limit=None,
            ),
            attack_types=repository.distinct_values("attack_type"),
            severities=repository.distinct_values("severity"),
            filters={
                "search": search,
                "attack_type": attack_type,
                "severity": severity,
            },
            db_available=repository.available,
        )

    @app.route("/statistics")
    def statistics():
        stats = _load_stats_snapshot(stats_path)
        attack_counts = repository.attack_counts()
        return render_template(
            "statistics.html",
            stats=stats,
            attack_counts=attack_counts,
            db_available=repository.available,
        )

    return app


def _load_stats_snapshot(path: Path) -> dict:
    """Load the latest TrafficStats JSON snapshot, if the IDS has written one."""
    try:
        if not path.exists():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("Failed to read traffic stats snapshot: %s", exc)
        return {}


app = create_app()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(host="0.0.0.0", port=int(os.getenv("AI_IDS_DASHBOARD_PORT", "5000")))
