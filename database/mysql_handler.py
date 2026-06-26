"""
database.mysql_handler - MySQL alert persistence for AI-IDS.

The repository uses mysql-connector-python connection pooling and keeps all
database failures contained so packet capture and rule detection can continue
when MySQL is temporarily unavailable.
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator

try:
    import mysql.connector
    from mysql.connector import Error
    from mysql.connector.pooling import MySQLConnectionPool
except ImportError:  # pragma: no cover - exercised when dependency is absent
    mysql = None
    Error = Exception
    MySQLConnectionPool = None

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MySQLConfig:
    """MySQL connection settings loaded from environment variables."""

    host: str = os.getenv("AI_IDS_DB_HOST", "localhost")
    port: int = int(os.getenv("AI_IDS_DB_PORT", "3306"))
    user: str = os.getenv("AI_IDS_DB_USER", "root")
    password: str = os.getenv("AI_IDS_DB_PASSWORD", "rachell09")
    database: str = os.getenv("AI_IDS_DB_NAME", "ai_ids")
    pool_name: str = os.getenv("AI_IDS_DB_POOL_NAME", "ai_ids_pool")
    pool_size: int = int(os.getenv("AI_IDS_DB_POOL_SIZE", "5"))


class MySQLAlertRepository:
    """Persist IDS alerts and provide read queries for the dashboard."""

    def __init__(self, config: MySQLConfig | None = None) -> None:
        self._config = config or MySQLConfig()
        self._pool = None
        self._available = False
        self._initialise_pool()

    @property
    def available(self) -> bool:
        """Return whether the repository currently has a connection pool."""
        return self._available

    def _initialise_pool(self) -> None:
        if MySQLConnectionPool is None:
            logger.error(
                "mysql-connector-python is not installed; alert persistence disabled"
            )
            return

        try:
            self._pool = MySQLConnectionPool(
                pool_name=self._config.pool_name,
                pool_size=self._config.pool_size,
                pool_reset_session=True,
                host=self._config.host,
                port=self._config.port,
                user=self._config.user,
                password=self._config.password,
                database=self._config.database,
            )
            self._available = True
            logger.info(
                "MySQL alert repository connected to %s:%s/%s",
                self._config.host,
                self._config.port,
                self._config.database,
            )
        except Error as exc:
            self._available = False
            logger.error("MySQL connection pool initialisation failed: %s", exc)

    @contextmanager
    def _connection(self) -> Iterator:
        if not self._available or self._pool is None:
            yield None
            return

        connection = None
        try:
            connection = self._pool.get_connection()
            yield connection
        except Error as exc:
            logger.error("MySQL connection error: %s", exc, exc_info=True)
            yield None
        finally:
            if connection is not None and connection.is_connected():
                connection.close()

    def insert_alert(self, alert) -> bool:
        """Insert one rule-engine alert using a parameterized query."""
        query = """
            INSERT INTO alerts (
                timestamp,
                source_ip,
                destination_ip,
                attack_type,
                severity,
                description
            )
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        params = (
            alert.timestamp,
            alert.source_ip,
            alert.destination_ip,
            alert.attack_type,
            alert.severity,
            alert.description,
        )

        with self._connection() as connection:
            if connection is None:
                logger.warning("Alert not persisted because MySQL is unavailable")
                return False

            try:
                with connection.cursor() as cursor:
                    cursor.execute(query, params)
                connection.commit()
                return True
            except Error as exc:
                connection.rollback()
                logger.error("Failed to insert alert into MySQL: %s", exc, exc_info=True)
                return False

    def fetch_alerts(
        self,
        search: str | None = None,
        attack_type: str | None = None,
        severity: str | None = None,
        limit: int | None = 100,
    ) -> list[dict]:
        """Fetch alerts for dashboard tables with optional filters."""
        clauses = []
        params: list[str | int] = []

        if search:
            like = f"%{search}%"
            clauses.append(
                "(source_ip LIKE %s OR destination_ip LIKE %s OR description LIKE %s)"
            )
            params.extend([like, like, like])
        if attack_type:
            clauses.append("attack_type = %s")
            params.append(attack_type)
        if severity:
            clauses.append("severity = %s")
            params.append(severity)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        query = f"""
            SELECT id, timestamp, source_ip, destination_ip, attack_type,
                   severity, description
            FROM alerts
            {where}
            ORDER BY timestamp DESC, id DESC
        """
        if limit is not None:
            query += " LIMIT %s"
            params.append(int(limit))

        return self._fetch_all(query, tuple(params))

    def count_alerts(self) -> int:
        """Return the total number of stored alerts."""
        rows = self._fetch_all("SELECT COUNT(*) AS total FROM alerts")
        return int(rows[0]["total"]) if rows else 0

    def count_active_threats(self) -> int:
        """Count unique sources that alerted in the last hour."""
        rows = self._fetch_all(
            """
            SELECT COUNT(DISTINCT source_ip) AS total
            FROM alerts
            WHERE timestamp >= NOW() - INTERVAL 1 HOUR
            """
        )
        return int(rows[0]["total"]) if rows else 0

    def attack_counts(self) -> list[dict]:
        """Return grouped alert counts by attack type."""
        return self._fetch_all(
            """
            SELECT attack_type, COUNT(*) AS total
            FROM alerts
            GROUP BY attack_type
            ORDER BY total DESC
            """
        )

    def distinct_values(self, column: str) -> list[str]:
        """Return distinct values for whitelisted filter columns."""
        if column not in {"attack_type", "severity"}:
            raise ValueError("Unsupported distinct-value column")
        rows = self._fetch_all(
            f"SELECT DISTINCT {column} AS value FROM alerts ORDER BY {column}"
        )
        return [row["value"] for row in rows]

    def _fetch_all(self, query: str, params: tuple | None = None) -> list[dict]:
        with self._connection() as connection:
            if connection is None:
                return []

            try:
                with connection.cursor(dictionary=True) as cursor:
                    cursor.execute(query, params or ())
                    return list(cursor.fetchall())
            except Error as exc:
                logger.error("MySQL query failed: %s", exc, exc_info=True)
                return []
