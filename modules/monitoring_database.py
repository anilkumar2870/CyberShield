"""
CyberShield - Monitoring Database

Stores:
1. Network device inventory
2. Security events and alerts
3. Alert acknowledgement and resolution details
4. Investigation notes
5. Monitoring scan history
6. SSH security events with duplicate prevention

Database: SQLite
"""

import json
import sqlite3

from datetime import datetime, timedelta, timezone
from pathlib import Path


# ==========================================
# DATABASE CONFIGURATION
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"

DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "cybershield.db"


# ==========================================
# DATABASE CONNECTION
# ==========================================

def get_connection():

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row

    return connection


# ==========================================
# DATABASE INITIALIZATION
# ==========================================

def initialize_database():

    with get_connection() as connection:

        # Device inventory
        connection.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                ip TEXT PRIMARY KEY,
                mac TEXT,
                status TEXT,
                last_seen TEXT
            )
        """)

        # Security events and alert management
        connection.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                ip TEXT,
                mac TEXT,
                message TEXT,
                timestamp TEXT,
                status TEXT DEFAULT 'New',
                acknowledged_at TEXT,
                resolved_at TEXT,
                investigation_notes TEXT,
                source_ip_category TEXT,
                source_ip_is_public INTEGER,
                source_ip_geolocation TEXT,
                source_ip_reputation TEXT,
                source_ip_note TEXT
            )
        """)

        # Monitoring scan history
        connection.execute("""
            CREATE TABLE IF NOT EXISTS monitoring_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                network TEXT,
                total INTEGER,
                event_count INTEGER,
                scanner TEXT,
                monitoring_time TEXT,
                result_json TEXT
            )
        """)

        # Safely upgrade existing security_events tables.
        # Existing records are preserved.

        existing_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(security_events)"
            ).fetchall()
        }

        new_columns = {
            "status": "TEXT DEFAULT 'New'",
            "acknowledged_at": "TEXT",
            "resolved_at": "TEXT",
            "investigation_notes": "TEXT",
            "source_ip_category": "TEXT",
            "source_ip_is_public": "INTEGER",
            "source_ip_geolocation": "TEXT",
            "source_ip_reputation": "TEXT",
            "source_ip_note": "TEXT"
        }

        for column_name, column_type in new_columns.items():

            if column_name not in existing_columns:

                connection.execute(
                    f"ALTER TABLE security_events "
                    f"ADD COLUMN {column_name} {column_type}"
                )

        # Assign New status to existing events
        connection.execute("""
            UPDATE security_events
            SET status = 'New'
            WHERE status IS NULL OR status = ''
        """)


# ==========================================
# DEVICE INVENTORY
# ==========================================

def get_previous_devices():

    with get_connection() as connection:

        rows = connection.execute(
            "SELECT * FROM devices"
        ).fetchall()

        return {
            row["ip"]: dict(row)
            for row in rows
        }


def save_devices(devices, timestamp):

    with get_connection() as connection:

        connection.execute("DELETE FROM devices")

        for device in devices:

            connection.execute("""
                INSERT INTO devices
                (ip, mac, status, last_seen)
                VALUES (?, ?, ?, ?)
            """, (
                device.get("ip"),
                device.get("mac", "Not available"),
                device.get("status", "Active"),
                timestamp
            ))


# ==========================================
# GENERAL SECURITY EVENT STORAGE
# ==========================================

def save_security_events(events):

    with get_connection() as connection:

        for event in events:

            connection.execute("""
                INSERT INTO security_events
                (
                    type,
                    severity,
                    ip,
                    mac,
                    message,
                    timestamp,
                    status
                )
                VALUES (?, ?, ?, ?, ?, ?, 'New')
            """, (
                event.get("type"),
                event.get("severity"),
                event.get("ip"),
                event.get("mac"),
                event.get("message"),
                event.get("timestamp")
            ))


# ==========================================
# SSH SECURITY EVENT STORAGE
# DUPLICATE PREVENTION
# ==========================================

def save_ssh_security_events(events, lookback_hours=24):
    """
    Save SSH security events without repeatedly inserting
    identical events within the configured lookback period.

    Existing alert records and their statuses are preserved.

    Returns:
        Dictionary containing inserted and skipped counts.
    """

    if not isinstance(events, (list, tuple)):
        raise ValueError("Events must be provided as a list.")

    if (
        not isinstance(lookback_hours, int)
        or isinstance(lookback_hours, bool)
        or lookback_hours < 1
    ):
        raise ValueError(
            "Lookback period must be a positive integer."
        )

    cutoff = (
        datetime.now(timezone.utc)
        - timedelta(hours=lookback_hours)
    ).isoformat()

    inserted = 0
    skipped = 0

    with get_connection() as connection:

        for event in events:

            event_type = event.get("type")
            ip = event.get("ip")
            message = event.get("message")
            severity = event.get("severity")

            if not all([event_type, ip, message, severity]):
                skipped += 1
                continue

            # Check whether an identical event already exists
            # within the configured lookback period.

            existing = connection.execute("""
                SELECT id
                FROM security_events
                WHERE type = ?
                  AND ip = ?
                  AND message = ?
                  AND timestamp >= ?
                LIMIT 1
            """, (
                event_type,
                ip,
                message,
                cutoff
            )).fetchone()

            if existing:

                skipped += 1
                continue

            event_timestamp = event.get("timestamp")

            if not event_timestamp:

                event_timestamp = datetime.now(
                    timezone.utc
                ).isoformat()

            # Optional local IP classification produced by
            # modules.ssh_threat_intelligence. No external lookup is made.
            intelligence = event.get("source_ip_intelligence") or {}

            if not isinstance(intelligence, dict):
                intelligence = {}

            is_public = intelligence.get("is_public")
            if is_public is not None:
                is_public = 1 if is_public else 0

            connection.execute("""
                INSERT INTO security_events
                (
                    type,
                    severity,
                    ip,
                    mac,
                    message,
                    timestamp,
                    status,
                    source_ip_category,
                    source_ip_is_public,
                    source_ip_geolocation,
                    source_ip_reputation,
                    source_ip_note
                )
                VALUES (?, ?, ?, ?, ?, ?, 'New', ?, ?, ?, ?, ?)
            """, (
                event_type,
                severity,
                ip,
                event.get("mac", "Not available"),
                message,
                event_timestamp,
                intelligence.get("category"),
                is_public,
                intelligence.get("geolocation"),
                intelligence.get("reputation"),
                intelligence.get("note")
            ))

            inserted += 1

    return {
        "inserted": inserted,
        "skipped": skipped
    }


# ==========================================
# RETRIEVE SECURITY EVENTS
# ==========================================

def get_security_events(limit=100, status=None, severity=None):
    """
    Retrieve alerts newest-first, optionally filtered by status and severity.

    Valid status values: New, Acknowledged, Resolved.
    Valid severity values: Critical, High, Medium, Low.
    """

    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise ValueError("Alert limit must be a positive integer.")

    allowed_statuses = {"New", "Acknowledged", "Resolved"}
    allowed_severities = {"Critical", "High", "Medium", "Low"}

    if status not in (None, "", "All") and status not in allowed_statuses:
        raise ValueError("Invalid alert status filter.")

    if severity not in (None, "", "All") and severity not in allowed_severities:
        raise ValueError("Invalid alert severity filter.")

    query = """
        SELECT *
        FROM security_events
        WHERE 1 = 1
    """
    parameters = []

    if status not in (None, "", "All"):
        query += " AND status = ?"
        parameters.append(status)

    if severity not in (None, "", "All"):
        query += " AND severity = ?"
        parameters.append(severity)

    query += " ORDER BY id DESC LIMIT ?"
    parameters.append(limit)

    with get_connection() as connection:
        rows = connection.execute(query, parameters).fetchall()
        return [dict(row) for row in rows]


def delete_alerts_by_ids(alert_ids):
    """
    Delete only explicitly selected alert IDs.

    This deliberately does not provide a delete-all operation, helping
    prevent accidental removal of genuine security records.
    Returns the number of deleted records.
    """

    if not isinstance(alert_ids, (list, tuple, set)):
        raise ValueError("Alert IDs must be provided as a list.")

    cleaned_ids = []
    for alert_id in alert_ids:
        if isinstance(alert_id, bool):
            raise ValueError("Alert IDs must be positive integers.")
        try:
            numeric_id = int(alert_id)
        except (TypeError, ValueError):
            raise ValueError("Alert IDs must be positive integers.")
        if numeric_id < 1:
            raise ValueError("Alert IDs must be positive integers.")
        cleaned_ids.append(numeric_id)

    cleaned_ids = sorted(set(cleaned_ids))
    if not cleaned_ids:
        return 0

    placeholders = ",".join("?" for _ in cleaned_ids)

    with get_connection() as connection:
        cursor = connection.execute(
            f"DELETE FROM security_events WHERE id IN ({placeholders})",
            cleaned_ids
        )
        return cursor.rowcount


# ==========================================
# RETRIEVE INDIVIDUAL ALERT
# ==========================================

def get_alert_by_id(alert_id):

    with get_connection() as connection:

        row = connection.execute("""
            SELECT *
            FROM security_events
            WHERE id = ?
        """, (alert_id,)).fetchone()

        return dict(row) if row else None


# ==========================================
# UPDATE ALERT STATUS
# ==========================================

def update_alert_status(alert_id, status):

    allowed_statuses = (
        "New",
        "Acknowledged",
        "Resolved"
    )

    if status not in allowed_statuses:
        raise ValueError("Invalid alert status.")

    timestamp = datetime.now(timezone.utc).isoformat()

    with get_connection() as connection:

        if status == "Acknowledged":

            cursor = connection.execute("""
                UPDATE security_events
                SET status = ?,
                    acknowledged_at = ?,
                    resolved_at = NULL
                WHERE id = ?
            """, (
                status,
                timestamp,
                alert_id
            ))

        elif status == "Resolved":

            cursor = connection.execute("""
                UPDATE security_events
                SET status = ?,
                    resolved_at = ?
                WHERE id = ?
            """, (
                status,
                timestamp,
                alert_id
            ))

        else:

            cursor = connection.execute("""
                UPDATE security_events
                SET status = ?,
                    acknowledged_at = NULL,
                    resolved_at = NULL
                WHERE id = ?
            """, (
                status,
                alert_id
            ))

        return cursor.rowcount > 0


# ==========================================
# INVESTIGATION NOTES
# ==========================================

def update_investigation_notes(alert_id, notes):

    with get_connection() as connection:

        cursor = connection.execute("""
            UPDATE security_events
            SET investigation_notes = ?
            WHERE id = ?
        """, (
            notes,
            alert_id
        ))

        return cursor.rowcount > 0


# ==========================================
# ALERT SUMMARY
# ==========================================

def get_alert_summary():

    with get_connection() as connection:

        row = connection.execute("""
            SELECT
                COUNT(*) AS total,

                COALESCE(
                    SUM(CASE WHEN status = 'New'
                    THEN 1 ELSE 0 END), 0
                ) AS new,

                COALESCE(
                    SUM(CASE WHEN status = 'Acknowledged'
                    THEN 1 ELSE 0 END), 0
                ) AS acknowledged,

                COALESCE(
                    SUM(CASE WHEN status = 'Resolved'
                    THEN 1 ELSE 0 END), 0
                ) AS resolved,

                COALESCE(
                    SUM(CASE WHEN severity = 'Critical'
                    THEN 1 ELSE 0 END), 0
                ) AS critical,

                COALESCE(
                    SUM(CASE WHEN severity = 'High'
                    THEN 1 ELSE 0 END), 0
                ) AS high

            FROM security_events
        """).fetchone()

        return dict(row)


# ==========================================
# MONITORING SCAN HISTORY
# ==========================================

def save_monitoring_scan(result):

    with get_connection() as connection:

        connection.execute("""
            INSERT INTO monitoring_scans
            (
                network,
                total,
                event_count,
                scanner,
                monitoring_time,
                result_json
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            result.get("network"),
            result.get("total"),
            result.get("event_count"),
            result.get("scanner"),
            result.get("monitoring_time"),
            json.dumps(result)
        ))


def get_latest_monitoring_scan():

    with get_connection() as connection:

        row = connection.execute("""
            SELECT result_json
            FROM monitoring_scans
            ORDER BY id DESC
            LIMIT 1
        """).fetchone()

        if row is None:
            return None

        return json.loads(row["result_json"])


def get_scan_history(limit=50):

    with get_connection() as connection:

        rows = connection.execute("""
            SELECT
                id,
                network,
                total,
                event_count,
                scanner,
                monitoring_time
            FROM monitoring_scans
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

        return [dict(row) for row in rows]
