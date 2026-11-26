"""
CyberShield - Monitoring Database

Stores device inventory, security events,
and monitoring scan history using SQLite.
"""

import json
import sqlite3

from pathlib import Path


# Database location
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"

DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "cybershield.db"


def get_connection():

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():

    with get_connection() as connection:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                ip TEXT PRIMARY KEY,
                mac TEXT,
                status TEXT,
                last_seen TEXT
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                ip TEXT,
                mac TEXT,
                message TEXT,
                timestamp TEXT
            )
        """)

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


def save_security_events(events):

    with get_connection() as connection:

        for event in events:

            connection.execute("""
                INSERT INTO security_events
                (type, severity, ip, mac, message, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                event.get("type"),
                event.get("severity"),
                event.get("ip"),
                event.get("mac"),
                event.get("message"),
                event.get("timestamp")
            ))


def get_security_events(limit=100):

    with get_connection() as connection:

        rows = connection.execute("""
            SELECT * FROM security_events
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

        return [dict(row) for row in rows]


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
