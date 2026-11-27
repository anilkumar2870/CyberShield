"""
CyberShield - Persistent SSH Threat Tracking

Tracks unique failed SSH authentication records in SQLite
and detects repeated failures within a rolling time window.
"""

import hashlib
import ipaddress
import re
import sqlite3

from datetime import datetime, timedelta, timezone

from modules.monitoring_database import DB_PATH


# ==========================================
# CONFIGURATION
# ==========================================

DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW_MINUTES = 15


# ==========================================
# DATABASE INITIALIZATION
# ==========================================

def initialize_ssh_tracking():

    with sqlite3.connect(DB_PATH) as connection:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS ssh_failed_attempts (
                fingerprint TEXT PRIMARY KEY,
                source_ip TEXT NOT NULL,
                event_time TEXT NOT NULL,
                processed_at TEXT NOT NULL
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_ssh_failed_ip_time
            ON ssh_failed_attempts(source_ip, event_time)
        """)


# ==========================================
# SOURCE IP EXTRACTION
# ==========================================

def extract_source_ip(log_line):

    match = re.search(
        r"\bfrom\s+([0-9a-fA-F:.]+)",
        log_line
    )

    if not match:
        return None

    try:
        return str(ipaddress.ip_address(match.group(1)))
    except ValueError:
        return None


# ==========================================
# JOURNAL TIMESTAMP EXTRACTION
# ==========================================

def extract_log_timestamp(log_line):

    if not log_line:
        return None

    timestamp_text = log_line.split(maxsplit=1)[0]

    try:
        timestamp = datetime.fromisoformat(timestamp_text)

        if timestamp.tzinfo is None:
            return None

        return timestamp.astimezone(timezone.utc)

    except ValueError:
        return None


# ==========================================
# PERSISTENT FAILED LOGIN ANALYSIS
# ==========================================

def analyze_persistent_ssh_threats(
    logs,
    threshold=DEFAULT_THRESHOLD,
    window_minutes=DEFAULT_WINDOW_MINUTES
):
    """
    Store unique failed SSH records and detect repeated
    failures from the same source IP within a rolling window.
    """

    if not isinstance(logs, (list, tuple)):
        return {
            "success": False,
            "error": "SSH logs must be provided as a list."
        }

    if (
        not isinstance(threshold, int)
        or isinstance(threshold, bool)
        or threshold < 1
    ):
        return {
            "success": False,
            "error": "Threshold must be a positive integer."
        }

    if (
        not isinstance(window_minutes, int)
        or isinstance(window_minutes, bool)
        or window_minutes < 1
    ):
        return {
            "success": False,
            "error": "Time window must be a positive integer."
        }

    initialize_ssh_tracking()

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=window_minutes)

    processed = 0
    ignored = 0

    failed_pattern = re.compile(
        r"\bFailed password\b|\bauthentication failure\b",
        re.IGNORECASE
    )

    # Insert each unique failed authentication record.
    with sqlite3.connect(DB_PATH) as connection:

        for log_line in logs:

            if not isinstance(log_line, str):
                ignored += 1
                continue

            if not failed_pattern.search(log_line):
                continue

            source_ip = extract_source_ip(log_line)
            event_time = extract_log_timestamp(log_line)

            # Do not count records without a valid source IP
            # or a trustworthy journal timestamp.
            if source_ip is None or event_time is None:
                ignored += 1
                continue

            # Ignore records outside the rolling window.
            if event_time < cutoff:
                continue

            fingerprint = hashlib.sha256(
                log_line.strip().encode("utf-8")
            ).hexdigest()

            cursor = connection.execute("""
                INSERT OR IGNORE INTO ssh_failed_attempts
                (
                    fingerprint,
                    source_ip,
                    event_time,
                    processed_at
                )
                VALUES (?, ?, ?, ?)
            """, (
                fingerprint,
                source_ip,
                event_time.isoformat(),
                now.isoformat()
            ))

            if cursor.rowcount == 1:
                processed += 1

    # Count all unique attempts in the rolling window.
    events = []
    source_counts = {}

    with sqlite3.connect(DB_PATH) as connection:

        rows = connection.execute("""
            SELECT source_ip, COUNT(*) AS attempt_count
            FROM ssh_failed_attempts
            WHERE event_time >= ?
            GROUP BY source_ip
        """, (
            cutoff.isoformat(),
        )).fetchall()

        for source_ip, attempt_count in rows:

            source_counts[source_ip] = attempt_count

            if attempt_count < threshold:
                continue

            events.append({
                "type": "REPEATED_SSH_LOGIN_FAILURES",
                "severity": "High",
                "ip": source_ip,
                "mac": "Not available",
                "message": (
                    f"At least {threshold} failed SSH login attempts "
                    f"detected from {source_ip} within "
                    f"{window_minutes} minutes."
                ),
                "timestamp": now.isoformat()
            })

    return {
        "success": True,
        "new_records_processed": processed,
        "records_ignored": ignored,
        "threshold": threshold,
        "window_minutes": window_minutes,
        "source_counts": source_counts,
        "events": events,
        "event_count": len(events),
        "analysis_time": now.isoformat()
    }
