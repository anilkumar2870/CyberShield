"""
CyberShield - Scan History Module

Retrieves previous network monitoring scans
from the CyberShield SQLite database.
"""

import sqlite3
import json
from pathlib import Path


DATABASE_PATH = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "cybershield.db"
)


def get_scan_history(limit=100):

    conn = None

    try:

        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row

        rows = conn.execute("""
            SELECT
                id,
                network,
                total,
                event_count,
                scanner,
                monitoring_time,
                result_json
            FROM monitoring_scans
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

        scans = []

        for row in rows:

            scan = dict(row)

            try:
                scan["devices"] = json.loads(
                    scan["result_json"]
                ).get("devices", [])

            except (json.JSONDecodeError, TypeError):
                scan["devices"] = []

            scans.append(scan)

        return {
            "success": True,
            "total": len(scans),
            "scans": scans
        }

    except sqlite3.Error as error:

        return {
            "success": False,
            "error": str(error),
            "scans": []
        }

    finally:

        if conn:
            conn.close()


def get_scan_by_id(scan_id):

    try:
        scan_id = int(scan_id)

        if scan_id <= 0:
            return None

    except (ValueError, TypeError):
        return None

    result = get_scan_history(limit=1000)

    if not result["success"]:
        return None

    for scan in result["scans"]:

        if scan["id"] == scan_id:
            return scan

    return None
