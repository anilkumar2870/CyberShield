"""
CyberShield - Security Reports Module

Generates security assessment report data
from historical monitoring scan records.
"""

import json

from modules.monitoring_database import get_connection


# ==========================================
# RETRIEVE AVAILABLE REPORTS
# ==========================================

def get_available_reports(limit=100):

    try:

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

            reports = [dict(row) for row in rows]

            return {
                "success": True,
                "total": len(reports),
                "reports": reports
            }

    except Exception as error:

        return {
            "success": False,
            "error": str(error),
            "reports": []
        }


# ==========================================
# GENERATE REPORT DATA
# ==========================================

def generate_security_report(scan_id):

    try:

        scan_id = int(scan_id)

        if scan_id <= 0:
            return {
                "success": False,
                "error": "Invalid scan ID."
            }

        with get_connection() as connection:

            row = connection.execute("""
                SELECT *
                FROM monitoring_scans
                WHERE id = ?
            """, (scan_id,)).fetchone()

            if row is None:

                return {
                    "success": False,
                    "error": "Scan record not found."
                }

            scan = dict(row)

        # Retrieve saved scan results
        try:

            result = json.loads(
                scan.get("result_json") or "{}"
            )

        except json.JSONDecodeError:

            return {
                "success": False,
                "error": "Unable to read saved scan results."
            }

        if not isinstance(result, dict):

            return {
                "success": False,
                "error": "Invalid scan result format."
            }

        devices = result.get("devices", [])
        events = result.get("events", [])

        if not isinstance(devices, list):
            devices = []

        if not isinstance(events, list):
            events = []

        # Build report
        report = {

            "success": True,

            "report_id": scan["id"],

            "generated_for": "CyberShield",

            "network": scan["network"],

            "total_devices": scan["total"] or 0,

            "event_count": scan["event_count"] or 0,

            "scanner": scan["scanner"],

            "scan_time": scan["monitoring_time"],

            "devices": devices,

            "events": events

        }

        return report

    except (ValueError, TypeError):

        return {
            "success": False,
            "error": "Invalid scan ID."
        }

    except Exception as error:

        return {
            "success": False,
            "error": str(error)
        }
