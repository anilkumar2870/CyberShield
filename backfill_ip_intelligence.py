"""
CyberShield - Backfill IP Intelligence for Existing Alerts

Run from the CyberShield project root:
    python backfill_ip_intelligence.py

This performs local IP classification only. It does not contact
geolocation or reputation services and does not change alert status,
acknowledgement timestamps, resolution timestamps, or investigation notes.
"""

from modules.monitoring_database import get_connection
from modules.ssh_threat_intelligence import classify_ip_address


def main():
    updated = 0
    skipped = 0

    with get_connection() as connection:
        rows = connection.execute("""
            SELECT id, ip
            FROM security_events
            WHERE ip IS NOT NULL AND TRIM(ip) != ''
        """).fetchall()

        for row in rows:
            result = classify_ip_address(row["ip"])

            if not result.get("success"):
                skipped += 1
                continue

            is_public = 1 if result["is_public"] else 0

            connection.execute("""
                UPDATE security_events
                SET source_ip_category = ?,
                    source_ip_is_public = ?,
                    source_ip_geolocation = ?,
                    source_ip_reputation = ?,
                    source_ip_note = ?
                WHERE id = ?
            """, (
                result["category"],
                is_public,
                result["geolocation"],
                result["reputation"],
                result["note"],
                row["id"],
            ))

            updated += 1

    print("IP intelligence backfill completed.")
    print("Alerts updated:", updated)
    print("Alerts skipped:", skipped)
    print("Geolocation: Not queried")
    print("Reputation: Not checked")


if __name__ == "__main__":
    main()
