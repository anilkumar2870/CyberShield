"""
CyberShield - SSH Threat Tracking Integration Test

Creates five simulated failed SSH login records using a reserved
documentation IP address, checks persistent detection, saves any
detected event to the existing security_events database table,
and verifies that the alert can be read back.

Run from the CyberShield project root with:
    python -m modules.test_ssh_threat_tracking
"""

from datetime import datetime, timezone

from modules.ssh_threat_tracking import (
    analyze_persistent_ssh_threats,
)

from modules.monitoring_database import (
    save_ssh_security_events,
    get_security_events,
)


def main():
    # Reserved documentation IP; no real device is contacted.
    test_ip = "192.0.2.123"
    timestamp = datetime.now(timezone.utc).isoformat()

    # Five distinct simulated failed-login records.
    test_logs = [
        (
            f"{timestamp} kali sshd[1234]: "
            f"Failed password for invalid user testuser "
            f"from {test_ip} port {port} ssh2"
        )
        for port in range(2300, 2305)
    ]

    print("\n========== SSH THREAT DETECTION ==========")

    detection = analyze_persistent_ssh_threats(
        test_logs,
        threshold=5,
        window_minutes=15,
    )

    if not detection.get("success"):
        raise RuntimeError(
            detection.get("error", "SSH threat detection failed.")
        )

    print("Detection successful:", detection["success"])
    print("New records processed:", detection["new_records_processed"])
    print("Events detected:", detection["event_count"])
    print("Source counts:", detection["source_counts"])

    events = detection.get("events", [])

    for event in events:
        print("Event type:", event.get("type"))
        print("Severity:", event.get("severity"))
        print("Source IP:", event.get("ip"))
        print("Message:", event.get("message"))

    print("\n========== SAVING SECURITY ALERTS ==========")

    storage = save_ssh_security_events(events)

    print("New alerts inserted:", storage.get("inserted", 0))
    print("Duplicate alerts skipped:", storage.get("skipped", 0))

    print("\n========== DATABASE VERIFICATION ==========")

    alerts = get_security_events(limit=100)
    matching_alerts = [
        alert for alert in alerts
        if alert.get("ip") == test_ip
        and alert.get("type") == "REPEATED_SSH_LOGIN_FAILURES"
    ]

    if matching_alerts:
        alert = matching_alerts[0]
        print("Alert found in database.")
        print("Alert ID:", alert.get("id"))
        print("Alert type:", alert.get("type"))
        print("Severity:", alert.get("severity"))
        print("Source IP:", alert.get("ip"))
        print("Message:", alert.get("message"))
        print("Status:", alert.get("status", "New"))
    else:
        print(
            "No matching alert was found. Check that the event was "
            "generated and that save_ssh_security_events stores it."
        )

    print("\n========== INTEGRATION TEST COMPLETED ==========")


if __name__ == "__main__":
    main()
