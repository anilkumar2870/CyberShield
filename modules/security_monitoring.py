"""
CyberShield - Security Monitoring Module

Monitors authorized private networks using Kali Linux
and detects changes in discovered network devices.

Features:
1. Device availability monitoring
2. Newly observed device detection
3. Previously observed device disappearance detection
4. Device identity change detection
5. Intelligent security event severity classification
6. Security event generation
"""

from datetime import datetime, timezone

from modules.kali_connector import discover_network_on_kali


def classify_event_severity(event_type):
    """
    Assign severity based on the security event type.

    """

    severity_rules = {
        "CONFIRMED_UNAUTHORIZED_ACCESS": "Critical",
        "DEVICE_IDENTITY_CHANGED": "High",
        "NEW_DEVICE": "Medium",
        "DEVICE_OFFLINE": "Low"
    }

    return severity_rules.get(event_type, "Medium")


def create_security_event(
    event_type,
    ip,
    mac,
    message,
    timestamp,
    previous_mac=None
):
    """
    Create a standardized security event.
    """

    event = {
        "type": event_type,
        "severity": classify_event_severity(event_type),
        "ip": ip,
        "mac": mac,
        "message": message,
        "timestamp": timestamp
    }

    if previous_mac is not None:
        event["previous_mac"] = previous_mac

    return event


def monitor_network(target, previous_devices=None):
    """
    Monitor an authorized private network.

    Args:
        target: Private IPv4 CIDR network.
        previous_devices: Previous successful device inventory.

    Returns:
        Dictionary containing current devices and security events.
    """

    # Validate input
    if not target or not target.strip():
        return {
            "success": False,
            "error": "Please enter a network range."
        }

    # Perform network discovery through Kali Linux
    result = discover_network_on_kali(target.strip())

    # Stop if discovery failed
    if not result.get("success"):
        return {
            "success": False,
            "error": result.get(
                "error",
                "Network monitoring failed."
            )
        }

    # Current successful device inventory
    devices = result.get("devices", [])

    # Normalize previous inventory
    previous_devices = previous_devices or {}

    if isinstance(previous_devices, list):
        previous_devices = {
            device["ip"]: device
            for device in previous_devices
            if device.get("ip")
        }

    current_devices = {
        device["ip"]: device
        for device in devices
        if device.get("ip")
    }

    events = []

    timestamp = datetime.now(timezone.utc).isoformat()

    # Compare current devices with previous inventory
    if previous_devices:

        # Detect new devices and identity changes
        for ip, device in current_devices.items():

            previous = previous_devices.get(ip)

            if previous is None:

                events.append(
                    create_security_event(
                        event_type="NEW_DEVICE",
                        ip=ip,
                        mac=device.get("mac", "Not available"),
                        message=f"New device observed: {ip}",
                        timestamp=timestamp
                    )
                )

            else:

                old_mac = previous.get("mac", "Not available")
                new_mac = device.get("mac", "Not available")

                if (
                    old_mac != "Not available"
                    and new_mac != "Not available"
                    and old_mac.lower() != new_mac.lower()
                ):

                    events.append(
                        create_security_event(
                            event_type="DEVICE_IDENTITY_CHANGED",
                            ip=ip,
                            mac=new_mac,
                            previous_mac=old_mac,
                            message=f"MAC address changed for device {ip}",
                            timestamp=timestamp
                        )
                    )

        # Detect previously observed devices that disappeared
        for ip, device in previous_devices.items():

            if ip not in current_devices:

                events.append(
                    create_security_event(
                        event_type="DEVICE_OFFLINE",
                        ip=ip,
                        mac=device.get("mac", "Not available"),
                        message=(
                            "Previously observed device is no longer "
                            f"visible: {ip}"
                        ),
                        timestamp=timestamp
                    )
                )

    return {
        "success": True,
        "network": result.get("network"),
        "total": len(devices),
        "devices": devices,
        "events": events,
        "event_count": len(events),
        "monitoring_time": timestamp,
        "scanner": result.get("scanner", "Kali Linux")
    }
