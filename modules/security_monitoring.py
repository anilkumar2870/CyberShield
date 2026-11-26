"""
CyberShield - Security Monitoring Module

Monitors authorized private networks using Kali Linux
and detects changes in discovered network devices.

Features:
1. Device availability monitoring
2. Newly observed device detection
3. Previously observed device disappearance detection
4. Device identity change detection
5. Security event generation
"""

from datetime import datetime, timezone

from modules.kali_connector import discover_network_on_kali


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
            "error": result.get("error", "Network monitoring failed.")
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

                events.append({
                    "type": "NEW_DEVICE",
                    "severity": "Medium",
                    "ip": ip,
                    "mac": device.get("mac", "Not available"),
                    "message": f"New device observed: {ip}",
                    "timestamp": timestamp
                })

            else:

                old_mac = previous.get("mac", "Not available")
                new_mac = device.get("mac", "Not available")

                if (
                    old_mac != "Not available"
                    and new_mac != "Not available"
                    and old_mac.lower() != new_mac.lower()
                ):

                    events.append({
                        "type": "DEVICE_IDENTITY_CHANGED",
                        "severity": "High",
                        "ip": ip,
                        "mac": new_mac,
                        "previous_mac": old_mac,
                        "message": f"MAC address changed for device {ip}",
                        "timestamp": timestamp
                    })

        # Detect previously observed devices that disappeared
        for ip, device in previous_devices.items():

            if ip not in current_devices:

                events.append({
                    "type": "DEVICE_OFFLINE",
                    "severity": "Low",
                    "ip": ip,
                    "mac": device.get("mac", "Not available"),
                    "message": f"Previously observed device is no longer visible: {ip}",
                    "timestamp": timestamp
                })

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