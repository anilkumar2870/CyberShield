"""
CyberShield - Network Discovery Module

This module forwards authorized network discovery
requests to Kali Linux through the SSH connector.
"""

from modules.kali_connector import discover_network_on_kali


def discover_network(target):

    """
    Perform network discovery using Kali Linux.

    Args:
        target: Private IPv4 network range.

    Returns:
        Dictionary containing discovered devices
        or an error message.
    """

    if not target or not target.strip():
        return {
            "error": "Please enter a network range."
        }

    result = discover_network_on_kali(target.strip())

    return result
