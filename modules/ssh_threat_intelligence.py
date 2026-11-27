"""
CyberShield - SSH Threat Intelligence

Performs local IP-address classification for SSH security events.

Privacy:
- This module does not send IP addresses to external services.
- It does not claim to determine geographic location or reputation.
- Public-IP geolocation and reputation lookups can be added later
  after choosing a provider and approving its data-sharing policy.
"""

import ipaddress


DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)


def classify_ip_address(value):
    """
    Classify an IPv4 or IPv6 address without making a network request.

    Returns a dictionary containing the normalized address, category,
    whether it is globally routable, and safe interpretation notes.
    """

    if not isinstance(value, str) or not value.strip():
        return {
            "success": False,
            "error": "A source IP address is required.",
        }

    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return {
            "success": False,
            "error": "Invalid IPv4 or IPv6 address.",
        }

    if any(address in network for network in DOCUMENTATION_NETWORKS):
        category = "Documentation"
        note = (
            "Reserved for examples and documentation; "
            "not a real-world source location."
        )
    elif address.is_loopback:
        category = "Loopback"
        note = "Local-host address; not a remote public source."
    elif address.is_link_local:
        category = "Link-local"
        note = "Link-local address; not globally routable."
    elif address.is_multicast:
        category = "Multicast"
        note = "Multicast address; not an individual source host."
    elif address.is_unspecified:
        category = "Unspecified"
        note = "Unspecified address; it does not identify a source host."
    elif address.is_global:
        category = "Public"
        note = (
            "Globally routable address. Geographic location and "
            "reputation have not been checked."
        )
    elif address.is_private:
        category = "Private"
        note = "Private network address; public geolocation is not applicable."
    elif address.is_reserved:
        category = "Reserved"
        note = "Special-purpose reserved address; not treated as a public source."
    else:
        category = "Non-public"
        note = "Not globally routable; geographic attribution is unavailable."

    return {
        "success": True,
        "ip": str(address),
        "version": address.version,
        "category": category,
        "is_public": address.is_global,
        "geolocation": "Not queried",
        "reputation": "Not checked",
        "note": note,
    }


def enrich_ssh_events(events):
    """
    Return copied SSH events with local source-IP classification.

    The input event dictionaries are not modified.
    """

    if not isinstance(events, (list, tuple)):
        raise ValueError("Events must be provided as a list or tuple.")

    enriched_events = []

    for event in events:
        if not isinstance(event, dict):
            continue

        enriched = dict(event)
        source_ip = event.get("ip")

        classification = classify_ip_address(source_ip)

        enriched["source_ip_intelligence"] = classification

        enriched_events.append(enriched)

    return enriched_events
