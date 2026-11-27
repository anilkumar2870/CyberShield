"""
CyberShield - SSH Security Analysis

Analyzes SSH authentication logs retrieved from Kali Linux.

Features:
1. Failed SSH login detection
2. Invalid username detection
3. Successful SSH login detection
4. Repeated failed login detection
5. Approved-source IP policy checks
6. Security event generation
"""

import ipaddress
import re

from datetime import datetime, timezone


# ==========================================
# SECURITY CONFIGURATION
# ==========================================

DEFAULT_FAILED_LOGIN_THRESHOLD = 5


# ==========================================
# SOURCE IP EXTRACTION
# ==========================================

def extract_source_ip(log_line):
    """
    Extract and validate a source IP address
    from an SSH authentication log.
    """

    patterns = [
        r"\bfrom\s+([0-9a-fA-F:.]+)",
        r"\brhost=([0-9a-fA-F:.]+)"
    ]

    for pattern in patterns:

        match = re.search(pattern, log_line)

        if match:

            candidate = match.group(1)

            try:
                return str(ipaddress.ip_address(candidate))

            except ValueError:
                continue

    return None


# ==========================================
# LOG ANALYSIS
# ==========================================

def analyze_ssh_logs(
    logs,
    approved_ips=None,
    failed_threshold=DEFAULT_FAILED_LOGIN_THRESHOLD
):
    """
    Analyze SSH authentication logs.

    Args:
        logs: List of SSH journal log lines.
        approved_ips: Explicitly approved source IP addresses.
        failed_threshold: Number of failed attempts
                          required to generate a High alert.

    Returns:
        Dictionary containing analysis results and security events.
    """

    if not isinstance(logs, (list, tuple)):
        return {
            "success": False,
            "error": "SSH logs must be provided as a list."
        }

    if not isinstance(failed_threshold, int) or failed_threshold < 1:
        return {
            "success": False,
            "error": "Failed login threshold must be a positive integer."
        }

    # Validate approved IP addresses.
    # None means no approved-source policy was supplied.
    if approved_ips is not None:

        if not isinstance(approved_ips, (list, tuple, set)):
            return {
                "success": False,
                "error": "Approved IP addresses must be a list or set."
            }

        try:
            approved_ips = {
                str(ipaddress.ip_address(ip))
                for ip in approved_ips
            }

        except ValueError:
            return {
                "success": False,
                "error": "An approved IP address is invalid."
            }

    # Track activity by source IP.
    activity = {}

    successful_logins = 0
    failed_logins = 0
    invalid_user_attempts = 0
    unmatched_source_logs = 0

    for log_line in logs:

        if not isinstance(log_line, str):
            continue

        # Identify authentication activity.
        is_success = bool(
            re.search(r"\bAccepted\s+", log_line, re.IGNORECASE)
        )

        is_failed = bool(
            re.search(
                r"\bFailed password\b|\bauthentication failure\b",
                log_line,
                re.IGNORECASE
            )
        )

        is_invalid_user = bool(
            re.search(r"\bInvalid user\b", log_line, re.IGNORECASE)
        )

        if not (is_success or is_failed or is_invalid_user):
            continue

        source_ip = extract_source_ip(log_line)

        if source_ip is None:
            unmatched_source_logs += 1
            continue

        if source_ip not in activity:

            activity[source_ip] = {
                "successful": 0,
                "failed": 0,
                "invalid_users": 0
            }

        record = activity[source_ip]

        if is_success:
            record["successful"] += 1
            successful_logins += 1

        if is_failed:
            record["failed"] += 1
            failed_logins += 1

        if is_invalid_user:
            record["invalid_users"] += 1
            invalid_user_attempts += 1

    # ==========================================
    # GENERATE SECURITY EVENTS
    # ==========================================

    events = []

    timestamp = datetime.now(timezone.utc).isoformat()

    for source_ip, record in activity.items():

        failed_count = record["failed"]
        invalid_count = record["invalid_users"]
        successful_count = record["successful"]

        # Repeated failed login detection
        if failed_count >= failed_threshold:

            events.append({
                "type": "REPEATED_SSH_LOGIN_FAILURES",
                "severity": "High",
                "ip": source_ip,
                "mac": "Not available",
                "message": (
                    f"{failed_count} failed SSH login attempts "
                    f"detected from {source_ip}."
                ),
                "timestamp": timestamp
            })

        elif failed_count > 0:

            events.append({
                "type": "SSH_LOGIN_FAILURE",
                "severity": "Low",
                "ip": source_ip,
                "mac": "Not available",
                "message": (
                    f"{failed_count} failed SSH login attempt(s) "
                    f"detected from {source_ip}."
                ),
                "timestamp": timestamp
            })

        # Invalid username detection
        if invalid_count > 0:

            events.append({
                "type": "SSH_INVALID_USERNAME",
                "severity": "Medium",
                "ip": source_ip,
                "mac": "Not available",
                "message": (
                    f"{invalid_count} invalid username attempt(s) "
                    f"detected from {source_ip}."
                ),
                "timestamp": timestamp
            })

        # Critical alert requires an explicitly configured
        # approved-source policy and a successful login
        # from an IP outside that policy.
        if (
            approved_ips is not None
            and successful_count > 0
            and source_ip not in approved_ips
        ):

            events.append({
                "type": "SSH_LOGIN_FROM_UNAPPROVED_IP",
                "severity": "Critical",
                "ip": source_ip,
                "mac": "Not available",
                "message": (
                    f"{successful_count} successful SSH login(s) "
                    f"detected from source IP {source_ip}, "
                    "which is outside the configured approved-source list."
                ),
                "timestamp": timestamp
            })

    return {
        "success": True,
        "total_logs": len(logs),
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,
        "invalid_user_attempts": invalid_user_attempts,
        "unmatched_source_logs": unmatched_source_logs,
        "unique_source_ips": len(activity),
        "approved_ip_policy_enabled": approved_ips is not None,
        "events": events,
        "event_count": len(events),
        "analysis_time": timestamp
    }
