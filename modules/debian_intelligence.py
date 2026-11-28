"""
CyberShield - Debian Security Tracker Lookup

Retrieves Debian package and CVE security information
from the official Debian Security Tracker JSON export.

Features:
- Local JSON cache with a 24-hour refresh interval.
- CVE lookup across Debian source packages.
- Optional package and release filtering.
- Fixed-version and release-status extraction.
- Conservative interpretation of tracker statuses.

IMPORTANT:
Debian tracker information is vendor-specific intelligence.
It does not independently verify the installed package version.
"""

import json
import logging
import os
import re
import time
import urllib.error
import urllib.request

from pathlib import Path
from datetime import datetime, timezone


logger = logging.getLogger(__name__)


# ==========================================
# CONFIGURATION
# ==========================================

DEBIAN_TRACKER_URL = (
    "https://security-tracker.debian.org/tracker/data/json"
)

DEBIAN_TRACKER_WEB_URL = (
    "https://security-tracker.debian.org/tracker/"
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_DIR = PROJECT_ROOT / "data"

CACHE_FILE = DATA_DIR / "debian_security_tracker.json"

CACHE_MAX_AGE = 24 * 60 * 60

REQUEST_TIMEOUT = 60

MAX_RESPONSE_SIZE = 100 * 1024 * 1024

USER_AGENT = "CyberShield-Debian-Security-Lookup/1.0"

CVE_PATTERN = re.compile(
    r"^CVE-\d{4}-\d{4,}$",
    re.IGNORECASE
)


# ==========================================
# VALIDATE CVE IDENTIFIER
# ==========================================

def validate_cve_id(cve_id):
    """Validate a CVE identifier."""

    if not isinstance(cve_id, str):
        return None

    cve_id = cve_id.strip().upper()

    if not CVE_PATTERN.fullmatch(cve_id):
        return None

    return cve_id


# ==========================================
# VALIDATE PACKAGE NAME
# ==========================================

def validate_package_name(package_name):
    """Validate a Debian source package name."""

    if package_name is None:
        return None

    if not isinstance(package_name, str):
        return None

    package_name = package_name.strip().lower()

    if not package_name:
        return None

    if len(package_name) > 128:
        return None

    if not re.fullmatch(
        r"[a-z0-9][a-z0-9+.-]*",
        package_name
    ):
        return None

    return package_name


# ==========================================
# VALIDATE RELEASE NAME
# ==========================================

def validate_release(release):
    """Validate a Debian release/codename."""

    if release is None:
        return None

    if not isinstance(release, str):
        return None

    release = release.strip().lower()

    if not release:
        return None

    if not re.fullmatch(
        r"[a-z0-9][a-z0-9-]*",
        release
    ):
        return None

    return release


# ==========================================
# DOWNLOAD TRACKER JSON
# ==========================================

def download_debian_tracker():
    """
    Download the official Debian tracker JSON export.

    The response is written to a temporary file first.
    The cache is replaced only after successful parsing.
    """

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    request = urllib.request.Request(
        DEBIAN_TRACKER_URL,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json"
        },
        method="GET"
    )

    temporary_file = CACHE_FILE.with_suffix(".tmp")

    try:

        with urllib.request.urlopen(
            request,
            timeout=REQUEST_TIMEOUT
        ) as response:

            if response.status != 200:

                return {
                    "success": False,
                    "error": (
                        "Debian tracker returned HTTP "
                        f"{response.status}."
                    )
                }

            content_length = response.headers.get(
                "Content-Length"
            )

            if content_length:

                try:
                    if int(content_length) > MAX_RESPONSE_SIZE:
                        return {
                            "success": False,
                            "error": (
                                "Debian tracker response "
                                "exceeds the configured size limit."
                            )
                        }
                except ValueError:
                    pass

            total_size = 0

            with open(temporary_file, "wb") as output:

                while True:

                    chunk = response.read(1024 * 1024)

                    if not chunk:
                        break

                    total_size += len(chunk)

                    if total_size > MAX_RESPONSE_SIZE:

                        output.close()

                        temporary_file.unlink(
                            missing_ok=True
                        )

                        return {
                            "success": False,
                            "error": (
                                "Debian tracker response "
                                "exceeds the configured size limit."
                            )
                        }

                    output.write(chunk)

        # Validate downloaded JSON before replacing cache.
        with open(
            temporary_file,
            "r",
            encoding="utf-8"
        ) as file:

            tracker_data = json.load(file)

        if not isinstance(tracker_data, dict):

            temporary_file.unlink(missing_ok=True)

            return {
                "success": False,
                "error": (
                    "Debian tracker returned an "
                    "unexpected JSON structure."
                )
            }

        os.replace(
            temporary_file,
            CACHE_FILE
        )

        return {
            "success": True,
            "path": str(CACHE_FILE),
            "size_bytes": total_size,
            "downloaded_at": datetime.now(
                timezone.utc
            ).isoformat()
        }

    except urllib.error.HTTPError as error:

        temporary_file.unlink(missing_ok=True)

        return {
            "success": False,
            "error": (
                f"Debian tracker HTTP error: {error.code}."
            )
        }

    except urllib.error.URLError as error:

        temporary_file.unlink(missing_ok=True)

        return {
            "success": False,
            "error": (
                "Unable to connect to Debian tracker: "
                f"{error.reason}"
            )
        }

    except (TimeoutError, OSError) as error:

        temporary_file.unlink(missing_ok=True)

        return {
            "success": False,
            "error": f"Debian tracker network error: {error}"
        }

    except (json.JSONDecodeError, UnicodeDecodeError):

        temporary_file.unlink(missing_ok=True)

        return {
            "success": False,
            "error": (
                "Unable to parse Debian tracker JSON."
            )
        }


# ==========================================
# LOAD CACHED TRACKER DATA
# ==========================================

def load_debian_tracker(force_refresh=False):
    """
    Load Debian tracker JSON from local cache.

    Cache refresh interval: 24 hours.

    If the cache is still valid, no network request
    is performed.
    """

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if CACHE_FILE.exists() and not force_refresh:

        cache_age = (
            time.time() - CACHE_FILE.stat().st_mtime
        )

        if cache_age < CACHE_MAX_AGE:

            try:

                with open(
                    CACHE_FILE,
                    "r",
                    encoding="utf-8"
                ) as file:

                    tracker_data = json.load(file)

                if isinstance(tracker_data, dict):

                    return {
                        "success": True,
                        "data": tracker_data,
                        "source": "Local Debian tracker cache",
                        "cache_age_seconds": int(cache_age)
                    }

            except (
                OSError,
                json.JSONDecodeError,
                UnicodeDecodeError
            ):

                logger.warning(
                    "Debian tracker cache is invalid."
                )

    # --------------------------------------
    # DOWNLOAD FRESH DATA
    # --------------------------------------

    download_result = download_debian_tracker()

    if not download_result.get("success"):

        # Use an older cache if a refresh fails.
        if CACHE_FILE.exists():

            try:

                with open(
                    CACHE_FILE,
                    "r",
                    encoding="utf-8"
                ) as file:

                    tracker_data = json.load(file)

                if isinstance(tracker_data, dict):

                    return {
                        "success": True,
                        "data": tracker_data,
                        "source": "Older Debian tracker cache",
                        "warning": download_result.get("error"),
                        "cache_stale": True
                    }

            except (
                OSError,
                json.JSONDecodeError,
                UnicodeDecodeError
            ):
                pass

        return {
            "success": False,
            "error": download_result.get(
                "error",
                "Unable to load Debian tracker data."
            )
        }

    try:

        with open(
            CACHE_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            tracker_data = json.load(file)

        return {
            "success": True,
            "data": tracker_data,
            "source": "Debian Security Tracker",
            "cache_stale": False,
            "downloaded_at": download_result.get(
                "downloaded_at"
            )
        }

    except (
        OSError,
        json.JSONDecodeError,
        UnicodeDecodeError
    ) as error:

        return {
            "success": False,
            "error": (
                "Unable to read downloaded tracker data: "
                f"{error}"
            )
        }


# ==========================================
# INTERPRET ONE RELEASE STATUS
# ==========================================

def interpret_release_status(release_data):
    """
    Interpret Debian tracker release information.

    Does not compare the installed package version.
    """

    if not isinstance(release_data, dict):

        return {
            "tracker_status": "Unknown",
            "interpretation": (
                "No release information is available."
            )
        }

    status = str(
        release_data.get("status", "unknown")
    ).strip().lower()

    fixed_version = str(
        release_data.get("fixed_version", "")
    ).strip()

    if fixed_version == "0":

        interpretation = (
            "Debian tracker indicates this CVE does not "
            "affect the package in this release."
        )

    elif status == "resolved":

        interpretation = (
            "Debian tracker marks the issue as resolved "
            "for this release. The fixed package version "
            "must be compared with the installed package."
        )

    elif status == "open":

        interpretation = (
            "Debian tracker marks the issue as open "
            "for this release."
        )

    elif status == "undetermined":

        interpretation = (
            "Debian tracker has not determined whether "
            "the package is affected."
        )

    elif status in ("no-dsa", "ignored"):

        interpretation = (
            "Debian tracker contains a special security "
            "handling status. Review the tracker details."
        )

    else:

        interpretation = (
            "Debian tracker returned an unrecognized "
            "release status."
        )

    return {
        "tracker_status": status,
        "fixed_version": fixed_version or None,
        "urgency": release_data.get("urgency"),
        "repositories": release_data.get(
            "repositories", {}
        ),
        "no_dsa": release_data.get("nodsa"),
        "no_dsa_reason": release_data.get("nodsa_reason"),
        "interpretation": interpretation
    }


# ==========================================
# FIND CVE ACROSS DEBIAN PACKAGES
# ==========================================

def find_cve_packages(tracker_data, cve_id):
    """
    Search the package-keyed Debian tracker JSON.

    Expected structure:

        {
            "package-name": {
                "CVE-YYYY-NNNN": {
                    "description": "...",
                    "releases": {...}
                }
            }
        }
    """

    matches = []

    for package_name, package_cves in tracker_data.items():

        if not isinstance(package_cves, dict):
            continue

        cve_record = package_cves.get(cve_id)

        if not isinstance(cve_record, dict):
            continue

        matches.append({
            "package": package_name,
            "record": cve_record
        })

    return matches


# ==========================================
# SEARCH DEBIAN SECURITY TRACKER
# ==========================================

def search_debian_cve(
    cve_id,
    package_name=None,
    release=None,
    force_refresh=False
):
    """
    Search the Debian Security Tracker for a CVE.

    Args:
        cve_id:
            CVE identifier.

        package_name:
            Optional Debian source package name.

        release:
            Optional Debian release codename,
            for example bookworm or trixie.

        force_refresh:
            Force a new download of tracker JSON.

    Returns:
        Debian package and release security information.

    NOTE:
        This function does not verify installed package
        versions or automatically confirm vulnerabilities.
    """

    cve_id = validate_cve_id(cve_id)

    if not cve_id:

        return {
            "success": False,
            "error": "Invalid CVE identifier.",
            "results": []
        }

    package_name = validate_package_name(
        package_name
    )

    if package_name is None and package_name is not None:

        return {
            "success": False,
            "error": "Invalid Debian package name.",
            "results": []
        }

    release = validate_release(release)

    if release is None and release is not None:

        return {
            "success": False,
            "error": "Invalid Debian release name.",
            "results": []
        }

    # --------------------------------------
    # LOAD TRACKER DATA
    # --------------------------------------

    tracker_result = load_debian_tracker(
        force_refresh=force_refresh
    )

    if not tracker_result.get("success"):

        return {
            "success": False,
            "error": tracker_result.get(
                "error",
                "Unable to retrieve Debian tracker data."
            ),
            "results": []
        }

    tracker_data = tracker_result["data"]

    # --------------------------------------
    # FIND CVE RECORDS
    # --------------------------------------

    package_matches = find_cve_packages(
        tracker_data,
        cve_id
    )

    if package_name:

        package_matches = [
            item for item in package_matches
            if item["package"].casefold()
            == package_name.casefold()
        ]

    if not package_matches:

        return {
            "success": True,
            "source": "Debian Security Tracker",
            "source_url": (
                DEBIAN_TRACKER_WEB_URL + cve_id
            ),
            "cve_id": cve_id,
            "found": False,
            "total_packages": 0,
            "results": [],
            "message": (
                "No matching Debian package record "
                "was found for this CVE and package filter."
            ),
            "warning": tracker_result.get("warning")
        }

    # --------------------------------------
    # NORMALIZE PACKAGE RESULTS
    # --------------------------------------

    results = []

    for item in package_matches:

        package = item["package"]

        record = item["record"]

        releases = record.get("releases", {})

        if not isinstance(releases, dict):
            releases = {}

        normalized_releases = {}

        for release_name, release_data in releases.items():

            if release is not None:

                if release_name.casefold() != release.casefold():
                    continue

            normalized_releases[release_name] = (
                interpret_release_status(release_data)
            )

        if release is not None and not normalized_releases:
            continue

        results.append({
            "package": package,

            "description": record.get("description"),

            "scope": record.get("scope"),

            "debian_bug": record.get("debianbug"),

            "releases": normalized_releases,

            "tracker_url": (
                DEBIAN_TRACKER_WEB_URL
                + cve_id
            )
        })

    # --------------------------------------
    # RETURN RESULTS
    # --------------------------------------

    return {
        "success": True,

        "source": "Debian Security Tracker",

        "source_url": (
            DEBIAN_TRACKER_WEB_URL + cve_id
        ),

        "cve_id": cve_id,

        "found": bool(results),

        "total_packages": len(results),

        "results": results,

        "cache_source": tracker_result.get("source"),

        "cache_stale": tracker_result.get(
            "cache_stale",
            False
        ),

        "warning": tracker_result.get("warning"),

        "checked_at": datetime.now(
            timezone.utc
        ).isoformat(),

        "verification_note": (
            "Debian tracker results are package and release "
            "intelligence. Compare the exact installed Debian "
            "package version with the reported fixed version "
            "before determining applicability. A service "
            "banner alone is not sufficient."
        )
    }


# ==========================================
# REFRESH TRACKER CACHE
# ==========================================

def refresh_debian_tracker():
    """Force a fresh download of Debian tracker data."""

    return load_debian_tracker(
        force_refresh=True
    )


# ==========================================
# DEBIAN PACKAGE VERSION COMPARISON
# ==========================================

import re


# ==========================================
# DEBIAN VERSION VALIDATION
# ==========================================

DEBIAN_VERSION_PATTERN = re.compile(
    r"(?:[0-9]+:)?"
    r"[0-9][A-Za-z0-9.+~\-]*"
    r"(?:-[A-Za-z0-9+.~]+)?"
)


# ==========================================
# SPLIT DEBIAN VERSION
# ==========================================

def split_debian_version(version):
    """
    Split a Debian version into:

        epoch
        upstream_version
        debian_revision

    Missing epoch defaults to 0.
    Missing Debian revision defaults to 0.
    """

    if not isinstance(version, str):
        raise ValueError("Version must be a string.")

    version = version.strip()

    if not version:
        raise ValueError("Version cannot be empty.")

    if not DEBIAN_VERSION_PATTERN.fullmatch(version):
        raise ValueError(
            f"Invalid Debian version format: {version}"
        )

    epoch = 0

    if ":" in version:

        epoch_text, version = version.split(":", 1)

        epoch = int(epoch_text)

    if "-" in version:

        upstream, revision = version.rsplit("-", 1)

    else:

        upstream = version
        revision = "0"

    if not upstream or not revision:
        raise ValueError("Invalid Debian version components.")

    return epoch, upstream, revision


# ==========================================
# DEBIAN CHARACTER ORDER
# ==========================================

def debian_character_order(character):
    """
    Character ordering used by Debian's verrevcmp algorithm.
    """

    if character == "~":
        return -1

    if character == "":
        return 0

    if character.isalpha():
        return ord(character)

    return ord(character) + 256


# ==========================================
# COMPARE VERSION PARTS
# ==========================================

def compare_version_parts(left, right):
    """
    Compare upstream versions or Debian revisions
    using Debian's verrevcmp ordering.
    """

    left_index = 0
    right_index = 0

    left_length = len(left)
    right_length = len(right)

    while (
        left_index < left_length
        or right_index < right_length
    ):

        # Compare non-numeric characters.

        while (
            (
                left_index < left_length
                and not left[left_index].isdigit()
            )
            or
            (
                right_index < right_length
                and not right[right_index].isdigit()
            )
        ):

            left_char = (
                left[left_index]
                if (
                    left_index < left_length
                    and not left[left_index].isdigit()
                )
                else ""
            )

            right_char = (
                right[right_index]
                if (
                    right_index < right_length
                    and not right[right_index].isdigit()
                )
                else ""
            )

            left_order = debian_character_order(
                left_char
            )

            right_order = debian_character_order(
                right_char
            )

            if left_order < right_order:
                return -1

            if left_order > right_order:
                return 1

            if left_char:
                left_index += 1

            if right_char:
                right_index += 1

        # Skip leading zeroes in numeric segments.

        while (
            left_index < left_length
            and left[left_index] == "0"
        ):
            left_index += 1

        while (
            right_index < right_length
            and right[right_index] == "0"
        ):
            right_index += 1

        left_start = left_index
        right_start = right_index

        # Read numeric segments.

        while (
            left_index < left_length
            and left[left_index].isdigit()
        ):
            left_index += 1

        while (
            right_index < right_length
            and right[right_index].isdigit()
        ):
            right_index += 1

        left_digits = left[left_start:left_index]
        right_digits = right[right_start:right_index]

        # Longer numeric segment is greater.

        if len(left_digits) < len(right_digits):
            return -1

        if len(left_digits) > len(right_digits):
            return 1

        if left_digits < right_digits:
            return -1

        if left_digits > right_digits:
            return 1

    return 0


# ==========================================
# COMPARE COMPLETE DEBIAN VERSIONS
# ==========================================

def compare_debian_versions(version_a, version_b):
    """
    Compare two Debian package versions.

    Returns:
        -1: version_a is older.
         0: versions are equal.
         1: version_a is newer.
    """

    epoch_a, upstream_a, revision_a = (
        split_debian_version(version_a)
    )

    epoch_b, upstream_b, revision_b = (
        split_debian_version(version_b)
    )

    # Compare epochs.

    if epoch_a < epoch_b:
        return -1

    if epoch_a > epoch_b:
        return 1

    # Compare upstream versions.

    upstream_result = compare_version_parts(
        upstream_a,
        upstream_b
    )

    if upstream_result != 0:
        return upstream_result

    # Compare Debian revisions.

    return compare_version_parts(
        revision_a,
        revision_b
    )


# ==========================================
# CHECK INSTALLED VERSION AGAINST FIXED VERSION
# ==========================================

def check_debian_fixed_version(
    installed_version,
    fixed_version
):
    """
    Compare an installed Debian package version
    against a Debian Security Tracker fixed version.

    This comparison does not independently establish
    whether a particular installation is vulnerable.
    """

    if not isinstance(installed_version, str):

        return {
            "success": False,
            "status": "Indeterminate",
            "error": "Installed package version is required."
        }

    if not isinstance(fixed_version, str):

        return {
            "success": False,
            "status": "Indeterminate",
            "error": "Fixed package version is required."
        }

    installed_version = installed_version.strip()
    fixed_version = fixed_version.strip()

    if not installed_version or not fixed_version:

        return {
            "success": False,
            "status": "Indeterminate",
            "error": "Package versions cannot be empty."
        }

    # Debian tracker convention: zero means not affected.

    if fixed_version == "0":

        return {
            "success": True,
            "status": "Not affected",
            "installed_version": installed_version,
            "fixed_version": fixed_version,
            "message": (
                "Debian tracker indicates this package "
                "is not affected in the selected release."
            )
        }

    try:

        comparison = compare_debian_versions(
            installed_version,
            fixed_version
        )

    except ValueError as error:

        return {
            "success": False,
            "status": "Indeterminate",
            "error": str(error)
        }

    if comparison >= 0:

        return {
            "success": True,
            "status": "Fixed version reached",
            "installed_version": installed_version,
            "fixed_version": fixed_version,
            "message": (
                "Installed package version is equal to "
                "or newer than the Debian fixed version."
            )
        }

    return {
        "success": True,
        "status": "Below fixed version",
        "installed_version": installed_version,
        "fixed_version": fixed_version,
        "message": (
            "Installed package version is older than "
            "the Debian fixed version. Further vendor "
            "applicability verification is required."
        )
    }

