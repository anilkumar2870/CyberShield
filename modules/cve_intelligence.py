"""
CyberShield - NVD CVE Intelligence Lookup

Features:
1. NVD keyword-based CVE searches.
2. NVD CPE-based CVE searches.
3. CPE normalization.
4. Extraction of affected-product and version-range criteria.
5. CVSS information extraction.
6. Detailed API error handling.

IMPORTANT:
- NVD search results are candidates.
- CPE matching does not prove a system is exploitable.
- NVD configurations can contain nested AND/OR conditions.
- Version-range criteria are retained for investigation.
- No CVE is automatically marked Verified.
"""

import json
import os
import socket
import urllib.error
import urllib.parse
import urllib.request

from datetime import datetime, timezone


# ==========================================
# NVD API CONFIGURATION
# ==========================================

NVD_API_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

REQUEST_TIMEOUT = 25
MAX_RESULTS = 10

USER_AGENT = "CyberShield-Vulnerability-Assessment/1.0"

# Optional NVD API key.
# Set the NVD_API_KEY environment variable if available.
NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()


# ==========================================
# GENERAL HELPERS
# ==========================================

def current_timestamp():
    """Return the current UTC timestamp."""

    return datetime.now(timezone.utc).isoformat()


def failed_response(message, details=None):
    """Create a consistent failed API response."""

    result = {
        "success": False,
        "error": message,
        "results": []
    }

    if details:
        result["details"] = details

    return result


def validate_limit(limit):
    """Validate the maximum number of API results."""

    return (
        isinstance(limit, int)
        and not isinstance(limit, bool)
        and 1 <= limit <= 20
    )


# ==========================================
# CPE NORMALIZATION
# ==========================================

def normalize_cpe(cpe):
    """
    Normalize supported CPE identifiers to CPE 2.3.

    Supports:
        cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
        cpe:/a:vendor:product:version

    Returns:
        (normalized_cpe, None) when valid.
        (None, error_message) otherwise.

    Escaped legacy CPE components are rejected rather
    than converted incorrectly.
    """

    if not isinstance(cpe, str) or not cpe.strip():

        return None, "A CPE identifier is required."

    cpe = cpe.strip()

    # --------------------------------------
    # CPE 2.3
    # --------------------------------------

    if cpe.startswith("cpe:2.3:"):

        parts = cpe.split(":")

        if len(parts) != 13:

            return None, (
                "Invalid CPE 2.3 component count. "
                "Expected 13 colon-separated components."
            )

        if parts[0] != "cpe" or parts[1] != "2.3":

            return None, "Unsupported CPE 2.3 format."

        normalized = cpe

    # --------------------------------------
    # LEGACY CPE 2.2
    # --------------------------------------

    elif cpe.startswith("cpe:/"):

        legacy_components = cpe[5:].split(":")

        if len(legacy_components) < 3:

            return None, "Incomplete legacy CPE identifier."

        if len(legacy_components) > 7:

            return None, "Unsupported legacy CPE format."

        if any(
            "\\" in component
            for component in legacy_components
        ):

            return None, (
                "Escaped legacy CPE components require "
                "manual normalization."
            )

        if any(
            "%" in component
            for component in legacy_components
        ):

            return None, (
                "Percent-encoded legacy CPE components "
                "are not supported by this normalizer."
            )

        # Legacy components:
        # part, vendor, product, version,
        # update, edition, language.

        legacy_components += (
            ["*"] * (7 - len(legacy_components))
        )

        # Add:
        # sw_edition, target_sw, target_hw, other.

        components = legacy_components + ["*"] * 4

        normalized = (
            "cpe:2.3:" + ":".join(components)
        )

    else:

        return None, "Unsupported CPE identifier format."

    parts = normalized.split(":")

    if len(parts) != 13:

        return None, "Invalid normalized CPE identifier."

    # Required for NVD cpeName searches:
    # part, vendor, product and version.

    required_components = parts[2:6]

    if any(
        component in {"", "*", "-"}
        for component in required_components
    ):

        return None, (
            "CPE must contain explicit part, vendor, "
            "product and version components."
        )

    return normalized, None


# ==========================================
# GENERIC VERSION COMPARISON
# ==========================================

def version_tokens(version):
    """
    Convert a version into generic numeric/text tokens.

    This is a basic comparison helper only.

    It does not implement Debian, RPM, dpkg, or
    vendor-specific package-version semantics.
    """

    if not isinstance(version, str) or not version.strip():
        return None

    import re

    tokens = re.findall(
        r"\d+|[a-zA-Z]+",
        version.lower()
    )

    if not tokens:
        return None

    result = []

    for token in tokens:

        if token.isdigit():
            result.append((0, int(token)))
        else:
            result.append((1, token))

    return result


def compare_versions(first, second):
    """
    Compare two simple version strings.

    Returns:
        -1 when first < second
         0 when equal under generic token comparison
         1 when first > second
        None when comparison is unavailable.

    Do not use this function alone to confirm
    vendor-specific package vulnerability status.
    """

    first_tokens = version_tokens(first)
    second_tokens = version_tokens(second)

    if first_tokens is None or second_tokens is None:
        return None

    try:

        if first_tokens < second_tokens:
            return -1

        if first_tokens > second_tokens:
            return 1

        return 0

    except TypeError:

        return None


# ==========================================
# EXTRACT ENGLISH DESCRIPTION
# ==========================================

def extract_description(cve):
    """Extract the English CVE description."""

    descriptions = cve.get("descriptions", [])

    for item in descriptions:

        if item.get("lang") == "en":
            return item.get("value", "")

    return "No English description available."


# ==========================================
# EXTRACT CVSS INFORMATION
# ==========================================

def extract_cvss(cve):
    """
    Extract the best available CVSS information.

    Preference:
    CVSS 4.0, 3.1, 3.0, then 2.0.
    """

    metrics = cve.get("metrics", {})

    metric_priority = [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2"
    ]

    for metric_name in metric_priority:

        metric_list = metrics.get(metric_name, [])

        if not metric_list:
            continue

        metric = metric_list[0]

        cvss_data = metric.get("cvssData", {})

        score = cvss_data.get("baseScore")

        severity = (
            cvss_data.get("baseSeverity")
            or metric.get("baseSeverity")
            or "Unknown"
        )

        return {
            "score": score,
            "severity": str(severity).upper(),
            "version": cvss_data.get("version"),
            "source": metric.get("type", "Unknown")
        }

    return {
        "score": None,
        "severity": "Unknown",
        "version": None,
        "source": "Not available"
    }


# ==========================================
# EXTRACT CVE REFERENCES
# ==========================================

def extract_references(cve):
    """Extract useful reference URLs from a CVE record."""

    references = []

    for reference in cve.get("references", []):

        url = reference.get("url")

        if url and url not in references:
            references.append(url)

        if len(references) >= 5:
            break

    return references


# ==========================================
# EXTRACT NVD CPE MATCH CRITERIA
# ==========================================

def extract_cpe_matches(configurations):
    """
    Extract CPE match criteria recursively.

    Preserves the criteria and version boundaries
    returned by NVD.

    This function deliberately does not flatten
    the logical AND/OR configuration into a
    definitive vulnerability decision.
    """

    matches = []

    def walk(value):

        if isinstance(value, list):

            for item in value:
                walk(item)

            return

        if not isinstance(value, dict):
            return

        # Modern NVD field.
        cpe_matches = value.get("cpeMatch", [])

        # Older field compatibility.
        if not cpe_matches:
            cpe_matches = value.get("cpe_match", [])

        if isinstance(cpe_matches, list):

            for match in cpe_matches:

                if not isinstance(match, dict):
                    continue

                matches.append({
                    "criteria": match.get(
                        "criteria",
                        match.get("cpe23Uri", "")
                    ),
                    "vulnerable": match.get(
                        "vulnerable"
                    ),
                    "version_start_including": match.get(
                        "versionStartIncluding"
                    ),
                    "version_start_excluding": match.get(
                        "versionStartExcluding"
                    ),
                    "version_end_including": match.get(
                        "versionEndIncluding"
                    ),
                    "version_end_excluding": match.get(
                        "versionEndExcluding"
                    ),
                    "match_criteria_id": match.get(
                        "matchCriteriaId"
                    )
                })

        # Recursively process nested configuration structures.
        for key in ("nodes", "children"):

            children = value.get(key, [])

            if isinstance(children, list):
                walk(children)

    walk(configurations)

    return matches


# ==========================================
# NORMALIZE ONE CVE RECORD
# ==========================================

def normalize_cve(
    vulnerability,
    product,
    version,
    installed_cpe=None,
    lookup_type="Keyword"
):
    """Convert one NVD vulnerability record into CyberShield format."""

    if not isinstance(vulnerability, dict):
        return None

    cve = vulnerability.get("cve", {})

    if not isinstance(cve, dict):
        return None

    cve_id = cve.get("id")

    if not cve_id:
        return None

    cvss = extract_cvss(cve)

    description = extract_description(cve)

    references = extract_references(cve)

    configurations = cve.get("configurations", [])

    cpe_matches = extract_cpe_matches(configurations)

    if installed_cpe:

        status_note = (
            "NVD returned this CVE for the supplied CPE. "
            "The NVD applicability configuration and version "
            "criteria require review. This is not confirmation "
            "that the installed system is vulnerable."
        )

        cve_status = "Potential"

    else:

        status_note = (
            "Candidate returned by NVD keyword search. "
            "Affected product and exact version applicability "
            "have not been established."
        )

        cve_status = "Potential"

    return {
        "cve_id": cve_id,

        "title": f"Potential vulnerability reference: {cve_id}",

        "description": description,

        "product": product,

        "version": version,

        "cpe": installed_cpe,

        "cvss_score": cvss["score"],

        "cvss_severity": cvss["severity"],

        "cvss_version": cvss["version"],

        "cvss_source": cvss["source"],

        "published": cve.get("published"),

        "last_modified": cve.get("lastModified"),

        "vulnerability_status": cve.get(
            "vulnStatus", "Unknown"
        ),

        "cve_url": (
            f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        ),

        "references": references,

        "lookup_type": lookup_type,

        "cpe_match_criteria": cpe_matches,

        "cve_status": cve_status,

        "verification_note": status_note,

        "verified": False
    }


# ==========================================
# INTERNAL NVD API REQUEST
# ==========================================

def request_nvd(params):
    """Send a request to the official NVD CVE API."""

    query_string = urllib.parse.urlencode(params)

    request_url = f"{NVD_API_URL}?{query_string}"

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json"
    }

    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    request = urllib.request.Request(
        request_url,
        headers=headers,
        method="GET"
    )

    with urllib.request.urlopen(
        request,
        timeout=REQUEST_TIMEOUT
    ) as response:

        if response.status != 200:

            raise RuntimeError(
                f"NVD API returned HTTP {response.status}."
            )

        return json.loads(
            response.read().decode("utf-8")
        )


# ==========================================
# NVD ERROR HANDLING
# ==========================================

def handle_nvd_error(error):
    """Return a useful message for an NVD HTTP error."""

    if error.code in {403, 429}:

        message = (
            "NVD API rate limit or access restriction. "
            "Please wait before trying again."
        )

    else:

        message = (
            f"NVD API returned HTTP error {error.code}."
        )

    try:

        details = error.read().decode(
            "utf-8",
            errors="replace"
        )

        details = details[:500]

    except Exception:

        details = "No additional response details available."

    return message, details


# ==========================================
# PROCESS NVD SEARCH RESULTS
# ==========================================

def process_nvd_results(
    response_data,
    product,
    version,
    installed_cpe=None,
    lookup_type="Keyword"
):
    """Normalize the CVE records returned by NVD."""

    vulnerabilities = response_data.get(
        "vulnerabilities", []
    )

    results = []

    for vulnerability in vulnerabilities:

        normalized = normalize_cve(
            vulnerability=vulnerability,
            product=product,
            version=version,
            installed_cpe=installed_cpe,
            lookup_type=lookup_type
        )

        if normalized:
            results.append(normalized)

    return {
        "success": True,
        "source": "National Vulnerability Database",
        "source_url": "https://nvd.nist.gov/",
        "lookup_type": lookup_type,
        "query": (
            installed_cpe
            if installed_cpe
            else f"{product} {version or ''}".strip()
        ),
        "normalized_cpe": installed_cpe,
        "total_results": response_data.get(
            "totalResults", 0
        ),
        "returned_results": len(results),
        "checked_at": current_timestamp(),
        "results": results,
        "message": (
            "NVD search completed. All returned CVEs "
            "require applicability verification."
        )
    }


# ==========================================
# SEARCH NVD BY CPE
# ==========================================

def search_nvd_cves_by_cpe(
    cpe,
    product="Unknown",
    version=None,
    limit=MAX_RESULTS
):
    """
    Search NVD using a specific CPE 2.3 identifier.

    NVD compares the supplied CPE against CVE
    applicability match criteria.

    Results remain Potential until independently
    verified against the vendor's affected package
    and patch information.
    """

    if not validate_limit(limit):

        return failed_response(
            "Result limit must be between 1 and 20."
        )

    normalized_cpe, error = normalize_cpe(cpe)

    if error:
        return failed_response(error)

    cpe_parts = normalized_cpe.split(":")

    if not product or product == "Unknown":
        product = cpe_parts[4]

    if not version:
        version = cpe_parts[5]

    # NVD cpeName search.
    # isVulnerable is intentionally omitted so that
    # all associated CVE applicability records can
    # be examined without that additional filter.

    params = {
        "cpeName": normalized_cpe,
        "resultsPerPage": limit
    }

    try:

        response_data = request_nvd(params)

        return process_nvd_results(
            response_data=response_data,
            product=product,
            version=version,
            installed_cpe=normalized_cpe,
            lookup_type="CPE"
        )

    except urllib.error.HTTPError as error:

        message, details = handle_nvd_error(error)

        return failed_response(
            message,
            details
        )

    except urllib.error.URLError as error:

        return failed_response(
            f"Unable to connect to NVD: {error.reason}"
        )

    except (socket.timeout, TimeoutError):

        return failed_response(
            "NVD API request timed out."
        )

    except (json.JSONDecodeError, UnicodeDecodeError):

        return failed_response(
            "Unable to read the NVD API response."
        )

    except OSError as error:

        return failed_response(
            f"Network error: {error}"
        )

    except RuntimeError as error:

        return failed_response(str(error))


# ==========================================
# SEARCH NVD BY PRODUCT AND VERSION
# ==========================================

def search_nvd_cves(
    product,
    version=None,
    limit=MAX_RESULTS,
    cpe=None
):
    """
    Search the official NVD CVE API.

    Args:
        product: Software product name.
        version: Detected software version.
        limit: Maximum number of CVE records.
        cpe: Optional CPE identifier.

    If CPE is supplied, CPE-based lookup is preferred.

    Without a CPE, results remain Potential keyword
    candidates.
    """

    if not validate_limit(limit):

        return failed_response(
            "Result limit must be between 1 and 20."
        )

    if cpe:

        return search_nvd_cves_by_cpe(
            cpe=cpe,
            product=product or "Unknown",
            version=version,
            limit=limit
        )

    if not isinstance(product, str) or not product.strip():

        return failed_response(
            "Product name is required."
        )

    product = product.strip()

    version = (
        str(version).strip()
        if version is not None
        else ""
    )

    search_terms = [product]

    if version:
        search_terms.append(version)

    keyword_search = " ".join(search_terms)

    params = {
        "keywordSearch": keyword_search,
        "resultsPerPage": limit
    }

    try:

        response_data = request_nvd(params)

        return process_nvd_results(
            response_data=response_data,
            product=product,
            version=version,
            installed_cpe=None,
            lookup_type="Keyword"
        )

    except urllib.error.HTTPError as error:

        message, details = handle_nvd_error(error)

        return failed_response(
            message,
            details
        )

    except urllib.error.URLError as error:

        return failed_response(
            f"Unable to connect to NVD: {error.reason}"
        )

    except (socket.timeout, TimeoutError):

        return failed_response(
            "NVD API request timed out."
        )

    except (json.JSONDecodeError, UnicodeDecodeError):

        return failed_response(
            "Unable to read the NVD API response."
        )

    except OSError as error:

        return failed_response(
            f"Network error: {error}"
        )

    except RuntimeError as error:

        return failed_response(str(error))


# ==========================================
# CPE APPLICABILITY EVALUATION
# ==========================================

# ==========================================
# PARSE CPE IDENTIFIERS
# ==========================================

def parse_cpe_components(cpe):
    """
    Parse CPE 2.3 identifiers directly.

    Legacy CPE 2.2 identifiers are normalized
    using the existing NVD lookup module.

    Returns:
        Dictionary containing CPE components.
        None when parsing fails.
    """

    if not isinstance(cpe, str) or not cpe.strip():
        return None

    cpe = cpe.strip()

    # --------------------------------------
    # CPE 2.3
    # --------------------------------------

    if cpe.startswith("cpe:2.3:"):

        parts = cpe.split(":")

        if len(parts) != 13:
            return None

        if parts[0] != "cpe" or parts[1] != "2.3":
            return None

        return {
            "part": parts[2],
            "vendor": parts[3],
            "product": parts[4],
            "version": parts[5],
            "update": parts[6],
            "edition": parts[7],
            "language": parts[8],
            "sw_edition": parts[9],
            "target_sw": parts[10],
            "target_hw": parts[11],
            "other": parts[12]
        }

    # --------------------------------------
    # LEGACY CPE 2.2
    # --------------------------------------

    normalized, error = normalize_cpe(cpe)

    if error:
        return None

    if not isinstance(normalized, str):
        return None

    parts = normalized.split(":")

    if len(parts) != 13:
        return None

    return {
        "part": parts[2],
        "vendor": parts[3],
        "product": parts[4],
        "version": parts[5],
        "update": parts[6],
        "edition": parts[7],
        "language": parts[8],
        "sw_edition": parts[9],
        "target_sw": parts[10],
        "target_hw": parts[11],
        "other": parts[12]
    }


# ==========================================
# CPE COMPONENT MATCHING
# ==========================================

def component_matches(installed, criterion):
    """
    Compare an installed CPE component against
    an NVD criterion component.

    A wildcard '*' in the criterion matches any
    installed component.

    Other values are compared case-insensitively.
    """

    if not isinstance(installed, str):
        return False

    if not isinstance(criterion, str):
        return False

    if criterion == "*":
        return True

    return installed.casefold() == criterion.casefold()


# ==========================================
# COMPARE CPE IDENTITY
# ==========================================

def compare_cpe_identity(installed_cpe, criteria_cpe):
    """
    Compare the part, vendor and product components
    of two CPE identifiers.

    Version is evaluated separately.
    """

    installed = parse_cpe_components(installed_cpe)

    criteria = parse_cpe_components(criteria_cpe)

    if installed is None or criteria is None:

        return False, (
            "Unable to parse one or both CPE identifiers."
        )

    identity_fields = (
        "part",
        "vendor",
        "product"
    )

    for field in identity_fields:

        if not component_matches(
            installed[field],
            criteria[field]
        ):

            return False, (
                f"CPE {field} does not match: "
                f"{installed[field]} versus "
                f"{criteria[field]}."
            )

    return True, (
        "CPE part, vendor and product match."
    )


# ==========================================
# CHECK ONE VERSION BOUNDARY
# ==========================================

def check_version_boundary(
    installed_version,
    boundary_version,
    comparison_type
):
    """
    Evaluate one NVD version boundary.

    Returns:
        True  - boundary satisfied.
        False - boundary not satisfied.
        None  - comparison unavailable.
    """

    if not boundary_version:
        return True

    comparison = compare_versions(
        installed_version,
        str(boundary_version)
    )

    if comparison is None:
        return None

    if comparison_type == "start_including":
        return comparison >= 0

    if comparison_type == "start_excluding":
        return comparison > 0

    if comparison_type == "end_including":
        return comparison <= 0

    if comparison_type == "end_excluding":
        return comparison < 0

    return None


# ==========================================
# EVALUATE VERSION RANGE
# ==========================================

def evaluate_version_range(
    installed_version,
    criteria
):
    """
    Evaluate NVD versionStart and versionEnd
    boundaries using the existing generic comparator.

    This does not implement Debian package-version
    comparison rules.
    """

    if not isinstance(criteria, dict):

        return {
            "status": "Indeterminate",
            "reason": "Invalid NVD version criteria."
        }

    if not isinstance(installed_version, str):

        return {
            "status": "Indeterminate",
            "reason": "Installed version is unavailable."
        }

    installed_version = installed_version.strip()

    if not installed_version:

        return {
            "status": "Indeterminate",
            "reason": "Installed version is empty."
        }

    boundaries = [
        (
            "version_start_including",
            "start_including"
        ),
        (
            "version_start_excluding",
            "start_excluding"
        ),
        (
            "version_end_including",
            "end_including"
        ),
        (
            "version_end_excluding",
            "end_excluding"
        )
    ]

    for field, comparison_type in boundaries:

        boundary = criteria.get(field)

        if not boundary:
            continue

        result = check_version_boundary(
            installed_version,
            str(boundary),
            comparison_type
        )

        if result is None:

            return {
                "status": "Indeterminate",
                "reason": (
                    f"Unable to compare installed version "
                    f"{installed_version} with {field} "
                    f"{boundary}."
                )
            }

        if not result:

            return {
                "status": "No match",
                "reason": (
                    f"Installed version {installed_version} "
                    f"does not satisfy {field} {boundary}."
                )
            }

    return {
        "status": "Potential match",
        "reason": (
            "Installed version satisfies the supplied "
            "NVD version boundaries using generic comparison."
        )
    }


# ==========================================
# EVALUATE ONE NVD CPE CRITERION
# ==========================================

def evaluate_one_cpe_criterion(
    installed_cpe,
    installed_version,
    criteria
):
    """
    Evaluate one NVD CPE match criterion.

    Does not evaluate the surrounding nested
    AND/OR configuration logic.
    """

    if not isinstance(criteria, dict):

        return {
            "status": "Indeterminate",
            "reason": "Invalid NVD CPE criterion."
        }

    criteria_cpe = (
        criteria.get("criteria")
        or criteria.get("cpe23Uri")
        or criteria.get("cpe_name")
    )

    if (
        not isinstance(criteria_cpe, str)
        or not criteria_cpe
    ):

        return {
            "status": "Indeterminate",
            "reason": (
                "NVD criterion does not contain a CPE string."
            )
        }

    # --------------------------------------
    # CHECK CPE IDENTITY
    # --------------------------------------

    identity_match, identity_reason = compare_cpe_identity(
        installed_cpe,
        criteria_cpe
    )

    if not identity_match:

        return {
            "status": "No match",
            "reason": identity_reason,
            "criteria": criteria_cpe
        }

    # --------------------------------------
    # CHECK VULNERABLE FLAG
    # --------------------------------------

    vulnerable = criteria.get("vulnerable")

    if vulnerable is False:

        return {
            "status": "Supporting criterion",
            "reason": (
                "NVD marks this CPE criterion as a supporting "
                "platform rather than the vulnerable component."
            ),
            "criteria": criteria_cpe
        }

    # --------------------------------------
    # PARSE CRITERION VERSION
    # --------------------------------------

    criteria_components = parse_cpe_components(
        criteria_cpe
    )

    if criteria_components is None:

        return {
            "status": "Indeterminate",
            "reason": (
                "Unable to parse the NVD CPE criterion."
            )
        }

    criteria_version = criteria_components["version"]

    has_range = any(
        criteria.get(field)
        for field in (
            "version_start_including",
            "version_start_excluding",
            "version_end_including",
            "version_end_excluding"
        )
    )

    # --------------------------------------
    # VERSION RANGE
    # --------------------------------------

    if has_range:

        version_result = evaluate_version_range(
            installed_version,
            criteria
        )

        return {
            "status": version_result["status"],
            "reason": version_result["reason"],
            "criteria": criteria_cpe,
            "installed_version": installed_version
        }

    # --------------------------------------
    # WILDCARD VERSION
    # --------------------------------------

    if criteria_version == "*":

        return {
            "status": "Potential match",
            "reason": (
                "CPE identity matches and the NVD criterion "
                "allows any version. Vendor patch status "
                "has not been checked."
            ),
            "criteria": criteria_cpe,
            "installed_version": installed_version
        }

    # --------------------------------------
    # N/A VERSION
    # --------------------------------------

    if criteria_version == "-":

        if installed_version == "-":

            return {
                "status": "Potential match",
                "reason": (
                    "Installed and criterion versions are N/A."
                ),
                "criteria": criteria_cpe
            }

        return {
            "status": "No match",
            "reason": (
                "NVD criterion specifies an N/A version, "
                "which does not match the installed version."
            ),
            "criteria": criteria_cpe
        }

    # --------------------------------------
    # EXACT VERSION MATCH
    # --------------------------------------

    comparison = compare_versions(
        installed_version,
        criteria_version
    )

    if comparison is None:

        return {
            "status": "Indeterminate",
            "reason": (
                "Unable to compare installed version "
                "with the exact NVD CPE version."
            ),
            "criteria": criteria_cpe
        }

    if comparison == 0:

        return {
            "status": "Potential match",
            "reason": (
                "Installed version matches the exact NVD "
                "CPE version under generic comparison."
            ),
            "criteria": criteria_cpe,
            "installed_version": installed_version
        }

    return {
        "status": "No match",
        "reason": (
            "Installed version does not match the exact "
            "version in the NVD CPE criterion."
        ),
        "criteria": criteria_cpe,
        "installed_version": installed_version
    }


# ==========================================
# EVALUATE ALL CPE CRITERIA FOR ONE CVE
# ==========================================

def evaluate_cpe_applicability(
    installed_cpe,
    installed_version,
    cpe_match_criteria
):
    """
    Evaluate extracted NVD CPE criteria individually.

    Returns per-criterion results and a conservative
    summary status.

    This does not establish complete CVE applicability
    because nested AND/OR logic and vendor-specific
    patch status are not evaluated.
    """

    if not isinstance(cpe_match_criteria, list):

        return {
            "success": False,
            "status": "Indeterminate",
            "error": (
                "CPE criteria must be provided as a list."
            ),
            "results": []
        }

    if not cpe_match_criteria:

        return {
            "success": True,
            "status": "Indeterminate",
            "message": (
                "No NVD CPE criteria were available."
            ),
            "results": [],
            "potential_matches": 0,
            "no_matches": 0,
            "indeterminate": 0,
            "supporting_criteria": 0
        }

    results = []

    for criterion in cpe_match_criteria:

        result = evaluate_one_cpe_criterion(
            installed_cpe,
            installed_version,
            criterion
        )

        results.append(result)

    potential_matches = sum(
        1 for item in results
        if item["status"] == "Potential match"
    )

    no_matches = sum(
        1 for item in results
        if item["status"] == "No match"
    )

    indeterminate = sum(
        1 for item in results
        if item["status"] == "Indeterminate"
    )

    supporting = sum(
        1 for item in results
        if item["status"] == "Supporting criterion"
    )

    if potential_matches:

        overall_status = "Potential match"

    elif indeterminate:

        overall_status = "Indeterminate"

    elif no_matches == len(results):

        overall_status = "No match"

    else:

        overall_status = "Indeterminate"

    return {
        "success": True,

        "status": overall_status,

        "installed_cpe": installed_cpe,

        "installed_version": installed_version,

        "total_criteria": len(results),

        "potential_matches": potential_matches,

        "no_matches": no_matches,

        "indeterminate": indeterminate,

        "supporting_criteria": supporting,

        "results": results,

        "verification_note": (
            "This is a preliminary per-criterion CPE assessment. "
            "It does not evaluate complete NVD AND/OR configuration "
            "logic or vendor-specific package patches. A Potential "
            "match is not a confirmed vulnerability."
        )
    }

