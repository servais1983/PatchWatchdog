# Shared utilities for PatchWatchdog


def format_cve_details(cve_id):
    """Return the NVD detail URL for a given CVE identifier."""
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def cvss_to_severity(score):
    """
    Convert a numeric CVSS score to a severity label.

    Args:
        score (float | None): CVSS base score (0.0 - 10.0) or None.

    Returns:
        str: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', or 'UNKNOWN'.
    """
    if score is None:
        return "UNKNOWN"
    score = float(score)
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


# Backward-compatible alias
format_severity = cvss_to_severity


def filter_criticality(vulns, min_severity=7.0):
    """Return vulnerabilities whose CVSS score is >= min_severity."""
    return [v for v in vulns if v.get("cvss") is not None and float(v["cvss"]) >= min_severity]
