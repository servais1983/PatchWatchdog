# Fonctions utilitaires pour PatchWatchdog


def format_cve_details(cve_id):
    """Retourne le lien NVD pour un identifiant CVE."""
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def cvss_to_severity(score):
    """
    Convertit un score CVSS numérique en label de sévérité français.

    Args:
        score (float | None): Score CVSS (0.0 – 10.0) ou None.

    Returns:
        str: 'CRITIQUE', 'ÉLEVÉE', 'MOYENNE', 'FAIBLE' ou 'INCONNUE'.
    """
    if score is None:
        return "INCONNUE"
    score = float(score)
    if score >= 9.0:
        return "CRITIQUE"
    if score >= 7.0:
        return "ÉLEVÉE"
    if score >= 4.0:
        return "MOYENNE"
    return "FAIBLE"


# Alias rétro-compatible (ancien nom utilisé ailleurs)
format_severity = cvss_to_severity


def filter_criticality(vulns, min_severity=7.0):
    """Filtre les vulnérabilités dont le score CVSS est >= min_severity."""
    return [v for v in vulns if v.get("cvss") is not None and float(v["cvss"]) >= min_severity]
