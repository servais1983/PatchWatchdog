# Fonctions utilitaires diverses pour le projet PatchWatchdog

def format_cve_details(cve_id):
    """Formate un identifiant CVE avec un lien vers la base NVD."""
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"

def format_severity(score):
    """Convertit un score CVSS en niveau de sévérité."""
    if score >= 9.0:
        return "CRITIQUE"
    elif score >= 7.0:
        return "ÉLEVÉE"
    elif score >= 4.0:
        return "MOYENNE"
    else:
        return "FAIBLE"

def filter_criticality(vulns, min_severity=7.0):
    """Filtre les vulnérabilités en fonction de leur score CVSS minimal."""
    return [v for v in vulns if v.get("cvss", 0) >= min_severity]