import requests
import time
import random
import os

# OSV.dev API (gratuit, sans authentification) — packages pip/PyPI
OSV_API = "https://api.osv.dev/v1/query"

# Vulners API — nécessite VULNERS_API_KEY (plan payant)
VULNERS_API = "https://vulners.com/api/v3/burp/software/"


def _cvss_to_severity(score):
    """Convertit un score CVSS numérique en label de sévérité."""
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


def _extract_cvss(vuln_json):
    """
    Extrait le score CVSS le plus élevé d'une entrée OSV.
    Cherche dans severity[], database_specific et dans les affected[].
    """
    best = None
    for sev in vuln_json.get("severity", []):
        score_str = sev.get("score", "")
        # Format CVSS:3.x/AV:... — le score numérique n'est pas direct dans OSV
        # On essaie database_specific qui peut contenir cvss_v3
        pass

    # database_specific peut contenir cvss_v3 ou cvss_score
    db = vuln_json.get("database_specific", {})
    for key in ("cvss_v3", "cvss_score", "severity_score"):
        val = db.get(key)
        if val is not None:
            try:
                candidate = float(val)
                if best is None or candidate > best:
                    best = candidate
            except (ValueError, TypeError):
                pass

    # Fallback: affected[].ecosystem_specific
    for aff in vuln_json.get("affected", []):
        eco = aff.get("ecosystem_specific", {})
        for key in ("severity", "cvss"):
            val = eco.get(key)
            if isinstance(val, (int, float)):
                if best is None or float(val) > best:
                    best = float(val)

    return best


def _check_osv(pkg):
    """
    Interroge OSV.dev pour un package PyPI.
    Retourne une liste de dicts vulnérabilité ou [] en cas d'erreur.
    """
    try:
        payload = {
            "package": {"name": pkg["package"], "ecosystem": "PyPI"},
            "version": pkg["version"]
        }
        r = requests.post(OSV_API, json=payload, timeout=15)
        r.raise_for_status()
        results = []
        for vuln in r.json().get("vulns", []):
            # Préférer l'alias CVE officiel
            cve_id = vuln.get("id", "unknown")
            for alias in vuln.get("aliases", []):
                if alias.startswith("CVE-"):
                    cve_id = alias
                    break
            cvss_score = _extract_cvss(vuln)
            results.append({
                "package": pkg["package"],
                "version": pkg["version"],
                "cve": cve_id,
                "cvss": cvss_score,
                "severity": _cvss_to_severity(cvss_score),
            })
        return results
    except requests.exceptions.RequestException:
        return []


def _check_vulners(pkg, api_key):
    """
    Interroge Vulners pour un package système.
    Retourne: liste de vulns | None (403 — clé invalide) | 'rate_limited'
    """
    try:
        r = requests.get(
            VULNERS_API,
            params={"software": pkg["package"], "version": pkg["version"], "apiKey": api_key},
            timeout=15,
        )
        if r.status_code == 403:
            return None
        if r.status_code == 429:
            return "rate_limited"
        r.raise_for_status()
        data = r.json()
        results = []
        for hit in data.get("data", {}).get("search", []):
            score = hit.get("_source", {}).get("cvss", {}).get("score")
            results.append({
                "package": pkg["package"],
                "version": pkg["version"],
                "cve": hit.get("id", "unknown"),
                "cvss": float(score) if score else None,
                "severity": _cvss_to_severity(score),
            })
        return results
    except requests.exceptions.RequestException:
        return []


def check_vulners(package_list, batch_size=20):
    """
    Vérifie les vulnérabilités de tous les packages.

    - type == 'pip'      → OSV.dev (gratuit, sans authentification)
    - type == 'system'   → Vulners si VULNERS_API_KEY est défini

    Retourne une liste de dicts avec les clés:
        package, version, cve, cvss (float|None), severity (str)
    """
    vulners_api_key = os.getenv("VULNERS_API_KEY", "")
    pip_pkgs = [p for p in package_list if p.get("type") == "pip"]
    sys_pkgs = [p for p in package_list if p.get("type") != "pip"]
    total = len(package_list)

    sys_note = ("(Vulners)" if vulners_api_key
                else "(ignorés — définissez VULNERS_API_KEY pour les analyser)")
    print(f"[🔍] Vérification : {len(pip_pkgs)} packages pip via OSV.dev "
          f"+ {len(sys_pkgs)} packages système {sys_note}...")

    vulnerable = []

    # ── pip via OSV.dev ───────────────────────────────────────────────────────
    for i, pkg in enumerate(pip_pkgs):
        if i > 0 and (i % batch_size == 0 or i == len(pip_pkgs) - 1):
            pct = i / len(pip_pkgs) * 100
            print(f"[🔄] pip : {i}/{len(pip_pkgs)} ({pct:.0f}%)...")
        vulnerable.extend(_check_osv(pkg))
        if i < len(pip_pkgs) - 1:
            time.sleep(0.3 + random.uniform(0, 0.2))

    # ── système via Vulners (optionnel) ───────────────────────────────────────
    if vulners_api_key and sys_pkgs:
        vulners_blocked = False
        print("[🔍] Vérification des packages système via Vulners...")
        for i, pkg in enumerate(sys_pkgs):
            if vulners_blocked:
                break
            if i > 0 and (i % batch_size == 0 or i == len(sys_pkgs) - 1):
                pct = i / len(sys_pkgs) * 100
                print(f"[🔄] système : {i}/{len(sys_pkgs)} ({pct:.0f}%)...")
            for _ in range(3):
                res = _check_vulners(pkg, vulners_api_key)
                if res is None:
                    print("[⚠️] Vulners 403 — clé invalide ou plan insuffisant. Packages système ignorés.")
                    vulners_blocked = True
                    break
                if res == "rate_limited":
                    print("[⚠️] Limite Vulners atteinte, pause 15 s...")
                    time.sleep(15)
                    continue
                vulnerable.extend(res)
                break
            time.sleep(0.5 + random.uniform(0, 0.3))
    elif sys_pkgs and not vulners_api_key:
        print(f"[ℹ️] {len(sys_pkgs)} packages système ignorés. "
              "Définissez VULNERS_API_KEY pour les analyser.")

    print(f"[✓] Vérification terminée : {len(vulnerable)} vulnérabilité(s) "
          f"sur {total} packages analysés.")
    return vulnerable