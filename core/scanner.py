"""
CVE scanner for PatchWatchdog.

Engines:
  - pip packages   : OSV.dev  (free, no key required)
  - system packages: NVD API v2 (free; NVD_API_KEY for 10x speed)
                     or Vulners  (VULNERS_API_KEY, paid plan, takes priority)
"""
import os
import time
import random

import requests

# API endpoints
OSV_API     = "https://api.osv.dev/v1/query"
NVD_API     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
VULNERS_API = "https://vulners.com/api/v3/burp/software/"


def _cvss_to_severity(score):
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


def _extract_cvss_osv(vuln_json):
    best = None
    db = vuln_json.get("database_specific", {})
    for key in ("cvss_v3", "cvss_score", "severity_score"):
        val = db.get(key)
        if val is not None:
            try:
                c = float(val)
                if best is None or c > best:
                    best = c
            except (ValueError, TypeError):
                pass
    for aff in vuln_json.get("affected", []):
        val = aff.get("ecosystem_specific", {}).get("severity")
        if isinstance(val, (int, float)):
            if best is None or float(val) > best:
                best = float(val)
    return best


def _check_osv(pkg):
    try:
        r = requests.post(
            OSV_API,
            json={"package": {"name": pkg["package"], "ecosystem": "PyPI"},
                  "version": pkg["version"]},
            timeout=15,
        )
        r.raise_for_status()
        results = []
        for vuln in r.json().get("vulns", []):
            cve_id = vuln.get("id", "unknown")
            for alias in vuln.get("aliases", []):
                if alias.startswith("CVE-"):
                    cve_id = alias
                    break
            cvss = _extract_cvss_osv(vuln)
            results.append({
                "package": pkg["package"],
                "version": pkg["version"],
                "cve": cve_id,
                "cvss": cvss,
                "severity": _cvss_to_severity(cvss),
            })
        return results
    except requests.exceptions.RequestException:
        return []


def _check_nvd(pkg, api_key=None):
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    name_lower = pkg["package"].lower().replace(" ", "_")
    cpe = f"cpe:2.3:a:*:{name_lower}:{pkg['version']}:*:*:*:*:*:*:*"
    try:
        r = requests.get(
            NVD_API,
            params={"virtualMatchString": cpe, "resultsPerPage": 10},
            headers=headers,
            timeout=20,
        )
        if r.status_code == 403:
            return "forbidden"
        if r.status_code == 429:
            return "rate_limited"
        r.raise_for_status()
        results = []
        for entry in r.json().get("vulnerabilities", []):
            cve_obj = entry.get("cve", {})
            cve_id = cve_obj.get("id", "unknown")
            metrics = cve_obj.get("metrics", {})
            cvss_score = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                lst = metrics.get(key, [])
                if lst:
                    s = lst[0].get("cvssData", {}).get("baseScore")
                    if s is not None:
                        cvss_score = float(s)
                        break
            results.append({
                "package": pkg["package"],
                "version": pkg["version"],
                "cve": cve_id,
                "cvss": cvss_score,
                "severity": _cvss_to_severity(cvss_score),
            })
        return results
    except requests.exceptions.Timeout:
        return []
    except requests.exceptions.RequestException:
        return []


def _check_vulners(pkg, api_key):
    try:
        r = requests.get(
            VULNERS_API,
            params={"software": pkg["package"], "version": pkg["version"],
                    "apiKey": api_key},
            timeout=15,
        )
        if r.status_code == 403:
            return None
        if r.status_code == 429:
            return "rate_limited"
        r.raise_for_status()
        results = []
        for hit in r.json().get("data", {}).get("search", []):
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
    Check all packages for known CVEs.

    Routing:
      - pip packages    -> OSV.dev (free, no key)
      - system packages -> Vulners if VULNERS_API_KEY is set (paid, priority)
                          else NVD API v2 (free; NVD_API_KEY for 10x speed)

    Returns a list of dicts: package, version, cve, cvss, severity.
    """
    vulners_key = os.getenv("VULNERS_API_KEY", "")
    nvd_key     = os.getenv("NVD_API_KEY", "")

    pip_pkgs = [p for p in package_list if p.get("type") == "pip"]
    sys_pkgs = [p for p in package_list if p.get("type") != "pip"]
    total    = len(package_list)

    if vulners_key:
        sys_engine = "Vulners"
    else:
        sys_engine = "NVD API v2"
        if sys_pkgs and not nvd_key:
            eta = max(1, len(sys_pkgs) // 5) * 7
            print(f"[i] {len(sys_pkgs)} system packages -> NVD API v2 (free).")
            print(f"    Estimated time without NVD_API_KEY: ~{eta}s. "
                  "Free key: https://nvd.nist.gov/developers/request-an-api-key")

    print(f"[*] Checking {len(pip_pkgs)} pip packages (OSV.dev) + "
          f"{len(sys_pkgs)} system packages ({sys_engine})...")

    vulnerable = []

    # -- pip packages via OSV.dev ---------------------------------------------
    for i, pkg in enumerate(pip_pkgs):
        if i > 0 and (i % batch_size == 0 or i == len(pip_pkgs) - 1):
            print(f"[*] pip: {i}/{len(pip_pkgs)} ({i/len(pip_pkgs)*100:.0f}%)...")
        vulnerable.extend(_check_osv(pkg))
        if i < len(pip_pkgs) - 1:
            time.sleep(0.3 + random.uniform(0, 0.2))

    # -- system packages via Vulners (if key present) -------------------------
    if vulners_key and sys_pkgs:
        vulners_blocked = False
        print(f"[*] Scanning {len(sys_pkgs)} system packages via Vulners...")
        for i, pkg in enumerate(sys_pkgs):
            if vulners_blocked:
                break
            if i > 0 and (i % batch_size == 0 or i == len(sys_pkgs) - 1):
                print(f"[*] system: {i}/{len(sys_pkgs)} ({i/len(sys_pkgs)*100:.0f}%)...")
            for _ in range(3):
                res = _check_vulners(pkg, vulners_key)
                if res is None:
                    print("[!] Vulners 403 - invalid key, switching to NVD API v2.")
                    vulners_key = ""
                    vulners_blocked = True
                    break
                if res == "rate_limited":
                    print("[!] Vulners rate limit, pausing 15s...")
                    time.sleep(15)
                    continue
                vulnerable.extend(res)
                break
            time.sleep(0.5 + random.uniform(0, 0.3))
        if vulners_blocked:
            sys_pkgs = sys_pkgs[i:]
        else:
            sys_pkgs = []

    # -- system packages via NVD API v2 (default or Vulners fallback) --------
    if sys_pkgs:
        delay_between = 0.7 if nvd_key else 6.5
        nvd_forbidden = False
        print(f"[*] Scanning {len(sys_pkgs)} system packages via NVD API v2...")
        for i, pkg in enumerate(sys_pkgs):
            if nvd_forbidden:
                break
            if i > 0 and (i % batch_size == 0 or i == len(sys_pkgs) - 1):
                pct = i / len(sys_pkgs) * 100
                print(f"[*] system: {i}/{len(sys_pkgs)} ({pct:.0f}%)...")
            for attempt in range(3):
                res = _check_nvd(pkg, nvd_key or None)
                if res == "forbidden":
                    print("[!] NVD API 403 - invalid key. Stopping system scan.")
                    nvd_forbidden = True
                    break
                if res == "rate_limited":
                    print("[!] NVD rate limit, pausing 35s...")
                    time.sleep(35)
                    continue
                if isinstance(res, list):
                    vulnerable.extend(res)
                    break
                break
            if not nvd_forbidden and i < len(sys_pkgs) - 1:
                time.sleep(delay_between)

    print(f"[OK] Scan complete: {len(vulnerable)} vulnerability(ies) "
          f"across {total} packages.")
    return vulnerable