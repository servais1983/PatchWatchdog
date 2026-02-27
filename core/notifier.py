import requests
import os


def send_alert(vuln_list, method="slack"):
    """
    Send a vulnerability alert via the chosen channel.

    Args:
        vuln_list (list): List of detected vulnerabilities.
        method (str): 'slack' or 'github'.

    Returns:
        bool: True if the notification was sent successfully, False otherwise.
    """
    if not vuln_list:
        return True

    lines = []
    for v in vuln_list:
        sev = v.get("severity", "UNKNOWN")
        cvss = v.get("cvss")
        cvss_str = f" (CVSS {cvss:.1f})" if cvss is not None else ""
        lines.append(f"- {v['package']} {v['version']} | {v['cve']}{cvss_str} | {sev}")

    msg = "[PatchWatchdog] Vulnerabilities detected:\n" + "\n".join(lines)

    if method == "slack":
        webhook = os.getenv("SLACK_WEBHOOK")
        if not webhook:
            print("[WARN] SLACK_WEBHOOK not set -- Slack notification skipped.")
            return False
        try:
            r = requests.post(webhook, json={"text": msg}, timeout=10)
            r.raise_for_status()
            print("[OK] Slack alert sent.")
            return True
        except requests.exceptions.RequestException as e:
            print(f"[FAIL] Slack notification failed: {e}")
            return False

    elif method == "github":
        token = os.getenv("GITHUB_TOKEN")
        repo  = os.getenv("GITHUB_REPO")
        if not token:
            print("[WARN] GITHUB_TOKEN not set -- GitHub notification skipped.")
            return False
        if not repo:
            print("[WARN] GITHUB_REPO not set -- GitHub notification skipped.")
            return False
        url = f"https://api.github.com/repos/{repo}/issues"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
        }
        payload = {
            "title": f"[PatchWatchdog] {len(vuln_list)} vulnerability(ies) detected",
            "body": msg,
            "labels": ["security"],
        }
        try:
            r = requests.post(url, json=payload, headers=headers, timeout=10)
            r.raise_for_status()
            issue_url = r.json().get("html_url", "")
            print(f"[OK] GitHub issue created: {issue_url}")
            return True
        except requests.exceptions.RequestException as e:
            print(f"[FAIL] GitHub issue creation failed: {e}")
            return False

    print(f"[WARN] Unknown notification method: {method}")
    return False