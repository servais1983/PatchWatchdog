import requests
import os

def send_alert(vuln_list, method="slack"):
    msg = "[PatchWatchdog] Vulnérabilités détectées :\n"
    for v in vuln_list:
        msg += f"- {v['package']} {v['version']} | CVE: {v['cve']}\n"

    if method == "slack":
        webhook = os.getenv("SLACK_WEBHOOK")
        if webhook:
            requests.post(webhook, json={"text": msg})
    elif method == "github":
        token = os.getenv("GITHUB_TOKEN")
        repo = os.getenv("GITHUB_REPO")
        if token and repo:
            url = f"https://api.github.com/repos/{repo}/issues"
            headers = {"Authorization": f"token {token}"}
            requests.post(url, json={"title": "Vulnerabilités détectées", "body": msg}, headers=headers)