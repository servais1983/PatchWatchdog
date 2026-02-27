import requests
import os


def send_alert(vuln_list, method="slack"):
    """
    Envoie une alerte de vulnérabilités via le canal choisi.

    Args:
        vuln_list (list): Liste des vulnérabilités détectées.
        method (str): 'slack' ou 'github'.

    Returns:
        bool: True si l'envoi a réussi, False sinon.
    """
    if not vuln_list:
        return True

    lines = []
    for v in vuln_list:
        sev = v.get('severity', 'INCONNUE')
        cvss = v.get('cvss')
        cvss_str = f" (CVSS {cvss:.1f})" if cvss is not None else ""
        lines.append(f"- {v['package']} {v['version']} | {v['cve']}{cvss_str} | {sev}")

    msg = "[PatchWatchdog] ⚠️ Vulnérabilités détectées :\n" + "\n".join(lines)

    if method == "slack":
        webhook = os.getenv("SLACK_WEBHOOK")
        if not webhook:
            print("[⚠️] SLACK_WEBHOOK non défini — notification Slack ignorée.")
            return False
        try:
            r = requests.post(webhook, json={"text": msg}, timeout=10)
            r.raise_for_status()
            print("[✅] Alerte Slack envoyée.")
            return True
        except requests.exceptions.RequestException as e:
            print(f"[❌] Échec de l'envoi Slack : {e}")
            return False

    elif method == "github":
        token = os.getenv("GITHUB_TOKEN")
        repo = os.getenv("GITHUB_REPO")
        if not token:
            print("[⚠️] GITHUB_TOKEN non défini — notification GitHub ignorée.")
            return False
        if not repo:
            print("[⚠️] GITHUB_REPO non défini — notification GitHub ignorée.")
            return False
        url = f"https://api.github.com/repos/{repo}/issues"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
        }
        payload = {
            "title": f"[PatchWatchdog] {len(vuln_list)} vulnérabilité(s) détectée(s)",
            "body": msg,
            "labels": ["security"],
        }
        try:
            r = requests.post(url, json=payload, headers=headers, timeout=10)
            r.raise_for_status()
            issue_url = r.json().get("html_url", "")
            print(f"[✅] Issue GitHub créée : {issue_url}")
            return True
        except requests.exceptions.RequestException as e:
            print(f"[❌] Échec de la création d'issue GitHub : {e}")
            return False

    print(f"[⚠️] Méthode de notification inconnue : {method}")
    return False