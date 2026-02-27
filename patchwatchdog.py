#!/usr/bin/env python3
"""
PatchWatchdog — Surveillance de patches & détection de CVEs.
Usage: python patchwatchdog.py --os {linux|windows} [--notify {slack|github}]
                                [--check-updates] [--auto-update]
"""

import argparse
import os
import sys

# ── Chargement optionnel du fichier .env ──────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv(override=False)   # ne pas écraser les variables déjà définies
except ImportError:
    pass   # python-dotenv non installé → on continue sans .env

from core import inventory, scanner, notifier, reporter, updater


def main():
    parser = argparse.ArgumentParser(
        description="PatchWatchdog – Vérification de patches & CVE"
    )
    parser.add_argument("--os", choices=["linux", "windows"], required=True,
                        help="Système d'exploitation cible")
    parser.add_argument("--notify", choices=["slack", "github"],
                        help="Canal de notification des alertes")
    parser.add_argument("--auto-update", action="store_true",
                        help="Appliquer automatiquement les mises à jour critiques")
    parser.add_argument("--check-updates", action="store_true",
                        help="Vérifier les mises à jour système disponibles")
    args = parser.parse_args()

    exit_code = 0   # 0 = OK, 1 = vulnérabilités détectées, 2 = erreur

    # ── Vérification / application des mises à jour système ──────────────────
    if args.check_updates or args.auto_update:
        print("[🔍] Vérification des mises à jour système...")
        os_updates = updater.check_os_updates(args.os)

        if os_updates["available"]:
            has_critical = os_updates["critical"]

            if has_critical:
                print("[⚠️] Mises à jour critiques disponibles :")
            else:
                print("[ℹ️] Mises à jour disponibles (aucune critique) :")

            for u in os_updates["updates_list"]:
                mark = "🔴" if u.get("critical") else "🔵"
                print(f"  {mark} {u['package']}")

            if args.auto_update:
                if has_critical:
                    print("[🔄] Application des mises à jour critiques système...")
                    res = updater.apply_os_updates(args.os, critical_only=True)
                    if res["success"]:
                        print(f"[✅] {res['message']}")
                    else:
                        print(f"[❌] {res['message']}")
                        if res.get("command_output"):
                            print(f"     Détail : {res['command_output'][:300]}")
                        exit_code = 2
                else:
                    print("[✓] Aucune mise à jour critique — rien à appliquer automatiquement.")
                    print("[ℹ️] Installez les mises à jour non critiques via Windows Update / apt.")
        else:
            if os_updates.get("command_output"):
                print(f"[ℹ️] {os_updates['command_output']}")
            else:
                print("[✓] Votre système est à jour.")

    # ── Inventaire des packages ───────────────────────────────────────────────
    print("[🔍] Analyse des packages installés...")
    packages = inventory.get_packages(args.os)

    if not packages:
        print("[⚠️] Aucun package trouvé. Vérifiez les permissions et les outils disponibles.")
        sys.exit(2)

    print(f"[✓] {len(packages)} packages collectés.")

    # ── Scan CVE ──────────────────────────────────────────────────────────────
    vulnerable = scanner.check_vulners(packages)

    if not vulnerable:
        print("[✅] Aucune vulnérabilité détectée dans vos packages pip.")
    else:
        exit_code = max(exit_code, 1)
        print(f"[!] {len(vulnerable)} vulnérabilité(s) détectée(s) :")
        for item in vulnerable:
            cvss_str = f" CVSS {item['cvss']:.1f}" if item.get("cvss") is not None else ""
            sev = item.get("severity", "INCONNUE")
            print(f"  ⚠️  {item['package']} {item['version']} → {item['cve']}{cvss_str} [{sev}]")

        # Notification externe (Slack / GitHub)
        if args.notify:
            notifier.send_alert(vulnerable, method=args.notify)

        # Auto-mise à jour des packages pip vulnérables
        if args.auto_update:
            pip_vuln_names = list({
                v["package"] for v in vulnerable if v.get("package")
            })
            print(f"[🔄] Mise à jour automatique des packages pip vulnérables : {', '.join(pip_vuln_names)}")
            pip_result = updater.upgrade_pip_packages(pip_vuln_names)
            if pip_result["upgraded"]:
                print(f"[✅] Mis à jour : {', '.join(pip_result['upgraded'])}")
            if pip_result["failed"]:
                for f in pip_result["failed"]:
                    print(f"[❌] Échec pour {f['package']} : {f['error']}")
                exit_code = max(exit_code, 2)

    # ── Rapport HTML ──────────────────────────────────────────────────────────
    report_path = reporter.generate_html_report(packages, vulnerable, args.os)
    print(f"[📊] Rapport HTML : {os.path.abspath(report_path)}")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
