#!/usr/bin/env python3

import argparse
import os
from core import inventory, scanner, notifier, reporter, updater

def main():
    parser = argparse.ArgumentParser(description="PatchWatchdog – Vérification de patch & CVE")
    parser.add_argument("--os", choices=["linux", "windows"], required=True)
    parser.add_argument("--notify", choices=["slack", "github"], help="Méthode de notification")
    parser.add_argument("--auto-update", action="store_true", help="Appliquer automatiquement les mises à jour critiques")
    parser.add_argument("--check-updates", action="store_true", help="Vérifier les mises à jour système disponibles")
    args = parser.parse_args()

    # Vérification des mises à jour système
    if args.check_updates or args.auto_update:
        print("[🔍] Vérification des mises à jour système...")
        os_updates = updater.check_os_updates(args.os)
        
        if os_updates["available"]:
            if os_updates["critical"]:
                print("[⚠️] Mises à jour critiques disponibles pour le système :")
            else:
                print("[ℹ️] Mises à jour disponibles pour le système :")
                
            for update in os_updates["updates_list"]:
                critical_mark = "🔴" if update.get("critical", False) else "🔵"
                print(f" {critical_mark} {update['package']}")
                
            if args.auto_update:
                print("[🔄] Application des mises à jour critiques...")
                update_result = updater.apply_os_updates(args.os, critical_only=True)
                if update_result["success"]:
                    print("[✅] Mises à jour critiques appliquées avec succès.")
                else:
                    print(f"[❌] Échec de l'application des mises à jour : {update_result['message']}")
        else:
            print("[✓] Votre système est à jour.")

    # Vérification des packages installés
    print("[🔍] Analyse des packages installés...")
    packages = inventory.get_packages(args.os)
    vulnerable = scanner.check_vulners(packages)

    if not vulnerable:
        print("[✓] Aucun package critique vulnérable trouvé.")
    else:
        print("[!] Vulnérabilités détectées :")
        for item in vulnerable:
            print(f" - {item['package']} {item['version']} → CVE: {item['cve']}")
        if args.notify:
            notifier.send_alert(vulnerable, method=args.notify)
    
    # Génération automatique du rapport HTML
    report_path = reporter.generate_html_report(packages, vulnerable, args.os)
    print(f"[📊] Rapport HTML généré : {os.path.abspath(report_path)}")

if __name__ == "__main__":
    main()