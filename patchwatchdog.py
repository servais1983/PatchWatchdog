#!/usr/bin/env python3

import argparse
from core import inventory, scanner, notifier

def main():
    parser = argparse.ArgumentParser(description="PatchWatchdog – Vérification de patch & CVE")
    parser.add_argument("--os", choices=["linux", "windows"], required=True)
    parser.add_argument("--notify", choices=["slack", "github"], help="Méthode de notification")
    args = parser.parse_args()

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

if __name__ == "__main__":
    main()