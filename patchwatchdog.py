#!/usr/bin/env python3
"""
PatchWatchdog -- Patch state monitoring and CVE detection.

Scan engines:
  - pip packages   : OSV.dev (free, no key required)
  - system packages: NVD API v2 (free; NVD_API_KEY for 10x speed)
                     or Vulners (VULNERS_API_KEY, paid plan)

Exit codes: 0 = clean  |  1 = vulnerabilities found  |  2 = error
"""

import argparse
import os
import sys

# Chargement optionnel du fichier .env
try:
    from dotenv import load_dotenv
    load_dotenv(override=False)
except ImportError:
    pass

from core import inventory, scanner, notifier, reporter, updater


def main():
    parser = argparse.ArgumentParser(
        description="PatchWatchdog -- Patch monitoring and CVE detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python patchwatchdog.py --os windows\n"
            "  python patchwatchdog.py --os windows --check-updates\n"
            "  python patchwatchdog.py --os windows --auto-update\n"
            "  python patchwatchdog.py --os windows --notify slack\n"
        )
    )
    parser.add_argument("--os", choices=["linux", "windows"], required=True,
                        help="Target operating system")
    parser.add_argument("--notify", choices=["slack", "github"],
                        help="Send an alert if vulnerabilities are found")
    parser.add_argument("--auto-update", action="store_true",
                        help="Automatically install fixes for all detected vulnerabilities")
    parser.add_argument("--check-updates", action="store_true",
                        help="Check for available OS updates (Windows Update / apt)")
    args = parser.parse_args()

    exit_code = 0

    # -- OS update check / apply ----------------------------------------------
    if args.check_updates or args.auto_update:
        print("[*] Checking for OS updates...")
        os_updates = updater.check_os_updates(args.os)

        if os_updates["available"]:
            has_critical = os_updates["critical"]
            label = "critical" if has_critical else "available (none critical)"
            print(f"[{'!!' if has_critical else 'i'}] Updates {label}:")
            for u in os_updates["updates_list"]:
                mark = "  [CRITICAL]" if u.get("critical") else "  [info]   "
                print(f"{mark} {u['package']}")

            if args.auto_update and has_critical:
                print("[*] Applying critical OS updates...")
                res = updater.apply_os_updates(args.os, critical_only=True)
                if res["success"]:
                    print(f"[OK] {res['message']}")
                else:
                    print(f"[FAIL] {res['message']}")
                    exit_code = max(exit_code, 2)
            elif not has_critical:
                print("[OK] No critical updates -- nothing to apply automatically.")
        else:
            msg = os_updates.get("command_output", "").strip()
            print(f"[OK] {msg}" if msg else "[OK] System is up to date.")

    # -- Package inventory ----------------------------------------------------
    print("[*] Scanning installed packages...")
    packages = inventory.get_packages(args.os)

    if not packages:
        print("[FAIL] No packages found. Check permissions.")
        sys.exit(2)

    pip_count = sum(1 for p in packages if p.get("type") == "pip")
    sys_count = len(packages) - pip_count
    print(f"[OK] {len(packages)} packages collected ({pip_count} pip, {sys_count} system).")

    # -- CVE scan -------------------------------------------------------------
    vulnerable = scanner.check_vulners(packages)

    if not vulnerable:
        print("[OK] No vulnerabilities detected.")
    else:
        exit_code = max(exit_code, 1)
        pip_vulns = [v for v in vulnerable if v.get("type") == "pip"
                     or next((p for p in packages
                               if p["package"] == v["package"]), {}).get("type") == "pip"]
        sys_vulns = [v for v in vulnerable if v not in pip_vulns]

        print(f"\n[!!] {len(vulnerable)} vulnerability(ies) detected:\n")

        if pip_vulns:
            print("  -- pip packages --")
            for v in pip_vulns:
                cvss_str = f" | CVSS {v['cvss']:.1f}" if v.get("cvss") is not None else ""
                print(f"  [!] {v['package']} {v['version']} -> {v['cve']}{cvss_str} [{v.get('severity','?')}]")

        if sys_vulns:
            print("  -- system packages --")
            for v in sys_vulns:
                cvss_str = f" | CVSS {v['cvss']:.1f}" if v.get("cvss") is not None else ""
                print(f"  [!] {v['package']} {v['version']} -> {v['cve']}{cvss_str} [{v.get('severity','?')}]")

        print()

        # External notification
        if args.notify:
            notifier.send_alert(vulnerable, method=args.notify)

        # -- Auto-install fixes -----------------------------------------------
        if args.auto_update:
            # 1. pip packages
            pip_names = list({
                v["package"] for v in vulnerable
                if next((p for p in packages
                         if p["package"] == v["package"]), {}).get("type") == "pip"
            })
            if pip_names:
                print(f"[*] Upgrading vulnerable pip packages: {', '.join(pip_names)}")
                pip_res = updater.upgrade_pip_packages(pip_names)
                if pip_res["upgraded"]:
                    print(f"[OK] pip upgraded: {', '.join(pip_res['upgraded'])}")
                if pip_res["failed"]:
                    for f in pip_res["failed"]:
                        print(f"[FAIL] pip {f['package']}: {f['error']}")
                    exit_code = max(exit_code, 2)

            # 2. System packages
            sys_names = list({
                v["package"] for v in vulnerable
                if next((p for p in packages
                         if p["package"] == v["package"]), {}).get("type") != "pip"
            })
            if sys_names:
                print(f"[*] Upgrading vulnerable system packages: {', '.join(sys_names)}")
                sys_res = updater.upgrade_system_packages(sys_names, args.os)
                if sys_res["upgraded"]:
                    print(f"[OK] System packages upgraded: {', '.join(sys_res['upgraded'])}")
                if sys_res.get("manual_steps"):
                    print("[i] Packages requiring manual update:")
                    for step in sys_res["manual_steps"]:
                        print(f"  > {step['command']}")

    # -- HTML report ----------------------------------------------------------
    report_path = reporter.generate_html_report(packages, vulnerable, args.os)
    print(f"[*] HTML report: {os.path.abspath(report_path)}")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
