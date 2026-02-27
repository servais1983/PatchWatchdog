"""
Updater module for PatchWatchdog.

Handles OS update checks/application and package upgrades.
"""
import subprocess
import sys
import json


def _run_ps(command, timeout=120):
    """Run a PowerShell command. Returns (stdout, stderr, returncode)."""
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True, text=True, timeout=timeout
        )
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", 1
    except Exception as e:
        return "", str(e), 1


# ---------------------------------------------------------------------------
# OS update check
# ---------------------------------------------------------------------------

def check_os_updates(os_type):
    """
    Check for available OS updates.

    Returns:
        dict: {available (bool), critical (bool), updates_list (list), command_output (str)}
    """
    updates = {
        "available": False,
        "critical": False,
        "updates_list": [],
        "command_output": "",
    }

    try:
        if os_type == "linux":
            out = subprocess.check_output(
                "apt-get update -qq && apt list --upgradable 2>/dev/null",
                shell=True, text=True, timeout=120
            )
            updates["command_output"] = out
            for line in out.strip().splitlines():
                if "upgradable" in line:
                    pkg_name = line.split("/")[0].strip()
                    is_critical = "security" in line.lower()
                    updates["updates_list"].append({"package": pkg_name, "critical": is_critical})
            updates["available"] = bool(updates["updates_list"])
            updates["critical"] = any(u["critical"] for u in updates["updates_list"])

        elif os_type == "windows":
            ps_cmd = """
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$result = $searcher.Search("IsInstalled=0")
$list = @()
foreach ($u in $result.Updates) {
    $list += @{ title = $u.Title; critical = ($u.MsrcSeverity -eq "Critical") }
}
ConvertTo-Json -Compress -InputObject @{ count = $result.Updates.Count; updates = $list }
"""
            stdout, stderr, rc = _run_ps(ps_cmd, timeout=120)
            updates["command_output"] = stdout or stderr

            if stderr == "TIMEOUT":
                updates["command_output"] = (
                    "Windows Update search timed out (>120s). "
                    "Check manually via Settings > Windows Update."
                )
                return updates

            if rc == 0 and stdout.strip():
                try:
                    data = json.loads(stdout.strip())
                    for u in data.get("updates", []):
                        updates["updates_list"].append({
                            "package": u.get("title", "Unknown update"),
                            "critical": bool(u.get("critical", False)),
                        })
                    updates["available"] = data.get("count", 0) > 0
                    updates["critical"] = any(u["critical"] for u in updates["updates_list"])
                except json.JSONDecodeError:
                    updates["command_output"] = (
                        "Could not parse Windows Update response. "
                        "Check manually via Settings > Windows Update."
                    )

    except Exception as e:
        updates["command_output"] = f"Error checking for updates: {e}"

    return updates


# ---------------------------------------------------------------------------
# OS update application
# ---------------------------------------------------------------------------

def apply_os_updates(os_type, critical_only=True):
    """
    Apply OS updates.

    Returns:
        dict: {success (bool), message (str), command_output (str)}
    """
    result = {"success": False, "message": "", "command_output": ""}

    try:
        if os_type == "linux":
            filter_flag = "-t $(lsb_release -cs)-security" if critical_only else ""
            cmd = (
                "apt-get update -qq && apt-get upgrade -y "
                "-o Dpkg::Options::='--force-confdef' "
                f"-o Dpkg::Options::='--force-confold' {filter_flag}"
            )
            out = subprocess.check_output(cmd, shell=True, text=True, timeout=600)
            result.update({"command_output": out, "success": True,
                           "message": "Linux updates applied successfully."})

        elif os_type == "windows":
            critical_filter = 'if ($u.MsrcSeverity -ne "Critical") { continue }' if critical_only else ""
            ps_cmd = f"""
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$found = $searcher.Search("IsInstalled=0")
$toInstall = New-Object -ComObject Microsoft.Update.UpdateColl

foreach ($u in $found.Updates) {{
    {critical_filter}
    if (-not $u.IsDownloaded) {{
        $dl = $session.CreateUpdateDownloader()
        $dl.Updates = (New-Object -ComObject Microsoft.Update.UpdateColl)
        $dl.Updates.Add($u) | Out-Null
        $dl.Download() | Out-Null
    }}
    $toInstall.Add($u) | Out-Null
}}

if ($toInstall.Count -eq 0) {{ Write-Output "NO_UPDATES"; exit 0 }}

$installer = $session.CreateUpdateInstaller()
$installer.Updates = $toInstall
$res = $installer.Install()
Write-Output "RESULT_CODE:$($res.ResultCode)"
Write-Output "REBOOT:$($res.RebootRequired)"
"""
            stdout, stderr, rc = _run_ps(ps_cmd, timeout=600)
            result["command_output"] = stdout or stderr

            if stderr == "TIMEOUT":
                result["message"] = "Install timed out (>10 min). Use Windows Update manually."
            elif "NO_UPDATES" in stdout:
                result.update({"success": True, "message": "No critical updates to install."})
            elif "RESULT_CODE:2" in stdout:
                reboot = "REBOOT:True" in stdout
                result.update({
                    "success": True,
                    "message": ("Updates installed. A reboot is required."
                                if reboot else "Updates installed successfully."),
                })
            else:
                result["message"] = "Unexpected result. Check Windows Update manually."

    except Exception as e:
        result["message"] = f"Error: {e}"

    return result


# ---------------------------------------------------------------------------
# pip package upgrades
# ---------------------------------------------------------------------------

def upgrade_pip_packages(package_names):
    """
    Upgrade a list of pip packages to their latest versions.

    Returns:
        dict: {success (bool), upgraded (list), failed (list)}
    """
    upgraded = []
    failed = []

    for name in package_names:
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--upgrade", "--quiet", name],
                timeout=120,
            )
            upgraded.append(name)
            print(f"    [OK] {name} upgraded.")
        except Exception as e:
            failed.append({"package": name, "error": str(e)})
            print(f"    [FAIL] {name}: {e}")

    return {"success": len(failed) == 0, "upgraded": upgraded, "failed": failed}


# ---------------------------------------------------------------------------
# System package upgrades
# ---------------------------------------------------------------------------

def upgrade_system_packages(package_names, os_type):
    """
    Upgrade system packages.

    - Windows: attempts Install-Package (PackageManagement), falls back to
               providing the equivalent winget command for manual execution.
    - Linux:   apt-get install --only-upgrade.

    Returns:
        dict: {success (bool), upgraded (list), failed (list), manual_steps (list)}
    """
    upgraded = []
    failed = []
    manual_steps = []

    if os_type == "linux":
        for name in package_names:
            try:
                subprocess.check_call(
                    ["apt-get", "install", "--only-upgrade", "-y", name],
                    timeout=120,
                )
                upgraded.append(name)
                print(f"    [OK] {name} upgraded.")
            except Exception as e:
                failed.append({"package": name, "error": str(e)})
                print(f"    [FAIL] {name}: {e}")

    elif os_type == "windows":
        for name in package_names:
            ps_cmd = (
                f"Install-Package -Name '{name}' -Force -AcceptLicense "
                f"-ErrorAction SilentlyContinue | Out-Null; Write-Output 'DONE'"
            )
            stdout, stderr, rc = _run_ps(ps_cmd, timeout=120)

            if "DONE" in stdout and rc == 0:
                upgraded.append(name)
                print(f"    [OK] {name} upgraded via Install-Package.")
            else:
                manual_cmd = f'winget upgrade --name "{name}" --accept-source-agreements'
                failed.append({"package": name, "error": "Install-Package unavailable"})
                manual_steps.append({"package": name, "command": manual_cmd})
                print(f"    [~] {name}: manual update required.")
                print(f"        > {manual_cmd}")

    return {
        "success": len(failed) == 0 or len(upgraded) > 0,
        "upgraded": upgraded,
        "failed": failed,
        "manual_steps": manual_steps,
    }