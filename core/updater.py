import subprocess
import sys
import json


def _run_ps(command, timeout=120):
    """Exécute une commande PowerShell et retourne (stdout, stderr, returncode)."""
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


def check_os_updates(os_type):
    """
    Vérifie les mises à jour disponibles pour le système d'exploitation.

    Returns:
        dict: {available, critical, updates_list, command_output}
    """
    updates = {
        "available": False,
        "critical": False,
        "updates_list": [],
        "command_output": ""
    }

    try:
        if os_type == "linux":
            import subprocess as sp
            out = sp.check_output(
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
                    "Délai dépassé lors de la recherche Windows Update (>120s). "
                    "Vérifiez manuellement via Paramètres > Windows Update."
                )
                return updates

            if rc == 0 and stdout.strip():
                try:
                    data = json.loads(stdout.strip())
                    for u in data.get("updates", []):
                        updates["updates_list"].append({
                            "package": u.get("title", "Mise à jour inconnue"),
                            "critical": bool(u.get("critical", False))
                        })
                    updates["available"] = data.get("count", 0) > 0
                    updates["critical"] = any(u["critical"] for u in updates["updates_list"])
                except json.JSONDecodeError:
                    updates["command_output"] = (
                        "Impossible de parser la réponse Windows Update. "
                        "Vérifiez manuellement via Paramètres > Windows Update."
                    )

    except Exception as e:
        updates["command_output"] = f"Erreur lors de la vérification des mises à jour : {e}"

    return updates


def apply_os_updates(os_type, critical_only=True):
    """
    Applique les mises à jour du système d'exploitation.

    Returns:
        dict: {success, message, command_output}
    """
    result = {"success": False, "message": "", "command_output": ""}

    try:
        if os_type == "linux":
            import subprocess as sp
            filter_flag = (
                "-t $(lsb_release -cs)-security" if critical_only else ""
            )
            cmd = (
                f"apt-get update -qq && apt-get upgrade -y "
                f"-o Dpkg::Options::='--force-confdef' "
                f"-o Dpkg::Options::='--force-confold' {filter_flag}"
            )
            out = sp.check_output(cmd, shell=True, text=True, timeout=600)
            result["command_output"] = out
            result["success"] = True
            result["message"] = "Mises à jour Linux appliquées avec succès."

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

if ($toInstall.Count -eq 0) {{
    Write-Output "NO_UPDATES"
    exit 0
}}

$installer = $session.CreateUpdateInstaller()
$installer.Updates = $toInstall
$res = $installer.Install()
Write-Output "RESULT_CODE:$($res.ResultCode)"
Write-Output "REBOOT:$($res.RebootRequired)"
"""
            stdout, stderr, rc = _run_ps(ps_cmd, timeout=600)
            result["command_output"] = stdout or stderr

            if stderr == "TIMEOUT":
                result["message"] = "Délai dépassé lors de l'installation (>10 min)."
            elif "NO_UPDATES" in stdout:
                result["success"] = True
                result["message"] = "Aucune mise à jour critique à installer."
            elif "RESULT_CODE:2" in stdout:
                result["success"] = True
                reboot = "REBOOT:True" in stdout
                result["message"] = (
                    "Mises à jour installées. Un redémarrage est nécessaire."
                    if reboot else
                    "Mises à jour installées avec succès."
                )
            else:
                result["message"] = (
                    "Échec ou résultat inattendu. "
                    "Vérifiez Windows Update manuellement."
                )

    except Exception as e:
        result["message"] = f"Erreur : {e}"

    return result


def upgrade_pip_packages(package_names):
    """
    Met à jour une liste de packages pip vers leur dernière version.

    Returns:
        dict: {success, upgraded, failed}
    """
    upgraded = []
    failed = []

    for name in package_names:
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--upgrade", "--quiet", name],
                timeout=120
            )
            upgraded.append(name)
            print(f"    [✓] {name} mis à jour.")
        except Exception as e:
            failed.append({"package": name, "error": str(e)})
            print(f"    [✗] {name} : {e}")

    return {"success": len(failed) == 0, "upgraded": upgraded, "failed": failed}


def upgrade_system_packages(package_names, os_type):
    """
    Met à jour des packages système.

    - Windows : tente Install-Package (NuGet/PackageManagement) puis suggère la commande manuelle.
    - Linux   : apt-get install --only-upgrade.

    Returns:
        dict: {success, upgraded, failed, manual_steps}
    """
    upgraded = []
    failed = []
    manual_steps = []

    if os_type == "linux":
        for name in package_names:
            try:
                subprocess.check_call(
                    ["apt-get", "install", "--only-upgrade", "-y", name],
                    timeout=120
                )
                upgraded.append(name)
                print(f"    [✓] {name} mis à jour.")
            except Exception as e:
                failed.append({"package": name, "error": str(e)})
                print(f"    [✗] {name} : {e}")

    elif os_type == "windows":
        for name in package_names:
            # Tentative via PowerShell Install-Package
            ps_cmd = (
                f"Install-Package -Name '{name}' -Force -AcceptLicense "
                f"-ErrorAction SilentlyContinue | Out-Null; Write-Output 'DONE'"
            )
            stdout, stderr, rc = _run_ps(ps_cmd, timeout=120)

            if "DONE" in stdout and rc == 0:
                upgraded.append(name)
                print(f"    [✓] {name} mis à jour via Install-Package.")
            else:
                # Fournir la commande manuelle
                manual_cmd = f'winget upgrade --name "{name}" --accept-source-agreements'
                failed.append({"package": name, "error": "Install-Package non disponible"})
                manual_steps.append({"package": name, "command": manual_cmd})
                print(f"    [~] {name} : mise à jour manuelle requise.")
                print(f"        > {manual_cmd}")

    return {
        "success": len(failed) == 0 or len(upgraded) > 0,
        "upgraded": upgraded,
        "failed": failed,
        "manual_steps": manual_steps,
    }



def check_os_updates(os_type):
    """
    Vérifie les mises à jour disponibles pour le système d'exploitation.

    Returns:
        dict: {available, critical, updates_list, command_output}
    """
    updates = {
        "available": False,
        "critical": False,
        "updates_list": [],
        "command_output": ""
    }

    try:
        if os_type == "linux":
            import subprocess as sp
            out = sp.check_output(
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
                    "Délai dépassé lors de la recherche Windows Update (>120s). "
                    "Vérifiez manuellement via Paramètres > Windows Update."
                )
                return updates

            if rc == 0 and stdout.strip():
                try:
                    data = json.loads(stdout.strip())
                    for u in data.get("updates", []):
                        updates["updates_list"].append({
                            "package": u.get("title", "Mise à jour inconnue"),
                            "critical": bool(u.get("critical", False))
                        })
                    updates["available"] = data.get("count", 0) > 0
                    updates["critical"] = any(u["critical"] for u in updates["updates_list"])
                except json.JSONDecodeError:
                    updates["command_output"] = (
                        "Impossible de parser la réponse Windows Update. "
                        "Vérifiez manuellement via Paramètres > Windows Update."
                    )

    except Exception as e:
        updates["command_output"] = f"Erreur lors de la vérification des mises à jour : {e}"

    return updates


def apply_os_updates(os_type, critical_only=True):
    """
    Applique les mises à jour du système d'exploitation.

    Returns:
        dict: {success, message, command_output}
    """
    result = {"success": False, "message": "", "command_output": ""}

    try:
        if os_type == "linux":
            import subprocess as sp
            filter_flag = (
                "-t $(lsb_release -cs)-security" if critical_only else ""
            )
            cmd = (
                f"apt-get update -qq && apt-get upgrade -y "
                f"-o Dpkg::Options::='--force-confdef' "
                f"-o Dpkg::Options::='--force-confold' {filter_flag}"
            )
            out = sp.check_output(cmd, shell=True, text=True, timeout=600)
            result["command_output"] = out
            result["success"] = True
            result["message"] = "Mises à jour Linux appliquées avec succès."

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

if ($toInstall.Count -eq 0) {{
    Write-Output "NO_UPDATES"
    exit 0
}}

$installer = $session.CreateUpdateInstaller()
$installer.Updates = $toInstall
$res = $installer.Install()
Write-Output "RESULT_CODE:$($res.ResultCode)"
Write-Output "REBOOT:$($res.RebootRequired)"
"""
            stdout, stderr, rc = _run_ps(ps_cmd, timeout=600)
            result["command_output"] = stdout or stderr

            if stderr == "TIMEOUT":
                result["message"] = "Délai dépassé lors de l'installation (>10 min)."
            elif "NO_UPDATES" in stdout:
                result["success"] = True
                result["message"] = "Aucune mise à jour critique à installer."
            elif "RESULT_CODE:2" in stdout:
                result["success"] = True
                reboot = "REBOOT:True" in stdout
                result["message"] = (
                    "Mises à jour installées. Un redémarrage est nécessaire."
                    if reboot else
                    "Mises à jour installées avec succès."
                )
            else:
                result["message"] = (
                    "Échec ou résultat inattendu. "
                    "Vérifiez Windows Update manuellement."
                )

    except Exception as e:
        result["message"] = f"Erreur : {e}"

    return result


def upgrade_pip_packages(package_names):
    """
    Met à jour une liste de packages pip.

    Args:
        package_names (list[str]): Noms des packages à mettre à jour.

    Returns:
        dict: {success, upgraded, failed}
    """
    upgraded = []
    failed = []

    for name in package_names:
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--upgrade", name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=120
            )
            upgraded.append(name)
        except Exception as e:
            failed.append({"package": name, "error": str(e)})

    return {
        "success": len(failed) == 0,
        "upgraded": upgraded,
        "failed": failed
    }


def check_os_updates(os_type):
    """
    Vérifie les mises à jour disponibles pour le système d'exploitation.
    
    Args:
        os_type (str): Type d'OS (linux ou windows)
    
    Returns:
        dict: Informations sur les mises à jour disponibles
    """
    updates = {
        "available": False,
        "critical": False,
        "updates_list": [],
        "command_output": ""
    }
    
    try:
        if os_type == "linux":
            # Vérifier les mises à jour sur Linux (Ubuntu/Debian)
            output = subprocess.check_output(
                "apt-get update -qq && apt list --upgradable 2>/dev/null",
                shell=True, text=True
            )
            updates["command_output"] = output
            
            # Analyser la sortie pour trouver les packages à mettre à jour
            lines = output.strip().split('\n')
            for line in lines:
                if "upgradable" in line:
                    parts = line.split('/')
                    if len(parts) > 0:
                        package_info = parts[0].strip()
                        updates["updates_list"].append({
                            "package": package_info,
                            "critical": "security" in line.lower()
                        })
            
            # Vérifier s'il y a des mises à jour critiques
            updates["available"] = len(updates["updates_list"]) > 0
            updates["critical"] = any(update["critical"] for update in updates["updates_list"])
            
        elif os_type == "windows":
            # Vérifier les mises à jour sur Windows via PowerShell
            ps_command = """
            $updateSession = New-Object -ComObject Microsoft.Update.Session
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            $searchResult = $updateSearcher.Search("IsInstalled=0")
            $updates = @()
            
            foreach ($update in $searchResult.Updates) {
                $updates += @{
                    "title" = $update.Title
                    "critical" = $update.MsrcSeverity -eq "Critical"
                }
            }
            
            ConvertTo-Json -InputObject @{
                "count" = $searchResult.Updates.Count
                "updates" = $updates
            }
            """
            
            try:
                output = subprocess.check_output(
                    ["powershell", "-Command", ps_command],
                    text=True, stderr=subprocess.PIPE,
                    timeout=120
                )
                updates["command_output"] = output
                
                # Analyser la sortie JSON
                import json
                result = json.loads(output)
                
                if result["count"] > 0:
                    updates["available"] = True
                    for update in result["updates"]:
                        updates["updates_list"].append({
                            "package": update["title"],
                            "critical": update["critical"]
                        })
                    updates["critical"] = any(update["critical"] for update in updates["updates_list"])
            except subprocess.TimeoutExpired:
                updates["command_output"] = "La vérification Windows Update a dépassé le délai. Vérifiez Windows Update manuellement."
            except Exception as e:
                # Méthode alternative pour Windows si PowerShell échoue
                try:
                    output = subprocess.check_output(
                        ["wmic", "qfe", "list", "brief"],
                        text=True, stderr=subprocess.PIPE
                    )
                    updates["command_output"] = "Impossible de vérifier les mises à jour via PowerShell. Utilisez Windows Update manuellement."
                except:
                    updates["command_output"] = "Impossible de vérifier les mises à jour Windows. Vérifiez manuellement via Windows Update."
    
    except Exception as e:
        updates["command_output"] = f"Erreur lors de la vérification des mises à jour: {str(e)}"
    
    return updates

def apply_os_updates(os_type, critical_only=True):
    """
    Applique les mises à jour du système d'exploitation.
    
    Args:
        os_type (str): Type d'OS (linux ou windows)
        critical_only (bool): Si True, n'applique que les mises à jour critiques
    
    Returns:
        dict: Résultat de l'opération de mise à jour
    """
    result = {
        "success": False,
        "message": "",
        "command_output": ""
    }
    
    try:
        if os_type == "linux":
            if critical_only:
                # Appliquer uniquement les mises à jour de sécurité sur Linux
                command = "apt-get update -qq && apt-get upgrade -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' --only-upgrade -t $(lsb_release -cs)-security"
            else:
                # Appliquer toutes les mises à jour sur Linux
                command = "apt-get update -qq && apt-get upgrade -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold'"
            
            output = subprocess.check_output(command, shell=True, text=True)
            result["command_output"] = output
            result["success"] = True
            result["message"] = "Mises à jour appliquées avec succès"
            
        elif os_type == "windows":
            # Appliquer les mises à jour sur Windows via PowerShell
            ps_command = """
            $updateSession = New-Object -ComObject Microsoft.Update.Session
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            $searchResult = $updateSearcher.Search("IsInstalled=0")
            
            if ($searchResult.Updates.Count -eq 0) {
                Write-Output "Aucune mise à jour disponible."
                exit 0
            }
            
            $updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
            
            foreach ($update in $searchResult.Updates) {
                if ($update.IsDownloaded) {
                    if ($args[0] -eq "critical") {
                        if ($update.MsrcSeverity -eq "Critical") {
                            $updatesToInstall.Add($update) | Out-Null
                        }
                    } else {
                        $updatesToInstall.Add($update) | Out-Null
                    }
                }
            }
            
            if ($updatesToInstall.Count -eq 0) {
                Write-Output "Aucune mise à jour à installer."
                exit 0
            }
            
            $installer = $updateSession.CreateUpdateInstaller()
            $installer.Updates = $updatesToInstall
            $installResult = $installer.Install()
            
            Write-Output "Résultat: $($installResult.ResultCode)"
            Write-Output "Redémarrage nécessaire: $($installResult.RebootRequired)"
            """
            
            critical_param = "critical" if critical_only else "all"
            try:
                output = subprocess.check_output(
                    ["powershell", "-Command", ps_command, critical_param],
                    text=True, stderr=subprocess.PIPE,
                    timeout=300
                )
                result["command_output"] = output
                result["success"] = "Résultat: 2" in output or "Aucune mise à jour" in output
                result["message"] = "Mises à jour Windows appliquées avec succès" if result["success"] else "Erreur lors de l'application des mises à jour Windows"
            except subprocess.TimeoutExpired:
                result["command_output"] = "L'installation Windows Update a dépassé le délai (5 min). Utilisez Windows Update manuellement."
                result["message"] = "Timeout lors de l'application des mises à jour."
            except Exception as e:
                result["command_output"] = f"Erreur lors de l'application des mises à jour Windows: {str(e)}"
                result["message"] = "Impossible d'appliquer les mises à jour automatiquement. Utilisez Windows Update manuellement."
    
    except Exception as e:
        result["command_output"] = f"Erreur lors de l'application des mises à jour: {str(e)}"
        result["message"] = "Échec de l'application des mises à jour"
    
    return result
