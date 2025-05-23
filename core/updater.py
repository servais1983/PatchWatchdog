import os
import platform
import subprocess
import sys

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
                    text=True, stderr=subprocess.PIPE
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
                    text=True, stderr=subprocess.PIPE
                )
                result["command_output"] = output
                result["success"] = "Résultat: 2" in output or "Aucune mise à jour" in output
                result["message"] = "Mises à jour Windows appliquées avec succès" if result["success"] else "Erreur lors de l'application des mises à jour Windows"
            except Exception as e:
                result["command_output"] = f"Erreur lors de l'application des mises à jour Windows: {str(e)}"
                result["message"] = "Impossible d'appliquer les mises à jour automatiquement. Utilisez Windows Update manuellement."
    
    except Exception as e:
        result["command_output"] = f"Erreur lors de l'application des mises à jour: {str(e)}"
        result["message"] = "Échec de l'application des mises à jour"
    
    return result
