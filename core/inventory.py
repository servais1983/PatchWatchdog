import subprocess
import sys
import os
import platform
import re

def get_packages(os_type):
    pkgs = []

    if os_type == "linux":
        try:
            output = subprocess.check_output(["dpkg-query", "-W", "-f=${binary:Package} ${Version}\n"])
            for line in output.decode().splitlines():
                name, version = line.strip().split(" ", 1)
                pkgs.append({"package": name, "version": version})
        except:
            pass
        try:
            pip = subprocess.check_output([sys.executable, "-m", "pip", "list", "--format=freeze"])
            for line in pip.decode().splitlines():
                if "==" in line:
                    name, version = line.split("==")
                    pkgs.append({"package": name, "version": version})
        except:
            pass

    elif os_type == "windows":
        # Méthode 1: WMIC (pour Windows 7, 8, 10, Server jusqu'à 2019)
        try:
            output = subprocess.check_output(["wmic", "product", "get", "name,version"], shell=True)
            for line in output.decode(errors="ignore").splitlines()[1:]:
                line = line.strip()
                if line:
                    # Amélioration du parsing pour gérer les espaces dans les noms
                    match = re.search(r'(.+?)\s+(\d+[\d\.]+)$', line)
                    if match:
                        name, version = match.groups()
                        pkgs.append({"package": name.strip(), "version": version.strip()})
        except:
            pass
            
        # Méthode 2: PowerShell Get-Package (pour Windows 10, 11, Server 2016+)
        try:
            ps_cmd = "powershell -Command \"Get-Package | Select-Object Name, Version | ConvertTo-Csv -NoTypeInformation\""
            output = subprocess.check_output(ps_cmd, shell=True)
            lines = output.decode(errors="ignore").splitlines()
            if len(lines) > 1:  # Skip header
                for line in lines[1:]:
                    if ',' in line:
                        # Gestion des CSV avec guillemets
                        line = line.replace('"', '')
                        parts = line.split(',')
                        if len(parts) >= 2:
                            name, version = parts[0], parts[1]
                            if name and version:
                                pkgs.append({"package": name.strip(), "version": version.strip()})
        except:
            pass
            
        # Méthode 3: PowerShell Get-WmiObject (alternative pour Windows 7+)
        if not pkgs:
            try:
                ps_cmd = "powershell -Command \"Get-WmiObject -Class Win32_Product | Select-Object Name, Version | ConvertTo-Csv -NoTypeInformation\""
                output = subprocess.check_output(ps_cmd, shell=True)
                lines = output.decode(errors="ignore").splitlines()
                if len(lines) > 1:  # Skip header
                    for line in lines[1:]:
                        if ',' in line:
                            line = line.replace('"', '')
                            parts = line.split(',')
                            if len(parts) >= 2:
                                name, version = parts[0], parts[1]
                                if name and version:
                                    pkgs.append({"package": name.strip(), "version": version.strip()})
            except:
                pass
        
        # Toujours collecter les packages pip sur Windows
        try:
            pip = subprocess.check_output([sys.executable, "-m", "pip", "list", "--format=freeze"], shell=True)
            for line in pip.decode(errors="ignore").splitlines():
                if "==" in line:
                    name, version = line.split("==")
                    pkgs.append({"package": name, "version": version})
        except:
            pass

    return pkgs