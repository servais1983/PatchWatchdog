import subprocess
import sys
import re


def _run(cmd, shell=False, timeout=60):
    """Lance une commande silencieusement (stderr supprimé). Retourne stdout décodé ou None."""
    try:
        return subprocess.check_output(
            cmd, shell=shell, timeout=timeout,
            stderr=subprocess.DEVNULL
        ).decode(errors="ignore")
    except Exception:
        return None


def _add_pip_packages(pkgs):
    """Collecte les packages installés via pip."""
    out = _run([sys.executable, "-m", "pip", "list", "--format=freeze"], shell=False, timeout=60)
    if out:
        for line in out.splitlines():
            if "==" in line:
                name, version = line.strip().split("==", 1)
                pkgs.append({"package": name.strip(), "version": version.strip(), "type": "pip"})


def _dedup(pkgs):
    """Supprime les doublons en conservant la première occurrence (name+version, insensible à la casse)."""
    seen = set()
    result = []
    for p in pkgs:
        key = (p["package"].lower(), p["version"].lower(), p.get("type", "system"))
        if key not in seen:
            seen.add(key)
            result.append(p)
    return result


def get_packages(os_type):
    """
    Retourne la liste des packages installés sur le système.

    Chaque entrée est un dict avec les clés:
        package (str), version (str), type ('pip' | 'system')
    """
    pkgs = []

    if os_type == "linux":
        # Packages système (dpkg / apt)
        out = _run(["dpkg-query", "-W", "-f=${binary:Package} ${Version}\n"])
        if out:
            for line in out.splitlines():
                parts = line.strip().split(" ", 1)
                if len(parts) == 2:
                    pkgs.append({"package": parts[0], "version": parts[1], "type": "system"})
        _add_pip_packages(pkgs)

    elif os_type == "windows":
        # Méthode 1: PowerShell Get-Package (Windows 10 / 11 / Server 2016+)
        ps_get_pkg = (
            "Get-Package | Select-Object Name,Version | "
            "ConvertTo-Csv -NoTypeInformation"
        )
        out = _run(["powershell", "-NoProfile", "-Command", ps_get_pkg], timeout=60)
        if out:
            lines = out.splitlines()
            for line in lines[1:]:          # ignorer l'en-tête CSV
                line = line.replace('"', '').strip()
                if ',' in line:
                    parts = line.split(',', 1)
                    name, version = parts[0].strip(), parts[1].strip()
                    if name and version:
                        pkgs.append({"package": name, "version": version, "type": "system"})

        # Méthode 2: Registre Windows via PowerShell (fiable sur toutes les versions)
        if not pkgs:
            ps_reg = (
                "$paths = @("
                "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
                "'HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'"
                ");"
                "Get-ItemProperty $paths -ErrorAction SilentlyContinue | "
                "Where-Object { $_.DisplayName -and $_.DisplayVersion } | "
                "Select-Object DisplayName,DisplayVersion | "
                "ConvertTo-Csv -NoTypeInformation"
            )
            out = _run(["powershell", "-NoProfile", "-Command", ps_reg], timeout=60)
            if out:
                for line in out.splitlines()[1:]:
                    line = line.replace('"', '').strip()
                    if ',' in line:
                        parts = line.split(',', 1)
                        name, version = parts[0].strip(), parts[1].strip()
                        if name and version:
                            pkgs.append({"package": name, "version": version, "type": "system"})

        # Toujours collecter les packages pip
        _add_pip_packages(pkgs)

    return _dedup(pkgs)