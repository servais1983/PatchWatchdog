import subprocess
import sys

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
        try:
            output = subprocess.check_output(["wmic", "product", "get", "name,version"])
            for line in output.decode(errors="ignore").splitlines()[1:]:
                parts = line.strip().rsplit(" ", 1)
                if len(parts) == 2:
                    pkgs.append({"package": parts[0], "version": parts[1]})
        except:
            pass

    return pkgs