import requests

API = "https://vulners.com/api/v3/burp/software/"

def check_vulners(package_list):
    vulnerable = []
    for pkg in package_list:
        try:
            r = requests.get(API, params={"software": pkg["package"], "version": pkg["version"]})
            data = r.json()
            if data.get("data", {}).get("search"):
                for hit in data["data"]["search"]:
                    vulnerable.append({
                        "package": pkg["package"],
                        "version": pkg["version"],
                        "cve": hit.get("id", "unknown")
                    })
        except:
            continue
    return vulnerable