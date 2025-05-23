import requests
import time

API = "https://vulners.com/api/v3/burp/software/"

def check_vulners(package_list, max_packages=50):
    """
    Vérifie les vulnérabilités des packages via l'API Vulners.
    
    Args:
        package_list (list): Liste des packages à vérifier
        max_packages (int): Nombre maximum de packages à vérifier (pour éviter les blocages)
    
    Returns:
        list: Liste des packages vulnérables
    """
    print(f"[🔍] Vérification des vulnérabilités pour {min(len(package_list), max_packages)} packages sur {len(package_list)} détectés...")
    
    vulnerable = []
    # Limiter le nombre de packages pour éviter les blocages
    limited_packages = package_list[:max_packages]
    
    for i, pkg in enumerate(limited_packages):
        # Afficher la progression tous les 10 packages
        if i > 0 and i % 10 == 0:
            print(f"[🔄] Progression: {i}/{len(limited_packages)} packages vérifiés...")
        
        try:
            # Ajouter un délai pour éviter de surcharger l'API
            if i > 0 and i % 5 == 0:
                time.sleep(0.5)
                
            r = requests.get(API, params={"software": pkg["package"], "version": pkg["version"]}, timeout=5)
            data = r.json()
            if data.get("data", {}).get("search"):
                for hit in data["data"]["search"]:
                    vulnerable.append({
                        "package": pkg["package"],
                        "version": pkg["version"],
                        "cve": hit.get("id", "unknown")
                    })
        except Exception as e:
            print(f"[⚠️] Erreur lors de la vérification du package {pkg['package']}: {str(e)}")
            continue
    
    print(f"[✓] Vérification terminée: {len(vulnerable)} vulnérabilités détectées.")
    return vulnerable