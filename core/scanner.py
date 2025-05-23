import requests
import time
import random

API = "https://vulners.com/api/v3/burp/software/"

def check_vulners(package_list, batch_size=20):
    """
    Vérifie les vulnérabilités des packages via l'API Vulners.
    
    Args:
        package_list (list): Liste des packages à vérifier
        batch_size (int): Nombre de packages à traiter par lot pour afficher la progression
    
    Returns:
        list: Liste des packages vulnérables
    """
    total_packages = len(package_list)
    print(f"[🔍] Vérification des vulnérabilités pour {total_packages} packages...")
    
    vulnerable = []
    retry_count = {}  # Pour suivre les tentatives de requêtes par package
    max_retries = 3   # Nombre maximum de tentatives par package
    
    # Paramètres pour le backoff exponentiel
    base_delay = 0.5
    max_delay = 5.0
    
    for i, pkg in enumerate(package_list):
        # Afficher la progression régulièrement
        if i > 0 and (i % batch_size == 0 or i == total_packages - 1):
            progress_percent = (i / total_packages) * 100
            print(f"[🔄] Progression: {i}/{total_packages} packages vérifiés ({progress_percent:.1f}%)...")
        
        pkg_id = f"{pkg['package']}@{pkg['version']}"
        retry_count[pkg_id] = 0
        
        while retry_count[pkg_id] < max_retries:
            try:
                # Ajouter un délai variable pour éviter de surcharger l'API
                # Plus de délai après chaque lot et après chaque retry
                if i > 0:
                    # Délai de base pour tous les packages
                    delay = base_delay
                    
                    # Augmenter le délai tous les X packages
                    if i % 10 == 0:
                        delay += 0.2
                    
                    # Ajouter un délai supplémentaire basé sur le nombre de tentatives
                    if retry_count[pkg_id] > 0:
                        # Backoff exponentiel avec jitter
                        exp_backoff = min(max_delay, base_delay * (2 ** retry_count[pkg_id]))
                        jitter = random.uniform(0, 0.5)
                        delay = exp_backoff + jitter
                        
                    # Appliquer le délai
                    time.sleep(delay)
                
                # Effectuer la requête avec timeout
                r = requests.get(
                    API, 
                    params={"software": pkg["package"], "version": pkg["version"]}, 
                    timeout=10  # Timeout plus long pour éviter les erreurs sur réseau lent
                )
                
                # Vérifier le code de statut
                if r.status_code == 429:  # Too Many Requests
                    print(f"[⚠️] Limitation d'API détectée, attente avant nouvelle tentative...")
                    retry_count[pkg_id] += 1
                    time.sleep(10)  # Attente plus longue en cas de rate limiting
                    continue
                    
                r.raise_for_status()  # Lever une exception pour les autres codes d'erreur
                
                data = r.json()
                if data.get("data", {}).get("search"):
                    for hit in data["data"]["search"]:
                        vulnerable.append({
                            "package": pkg["package"],
                            "version": pkg["version"],
                            "cve": hit.get("id", "unknown")
                        })
                
                # Si on arrive ici, c'est que la requête a réussi
                break
                
            except requests.exceptions.Timeout:
                retry_count[pkg_id] += 1
                if retry_count[pkg_id] < max_retries:
                    print(f"[⚠️] Timeout lors de la vérification du package {pkg['package']}, nouvelle tentative ({retry_count[pkg_id]}/{max_retries})...")
                else:
                    print(f"[❌] Échec après {max_retries} tentatives pour {pkg['package']}, package ignoré.")
            
            except requests.exceptions.RequestException as e:
                retry_count[pkg_id] += 1
                if retry_count[pkg_id] < max_retries:
                    print(f"[⚠️] Erreur réseau lors de la vérification du package {pkg['package']}: {str(e)}, nouvelle tentative ({retry_count[pkg_id]}/{max_retries})...")
                else:
                    print(f"[❌] Échec après {max_retries} tentatives pour {pkg['package']}, package ignoré.")
            
            except Exception as e:
                print(f"[⚠️] Erreur inattendue lors de la vérification du package {pkg['package']}: {str(e)}")
                break  # Ne pas réessayer pour les erreurs non liées au réseau
    
    print(f"[✓] Vérification terminée: {len(vulnerable)} vulnérabilités détectées sur {total_packages} packages analysés.")
    return vulnerable