#!/bin/bash
set -e
echo "[*] Installation PatchWatchdog..."

# Vérifier Python 3
if ! command -v python3 &>/dev/null; then
    echo "[*] Installation de Python 3..."
    sudo apt-get update -qq
    sudo apt-get install -y python3 python3-pip
fi

# Mettre pip à jour (résout des CVEs connues dans pip lui-même)
echo "[*] Mise à jour de pip..."
python3 -m pip install --upgrade pip --quiet

# Installer les dépendances
echo "[*] Installation des dépendances..."
python3 -m pip install -r requirements.txt --quiet

# Créer .env s'il n'existe pas
if [ ! -f .env ] && [ -f .env.example ]; then
    cp .env.example .env
    echo "[i] Fichier .env créé depuis .env.example"
    echo "[i] Éditez .env pour configurer vos webhooks et tokens."
fi

# Créer le dossier reports
mkdir -p reports

echo ""
echo "[OK] Installation complète !"
echo ""
echo "Exemples d'utilisation :"
echo "  python3 patchwatchdog.py --os linux"
echo "  python3 patchwatchdog.py --os linux --check-updates"
echo "  python3 patchwatchdog.py --os linux --auto-update"
echo "  python3 patchwatchdog.py --os linux --notify slack"
