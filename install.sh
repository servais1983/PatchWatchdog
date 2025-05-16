#!/bin/bash
echo "[*] Installation PatchWatchdog..."

sudo apt update
sudo apt install -y python3 python3-pip
pip install -r requirements.txt

echo "[✓] Installation complète. Exemple d'exécution :"
echo "python3 patchwatchdog.py --os linux --notify slack"