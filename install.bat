@echo off
echo [*] Installation PatchWatchdog...

:: Vérifier si Python est installé
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python n'est pas installé ou n'est pas dans le PATH.
    echo [!] Veuillez installer Python depuis https://www.python.org/downloads/
    echo [!] Assurez-vous de cocher l'option "Add Python to PATH" lors de l'installation.
    pause
    exit /b 1
)

:: Installer les dépendances
echo [*] Installation des dépendances...
python -m pip install -r requirements.txt

echo [✓] Installation complète. Exemple d'exécution :
echo python patchwatchdog.py --os windows --notify slack
echo.
echo Appuyez sur une touche pour quitter...
pause >nul
