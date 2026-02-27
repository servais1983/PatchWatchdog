@echo off
setlocal enabledelayedexpansion
echo [*] Installation PatchWatchdog...

:: Vérifier si Python est installé
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python n'est pas installe ou n'est pas dans le PATH.
    echo [!] Telechargez Python sur https://www.python.org/downloads/
    echo [!] Cochez bien "Add Python to PATH" lors de l'installation.
    pause
    exit /b 1
)

:: Mettre pip à jour (résout des CVEs connues dans pip lui-même)
echo [*] Mise a jour de pip...
python -m pip install --upgrade pip --quiet

:: Installer les dépendances
echo [*] Installation des dependances...
python -m pip install -r requirements.txt --quiet
if %errorlevel% neq 0 (
    echo [!] Erreur lors de l'installation des dependances.
    pause
    exit /b 1
)

:: Créer le fichier .env s'il n'existe pas encore
if not exist ".env" (
    if exist ".env.example" (
        copy ".env.example" ".env" >nul
        echo [i] Fichier .env cree depuis .env.example
        echo [i] Editez .env pour configurer vos webhooks et tokens.
    )
)

:: Créer le dossier reports
if not exist "reports" mkdir reports

echo.
echo [OK] Installation complete !
echo.
echo Exemples d'utilisation :
echo   python patchwatchdog.py --os windows
echo   python patchwatchdog.py --os windows --check-updates
echo   python patchwatchdog.py --os windows --auto-update
echo   python patchwatchdog.py --os windows --notify slack
echo.
pause >nul
