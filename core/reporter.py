import os
import datetime
from core.utils import format_cve_details, format_severity

def generate_html_report(packages, vulnerable, os_type):
    """
    Génère un rapport HTML complet avec les résultats du scan.
    
    Args:
        packages (list): Liste des packages scannés
        vulnerable (list): Liste des packages vulnérables
        os_type (str): Type d'OS (linux ou windows)
    
    Returns:
        str: Chemin du fichier HTML généré
    """
    # Enrichir les données de vulnérabilité avec des liens et des informations supplémentaires
    for vuln in vulnerable:
        vuln['cve_link'] = format_cve_details(vuln['cve'])
        # Par défaut, on considère toutes les vulnérabilités comme critiques
        vuln['severity'] = 'CRITIQUE'
        
    # Créer le dossier reports s'il n'existe pas
    os.makedirs('reports', exist_ok=True)
    
    # Générer un nom de fichier unique basé sur la date et l'heure
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"reports/patchwatchdog_report_{timestamp}.html"
    
    # Statistiques pour le résumé
    total_packages = len(packages)
    total_vulnerable = len(vulnerable)
    vulnerability_rate = (total_vulnerable / total_packages * 100) if total_packages > 0 else 0
    
    # Générer le contenu HTML
    html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport PatchWatchdog - {timestamp}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
        }}
        header {{
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        h1, h2, h3 {{
            color: #2c3e50;
            margin-top: 30px;
        }}
        header h1 {{
            color: white;
            margin-top: 0;
        }}
        .summary-box {{
            background-color: white;
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
        }}
        .summary-item {{
            text-align: center;
            padding: 15px;
            flex: 1;
            min-width: 200px;
        }}
        .summary-number {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        .summary-label {{
            font-size: 1.1em;
            color: #555;
        }}
        .critical {{
            color: #e74c3c;
        }}
        .safe {{
            color: #27ae60;
        }}
        .warning {{
            color: #f39c12;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background-color: white;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            border-radius: 5px;
            overflow: hidden;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #34495e;
            color: white;
            font-weight: 600;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .container {{
            background-color: white;
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding: 20px;
            color: #7f8c8d;
            font-size: 0.9em;
        }}
        a {{
            color: #3498db;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
        .badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 3px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .badge-critical {{
            background-color: #e74c3c;
            color: white;
        }}
        .badge-high {{
            background-color: #e67e22;
            color: white;
        }}
        .badge-medium {{
            background-color: #f39c12;
            color: white;
        }}
        .badge-low {{
            background-color: #3498db;
            color: white;
        }}
        .no-vulnerabilities {{
            background-color: #27ae60;
            color: white;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
            font-weight: bold;
            font-size: 1.2em;
            margin: 20px 0;
        }}
    </style>
</head>
<body>
    <header>
        <h1>🛡️ Rapport PatchWatchdog</h1>
        <p>Analyse de sécurité des packages installés - {datetime.datetime.now().strftime("%d/%m/%Y à %H:%M:%S")}</p>
    </header>
    
    <div class="summary-box">
        <div class="summary-item">
            <div class="summary-number">{total_packages}</div>
            <div class="summary-label">Packages analysés</div>
        </div>
        <div class="summary-item">
            <div class="summary-number {'critical' if total_vulnerable > 0 else 'safe'}">{total_vulnerable}</div>
            <div class="summary-label">Vulnérabilités détectées</div>
        </div>
        <div class="summary-item">
            <div class="summary-number {'critical' if vulnerability_rate > 5 else 'warning' if vulnerability_rate > 0 else 'safe'}">{vulnerability_rate:.1f}%</div>
            <div class="summary-label">Taux de vulnérabilité</div>
        </div>
        <div class="summary-item">
            <div class="summary-number">{os_type.capitalize()}</div>
            <div class="summary-label">Système d'exploitation</div>
        </div>
    </div>
    
    <div class="container">
        <h2>Résumé de l'analyse</h2>
        <p>
            PatchWatchdog a analysé <strong>{total_packages} packages</strong> installés sur votre système <strong>{os_type.capitalize()}</strong>.
            L'analyse a été effectuée le {datetime.datetime.now().strftime("%d/%m/%Y à %H:%M:%S")}.
        </p>
        
        {f'<div class="no-vulnerabilities">✅ Aucune vulnérabilité critique détectée dans vos packages.</div>' if not vulnerable else ''}
    </div>
"""

    # Section des vulnérabilités détectées (conditionnelle)
    if vulnerable:
        vuln_section = """
    <div class="container">
        <h2>Vulnérabilités détectées</h2>
        <p>Les packages suivants présentent des vulnérabilités connues et devraient être mis à jour dès que possible :</p>
        
        <table>
            <thead>
                <tr>
                    <th>Package</th>
                    <th>Version</th>
                    <th>CVE</th>
                    <th>Sévérité</th>
                </tr>
            </thead>
            <tbody>
"""
        for vuln in vulnerable:
            vuln_section += f"""                <tr>
                    <td><strong>{vuln['package']}</strong></td>
                    <td>{vuln['version']}</td>
                    <td><a href="{vuln['cve_link']}" target="_blank">{vuln['cve']}</a></td>
                    <td><span class="badge badge-critical">{vuln['severity']}</span></td>
                </tr>
"""
        vuln_section += """            </tbody>
        </table>
    </div>
"""
        html_content += vuln_section

    # Section de tous les packages analysés
    packages_section = f"""
    <div class="container">
        <h2>Tous les packages analysés</h2>
        <p>Liste complète des {total_packages} packages analysés sur votre système :</p>
        
        <table>
            <thead>
                <tr>
                    <th>Package</th>
                    <th>Version</th>
                    <th>Statut</th>
                </tr>
            </thead>
            <tbody>
"""
    for pkg in packages:
        is_vulnerable = any(v['package'] == pkg['package'] and v['version'] == pkg['version'] for v in vulnerable)
        status_badge = '<span class="badge badge-critical">Vulnérable</span>' if is_vulnerable else '<span class="badge badge-low">Sécurisé</span>'
        packages_section += f"""                <tr>
                    <td><strong>{pkg['package']}</strong></td>
                    <td>{pkg['version']}</td>
                    <td>{status_badge}</td>
                </tr>
"""
    packages_section += """            </tbody>
        </table>
    </div>
"""
    html_content += packages_section

    # Section des recommandations et pied de page
    html_content += """
    <div class="container">
        <h2>Recommandations</h2>
        <p>Pour améliorer la sécurité de votre système, nous vous recommandons de :</p>
        <ul>
            <li>Mettre à jour régulièrement tous vos packages</li>
            <li>Porter une attention particulière aux packages marqués comme vulnérables</li>
            <li>Configurer des mises à jour automatiques lorsque c'est possible</li>
            <li>Exécuter PatchWatchdog régulièrement pour surveiller l'état de vos packages</li>
        </ul>
    </div>
    
    <div class="footer">
        <p>Rapport généré par <strong>PatchWatchdog</strong> | <a href="https://github.com/servais1983/PatchWatchdog" target="_blank">GitHub</a></p>
    </div>
</body>
</html>
"""
    
    # Écrire le contenu dans le fichier
    with open(report_filename, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return report_filename
