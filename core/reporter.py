import os
import html
import datetime
from core.utils import format_cve_details, cvss_to_severity


def _esc(value):
    """Échappe les caractères HTML pour prévenir toute injection (XSS)."""
    return html.escape(str(value), quote=True)


def _severity_badge_class(severity):
    """Return the CSS class for a given severity label."""
    mapping = {
        "CRITICAL": "badge-critical",
        "HIGH":     "badge-high",
        "MEDIUM":   "badge-medium",
        "LOW":      "badge-low",
    }
    return mapping.get(severity.upper() if severity else "", "badge-low")


CSS = """
        body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;line-height:1.6;color:#333;max-width:1200px;margin:0 auto;padding:20px;background:#f8f9fa}
        header{background:#2c3e50;color:#fff;padding:20px;border-radius:5px;margin-bottom:20px;box-shadow:0 2px 5px rgba(0,0,0,.1)}
        h1,h2,h3{color:#2c3e50;margin-top:30px}
        header h1{color:#fff;margin-top:0}
        .summary-box{background:#fff;border-radius:5px;padding:20px;margin-bottom:20px;box-shadow:0 2px 5px rgba(0,0,0,.1);display:flex;justify-content:space-between;flex-wrap:wrap}
        .summary-item{text-align:center;padding:15px;flex:1;min-width:200px}
        .summary-number{font-size:2.5em;font-weight:700;margin-bottom:10px}
        .summary-label{font-size:1.1em;color:#555}
        .critical{color:#e74c3c}.safe{color:#27ae60}.warning{color:#f39c12}
        table{width:100%;border-collapse:collapse;margin:20px 0;background:#fff;box-shadow:0 2px 5px rgba(0,0,0,.1);border-radius:5px;overflow:hidden}
        th,td{padding:12px 15px;text-align:left;border-bottom:1px solid #ddd}
        th{background:#34495e;color:#fff;font-weight:600}
        tr:hover{background:#f5f5f5}
        .container{background:#fff;border-radius:5px;padding:20px;margin-bottom:20px;box-shadow:0 2px 5px rgba(0,0,0,.1)}
        .footer{text-align:center;margin-top:30px;padding:20px;color:#7f8c8d;font-size:.9em}
        a{color:#3498db;text-decoration:none}a:hover{text-decoration:underline}
        .badge{display:inline-block;padding:5px 10px;border-radius:3px;font-size:.8em;font-weight:700;text-transform:uppercase}
        .badge-critical{background:#e74c3c;color:#fff}
        .badge-high{background:#e67e22;color:#fff}
        .badge-medium{background:#f39c12;color:#fff}
        .badge-low{background:#3498db;color:#fff}
        .no-vulnerabilities{background:#27ae60;color:#fff;padding:15px;border-radius:5px;text-align:center;font-weight:700;font-size:1.2em;margin:20px 0}
"""


def generate_html_report(packages, vulnerable, os_type):
    """
    Generate a secure HTML report (protection XSS, sévérité réelle).

    Args:
        packages (list): Liste des packages scannés.
        vulnerable (list): Liste des vulnérabilités (dict avec clés package, version, cve, cvss, severity).
        os_type (str): 'linux' ou 'windows'.

    Returns:
        str: Chemin absolu du rapport HTML généré.
    """
    # Enrichir les vulnérabilités avec les liens NVD et la sévérité réelle
    for vuln in vulnerable:
        vuln.setdefault("cve_link", format_cve_details(vuln["cve"]))
        # Ne pas écraser la sévérité fournie par le scanner
        if "severity" not in vuln or vuln["severity"] == "UNKNOWN":
            cvss = vuln.get("cvss")
            vuln["severity"] = cvss_to_severity(cvss) if cvss is not None else "UNKNOWN"

    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"reports/patchwatchdog_report_{timestamp}.html"

    total_packages = len(packages)
    total_vulnerable = len(vulnerable)
    vuln_rate = (total_vulnerable / total_packages * 100) if total_packages > 0 else 0
    now_str = datetime.datetime.now().strftime("%d/%m/%Y à %H:%M:%S")

    vuln_class = "critical" if total_vulnerable > 0 else "safe"
    rate_class = "critical" if vuln_rate > 5 else ("warning" if vuln_rate > 0 else "safe")

    # ── En-tête + résumé ─────────────────────────────────────────────────────
    html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport PatchWatchdog &mdash; {_esc(timestamp)}</title>
    <style>{CSS}</style>
</head>
<body>
<header>
    <h1>PatchWatchdog Report</h1>
    <p>Installed package security scan &mdash; {_esc(now_str)}</p>
</header>

<div class="summary-box">
    <div class="summary-item">
        <div class="summary-number">{total_packages}</div>
        <div class="summary-label">Packages scanned</div>
    </div>
    <div class="summary-item">
        <div class="summary-number {vuln_class}">{total_vulnerable}</div>
        <div class="summary-label">Vulnerabilities detected</div>
    </div>
    <div class="summary-item">
        <div class="summary-number {rate_class}">{vuln_rate:.1f}%</div>
        <div class="summary-label">Vulnerability rate</div>
    </div>
    <div class="summary-item">
        <div class="summary-number">{_esc(os_type.capitalize())}</div>
        <div class="summary-label">Operating system</div>
    </div>
</div>

<div class="container">
    <h2>Scan summary</h2>
    <p>PatchWatchdog scanned <strong>{total_packages} packages</strong>
    on your <strong>{_esc(os_type.capitalize())}</strong>.
    Scan completed at {_esc(now_str)}.</p>
    {"<div class=\"no-vulnerabilities\">No vulnerabilities detected in your packages.</div>" if not vulnerable else ""}
</div>
"""

    # ── Section vulnérabilités ────────────────────────────────────────────────
    if vulnerable:
        html_out += """
<div class="container">
    <h2>Vulnerabilities detected</h2>
    <p>These packages have known vulnerabilities and should be updated immediately.</p>
    <table>
        <thead>
            <tr>
                <th>Package</th><th>Version</th><th>CVE</th>
                <th>CVSS</th><th>Severity</th>
            </tr>
        </thead>
        <tbody>
"""
        for v in vulnerable:
            badge_class = _severity_badge_class(v["severity"])
            cvss_display = f"{v['cvss']:.1f}" if v.get("cvss") is not None else "N/A"
            html_out += (
                f"            <tr>"
                f"<td><strong>{_esc(v['package'])}</strong></td>"
                f"<td>{_esc(v['version'])}</td>"
                f"<td><a href=\"{_esc(v['cve_link'])}\" target=\"_blank\" rel=\"noopener noreferrer\">"
                f"{_esc(v['cve'])}</a></td>"
                f"<td>{_esc(cvss_display)}</td>"
                f"<td><span class=\"badge {badge_class}\">{_esc(v['severity'])}</span></td>"
                f"</tr>\n"
            )
        html_out += "        </tbody>\n    </table>\n</div>\n"

    # ── Tous les packages ─────────────────────────────────────────────────────
    vuln_keys = {(v["package"], v["version"]) for v in vulnerable}
    html_out += f"""
<div class="container">
    <h2>All scanned packages ({total_packages})</h2>
    <table>
        <thead>
            <tr><th>Package</th><th>Version</th><th>Type</th><th>Statut</th></tr>
        </thead>
        <tbody>
"""
    for pkg in packages:
        is_vuln = (pkg["package"], pkg["version"]) in vuln_keys
        badge = ('<span class="badge badge-critical">Vulnerable</span>'
                 if is_vuln else
                 '<span class="badge badge-low">Safe</span>')
        pkg_type = _esc(pkg.get("type", "system"))
        html_out += (
            f"            <tr>"
            f"<td><strong>{_esc(pkg['package'])}</strong></td>"
            f"<td>{_esc(pkg['version'])}</td>"
            f"<td>{pkg_type}</td>"
            f"<td>{badge}</td>"
            f"</tr>\n"
        )
    html_out += "        </tbody>\n    </table>\n</div>\n"

    # ── Recommandations + pied de page ────────────────────────────────────────
    html_out += """
<div class="container">
    <h2>Recommandations</h2>
    <ul>
        <li>Keep all packages regularly updated.</li>
        <li>Prioritize packages flagged as vulnerable.</li>
        <li>Configure automatic updates where possible.</li>
        <li>Run PatchWatchdog regularly to monitor your package state.</li>
        <li>D&#233;finir <code>NVD_API_KEY</code> (free) to speed up system package scans 10x.</li>
    </ul>
</div>

<div class="footer">
    <p>Report generated by <strong>PatchWatchdog</strong> &mdash;
    <a href="https://github.com/servais1983/PatchWatchdog" target="_blank" rel="noopener noreferrer">GitHub</a></p>
</div>
</body>
</html>
"""

    with open(report_filename, "w", encoding="utf-8") as f:
        f.write(html_out)

    return report_filename

    """
    Generate a secure HTML report complet avec les résultats du scan.
    
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
<html lang="en">
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
