<p align="center">
  <img src="patchwatchdog.png" alt="PatchWatchdog" width="180"/>
</p>

<h1 align="center">PatchWatchdog</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg?style=flat-square&logo=python&logoColor=white" alt="Python 3.8+"/>
  <img src="https://img.shields.io/badge/OS-Linux%20%7C%20Windows-informational.svg?style=flat-square" alt="Linux & Windows"/>
  <img src="https://img.shields.io/badge/CVE%20Engine-OSV.dev%20%7C%20NVD%20%7C%20Vulners-critical.svg?style=flat-square" alt="CVE Engine"/>
  <img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square" alt="MIT License"/>
</p>

<p align="center">
  <strong>Patch state monitoring and CVE detection for Linux and Windows systems.</strong>
</p>

---

## Table of Contents

- [Description](#description)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [HTML Reports](#html-reports)
- [Project Structure](#project-structure)
- [Integrations](#integrations)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Description

**PatchWatchdog** is a command-line tool that inventories installed packages, checks them against public CVE databases, and alerts you when vulnerable versions are found. It produces a timestamped HTML security report on every run and can automatically apply critical updates.

**CVE scanning engines:**

| Scope | Engine | Authentication |
|---|---|---|
| Python (pip) packages | [OSV.dev](https://osv.dev/) API | None â€” free |
| System packages | [NVD API v2](https://nvd.nist.gov/developers) | None free (NVD_API_KEY for 10x speed) |
| System packages (enhanced) | [Vulners](https://vulners.com/) API | `VULNERS_API_KEY` required (paid plan) |

> **Note:** This tool complements a patch management strategy; it does not replace it.

---

## Features

- Inventory of installed packages (apt + pip on Linux; Windows registry + pip on Windows)
- Automatic CVE detection via OSV.dev (pip, free) and NVD API v2 (system, free) or Vulners (optional)
- Real CVSS scores and severity levels (Critical / High / Medium / Low) in every report
- Configurable alerts: Slack Incoming Webhook, GitHub Issues
- **Automatic installation of vulnerable packages** with `--auto-update` (pip + system)
- Windows Update check and critical patch application
- HTML reports with XSS protection (all output HTML-escaped)
- `.env` file support via `python-dotenv`
- Exit codes suitable for CI/CD pipelines (`0` = clean, `1` = vulnerabilities, `2` = error)

---

## Requirements

- Python 3.8 or later
- pip

All Python dependencies are listed in `requirements.txt`:

```
requests>=2.31.0
python-dotenv>=1.0.0
```

---

## Installation

### Linux

```bash
git clone https://github.com/servais1983/PatchWatchdog.git
cd PatchWatchdog
cp .env.example .env          # then edit .env with your credentials
chmod +x install.sh
./install.sh
```

### Windows

```powershell
git clone https://github.com/servais1983/PatchWatchdog.git
cd PatchWatchdog
copy .env.example .env        # then edit .env with your credentials
.\install.bat
```

> **Windows requirement:** Python must be installed and added to the system PATH.  
> Download from [python.org](https://www.python.org/downloads/) and check **"Add Python to PATH"** during setup.

---

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```ini
# Slack notification (Incoming Webhook URL)
SLACK_WEBHOOK=https://hooks.slack.com/services/XXXXX/XXXXX/XXXXX

# GitHub Issues notification
GITHUB_TOKEN=ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
GITHUB_REPO=your_user/your_repository

# NVD API key — free, speeds up system package scanning x10
# Get yours in 2 min: https://nvd.nist.gov/developers/request-an-api-key
# Without key: ~6s/package | With key: ~0.6s/package
NVD_API_KEY=

# Vulners API key — optional, paid plan, replaces NVD for system packages
VULNERS_API_KEY=
```

All variables are optional. Features that depend on missing variables are gracefully disabled with an informational message.

---

## Usage

### Basic scan

```bash
# Linux
python3 patchwatchdog.py --os linux

# Windows
python patchwatchdog.py --os windows
```

### Scan with notification

```bash
# Send alert to Slack
python3 patchwatchdog.py --os linux --notify slack

# Open a GitHub Issue
python patchwatchdog.py --os windows --notify github
```

### Check and apply system updates

```bash
# Check available system updates (no installation)
python3 patchwatchdog.py --os linux --check-updates
python  patchwatchdog.py --os windows --check-updates

# Check CVEs and apply critical updates automatically
python3 patchwatchdog.py --os linux  --auto-update
python  patchwatchdog.py --os windows --auto-update
```

`--auto-update` does two things:
1. Applies **critical system patches** (Windows Update / apt security).
2. Upgrades **vulnerable pip packages** to their latest version.

> **Privilege note:** Applying system updates requires administrator rights.  
> On Linux, prefix the command with `sudo`. On Windows, run the terminal as Administrator.

### All options

| Flag | Description |
|---|---|
| `--os {linux,windows}` | Target operating system (required) |
| `--notify {slack,github}` | Send an alert when vulnerabilities are found |
| `--check-updates` | Query the OS for available system updates |
| `--auto-update` | Apply critical system updates and upgrade vulnerable pip packages |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No vulnerabilities found |
| `1` | One or more vulnerabilities detected |
| `2` | Runtime error (missing packages, permission denied, etc.) |

---

## HTML Reports

A detailed HTML report is generated automatically on every run and saved to the `reports/` directory with a unique timestamp:

```
reports/patchwatchdog_report_20260227_203629.html
```

Each report includes:

- Summary statistics (packages scanned, vulnerabilities found, vulnerability rate)
- Vulnerability table with CVE identifier, CVSS score, severity badge, and NVD link
- Full package inventory with status (Secure / Vulnerable) and package type (pip / system)
- Security recommendations

---

## Project Structure

```
PatchWatchdog/
â”œâ”€â”€ core/
â”‚   â”œâ”€â”€ __init__.py        # Package marker
â”‚   â”œâ”€â”€ inventory.py       # Package collection (apt, pip, Windows registry)
â”‚   â”œâ”€â”€ scanner.py         # CVE lookup via OSV.dev, NVD API v2, and Vulners
â”‚   â”œâ”€â”€ notifier.py        # Slack and GitHub Issues alerts
â”‚   â”œâ”€â”€ reporter.py        # HTML report generation (XSS-safe)
â”‚   â”œâ”€â”€ updater.py         # OS update check/apply, pip upgrade
â”‚   â””â”€â”€ utils.py           # Shared utilities (CVSS scoring, NVD links)
â”œâ”€â”€ patchwatchdog.py       # CLI entry point
â”œâ”€â”€ requirements.txt       # Python dependencies
â”œâ”€â”€ install.sh             # Linux installer
â”œâ”€â”€ install.bat            # Windows installer
â”œâ”€â”€ .env.example           # Environment variable template
â””â”€â”€ README.md              # This file
```

---

## Integrations

### Slack

1. Create a Slack App at [api.slack.com](https://api.slack.com/apps).
2. Enable **Incoming Webhooks** and add a webhook to a channel.
3. Copy the webhook URL into `SLACK_WEBHOOK` in your `.env`.

### GitHub Issues

1. Generate a personal access token with the `repo` scope at  
   **Settings > Developer settings > Personal access tokens**.
2. Set `GITHUB_TOKEN` and `GITHUB_REPO` (format: `owner/repository`) in your `.env`.

### Vulners (system packages)

1. Create an account at [vulners.com](https://vulners.com/).
2. Subscribe to an API plan and copy your key into `VULNERS_API_KEY` in your `.env`.
3. Without this key, only pip packages are analysed (via the free OSV.dev API).

---

## Roadmap

- [ ] OSQuery integration for more accurate system package discovery
- [ ] Wazuh integration for centralised security management
- [ ] Web dashboard with FastAPI
- [ ] Redis-backed historical vulnerability tracking
- [ ] Differential alerts (report only new vulnerabilities since last run)
- [ ] NVD API v2 integration for richer CVE metadata

---

## Contributing

Contributions are welcome. Please open an issue to discuss your proposal before submitting a pull request. Follow PEP 8 for Python code style.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Developed for secure and up-to-date environments.
</p>

