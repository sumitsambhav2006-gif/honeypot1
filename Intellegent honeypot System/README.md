# 🛡️ Intelligent Honeypot & Threat Intelligence Platform (IHTIP)
### *Next-Generation Deception Technology, Attacker Behavioral Forensics & SOC Platform*

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.15-00e5ff?logo=python)](https://python.org)
[![Framework](https://img.shields.io/badge/Framework-Flask%203.1-00ff9d?logo=flask)](https://flask.palletsprojects.com/)
[![Database](https://img.shields.io/badge/Database-MySQL%20%7C%20SQLAlchemy-3b82f6?logo=mysql)](https://mysql.com)
[![Honeypot](https://img.shields.io/badge/Honeypot-Cowrie%20SSH%2FTelnet-ef4444?logo=gnu-bash)](https://cowrie.readthedocs.io/)
[![Tests](https://img.shields.io/badge/Tests-21%2F21%20Passed%20(100%25)-00ff9d)](https://pytest.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

```
  ████████  ██   ██  ████████  ██  ██████  
     ██     ██   ██     ██     ██  ██   ██ 
     ██     ███████     ██     ██  ██████  
     ██     ██   ██     ██     ██  ██      
  ████████  ██   ██     ██     ██  ██      
  [ INTELLIGENT HONEYPOT & THREAT INTEL PLATFORM ]
```

## 📌 Project Overview
**IHTIP** is an enterprise-grade deception and threat intelligence platform designed for **SOC (Security Operations Center) / Blue Teams**. Unlike standard honeypot scripts that merely record attacking IPs, IHTIP captures the **entire interactive attacker session behavior** inside a simulated SSH/Telnet Linux environment, normalizes security events, classifies command behaviors via **MITRE ATT&CK**, computes cumulative **Risk Scores**, and visualizes actionable intelligence in a high-tech cybersecurity dashboard.

---

## 🏛️ 6-Layer Architecture

| Layer | Component | Functionality |
|---|---|---|
| **Layer 1** | **Attack Simulation** | Automated attacker traffic, SSH scans, credential stuffing bots. |
| **Layer 2** | **Honeypot Engine** | Cowrie medium/high-interaction SSH/Telnet server, fake shell & filesystem. |
| **Layer 3** | **Data Collection** | Log watcher, robust JSON parser, zero-trust password redaction (`[LEN:x_HASH:y]`). |
| **Layer 4** | **Analytics Engine** | Brute force velocity detector, command classifier, attacker profiling. |
| **Layer 5** | **Storage Layer** | 7 core normalized MySQL tables, indexed telemetry, forensic logs. |
| **Layer 6** | **SOC Dashboard** | Flask REST API, Server-Sent Events (SSE) live radar, Chart.js, PDF briefings. |

---

## 🧮 Mathematical Risk Scoring Model

Each adversary session is evaluated deterministically using weighted activity scores:

$$\mathbf{RiskScore} = \min\left(100, \sum \mathbf{ActivityScores}\right)$$

### Activity Weights Matrix:
- **Failed Login Attempt:** `+5 pts`
- **Username Enumeration (Multiple distinct accounts):** `+10 pts`
- **Reconnaissance Commands (`whoami`, `id`, `uname`, `cpuinfo`):** `+15 pts`
- **Suspicious File Retrieval (`wget`, `curl`, `ftpget`):** `+20 pts`
- **Persistence Attempt (`crontab`, `authorized_keys`):** `+20 pts`
- **Privilege Escalation Attempt (`sudo -l`, `/etc/shadow`):** `+20 pts`
- **Destructive Command Attempt (`rm -rf`, `mkfs`, `dd`):** `+25 pts`
- **Interactive Reverse Shell (`/dev/tcp/`, `nc -e`, `pty.spawn`):** `+25 pts`

### Operational Severity Bands:
- `0 – 29` : **LOW** (Automated scanning)
- `30 – 59`: **MEDIUM** (Targeted reconnaissance)
- `60 – 79`: **HIGH** (Active credential compromise)
- `80 – 100`: **CRITICAL** (Payload ingress / Privilege escalation)

---

## 🖥️ SOC Dashboard Navigation & Features

- **Executive Overview (`/dashboard`):** Real-time KPIs, 7-day attack frequency chart, top attacked usernames.
- **Live Attack Radar (`/live`):** Retro-cyber live scrolling terminal updating via Server-Sent Events (SSE).
- **IP Intelligence (`/attackers`):** Attacker profiles with geolocation coordinates, ISP, ASN, and reputation meters.
- **SSH Attack Events (`/attacks`):** Searchable normalized logs with zero-trust credential masking.
- **Attacker Sessions (`/sessions`):** Interactive session durations, command counts, and **Forensic Timeline Replay**.
- **Command Analysis (`/commands`):** MITRE ATT&CK mapped shell executions with risk points.
- **Threat Scoring (`/threat-intel`):** Mathematical model breakdown and global geographic attack distribution.
- **Security Alerts (`/alerts`):** Incident queue with one-click status transitions (`open`, `investigating`, `resolved`).
- **Reports & Export (`/reports`):** One-click **Executive PDF Briefing** download and CSV exports for SIEMs.
- **Honeypot Nodes (`/settings`):** Health check and status monitoring across distributed sensors.

---

## ⚡ Quick Start Guide (Windows & Linux)

### 1. Installation
```bash
# Clone the repository
git clone <repository-url>
cd "Intelligent Honeypot System"

# Install dependencies
pip install -r requirements.txt
```

### 2. Initialize Database & Run Automated Tests
```bash
# Initialize and seed database with rich sample SOC data
python run.py seed

# Execute 21 automated tests (Parsers, Analytics, API, Risk Engine, Real SSH)
python run.py test
```

### 3. Launch the SOC Platform
```bash
# Starts both the SOC Dashboard (Port 5000) and Real-Time Event Collector
python run.py all
```
Open **`http://localhost:5000`** in your browser.
- **Admin Login:** `admin` / `admin123`
- **Analyst Login:** `analyst` / `analyst123`

### 4. Ingest Live Simulated Attacks
In a second terminal window, trigger simulated Cowrie SSH attack scenarios:
```bash
# Single multi-stage attack session:
python run.py simulate --count 1

# Continuous automated attacks every 8 seconds:
python run.py simulate --count 0 --interval 8
```
Watch the **Live Radar Terminal** and **Executive Dashboard** update live!

---

## 📁 Repository Directory Structure

```text
intelligent-honeypot-platform/
├── README.md                           # Master Project Documentation
├── requirements.txt                     # Python Dependencies
├── .env.example                         # Environment Configuration
├── docker-compose.yml                   # Docker Stack (MySQL + Cowrie + IHTIP)
├── Dockerfile                           # Container Definition
├── run.py                               # Master CLI Entry Point
│
├── config/                              # Configuration Management
│   ├── settings.py                      # Environment & Path Configuration
│   ├── database.py                      # SQLAlchemy Engine & Pool Config
│   ├── logging_config.py                # Rotating File Handlers & Logging
│   └── security_config.py               # Redaction & Security Headers
│
├── honeypot/                            # Honeypot Engine (SSH Server & Simulators)
│   ├── ssh_server.py                    # Built-in Real Interactive SSH Honeypot (Port 2222)
│   ├── cowrie/                          # Cowrie Configuration & Deployment Guide
│   │   ├── cowrie.cfg                   # Production Cowrie Configuration
│   │   └── deployment.md                # Hardening & Setup Instructions
│   ├── deployment/                      # Automation Shell Scripts
│   │   ├── install.sh                   # Native Ubuntu Cowrie Installer
│   │   ├── start.sh                     # Service Starter
│   │   └── stop.sh                      # Service Stopper
│   └── simulator/                       # Attack Simulators
│       ├── attack_simulator.py          # Synthetic Cowrie Log Generator
│       └── real_attack_demo.py          # Real TCP/SSH Multi-Stage Attack Demo
│
├── collector/                           # Ingestion & Log Processing Engine
│   ├── log_watcher.py                   # Continuous Log Tailer (tail -f)
│   ├── event_collector.py               # Database Sync & Entity Resolution
│   ├── json_parser.py                   # Resilient JSON Parser
│   └── event_normalizer.py              # Canonical Event Normalization & Redaction
│
├── analytics/                           # Analytics & Behavioral Classification
│   ├── attack_detector.py               # Primary Detection & Alert Coordinator
│   ├── brute_force_detector.py          # Authentication Velocity & Enumeration
│   ├── command_analyzer.py              # MITRE ATT&CK Command Categorization
│   └── risk_engine.py                   # Deterministic Scoring: min(100, sum)
│
├── threat_intelligence/                 # Geolocation & IP Reputation
│   ├── geolocation.py                   # IP-API & Offline Subnet Geographic Telemetry
│   ├── reputation_checker.py            # AbuseIPDB / Heuristic Scoring
│   ├── ip_enrichment.py                 # Unified IP Profile Enrichment
│   └── intelligence_service.py          # Singleton Threat Intel Service
│
├── backend/                             # Flask REST API & Web Application
│   ├── app.py                           # App Factory & Middleware
│   ├── models/                          # 7 Normalized Relational Models
│   │   ├── user.py                      # SOC Analyst Accounts
│   │   ├── attacker.py                  # Threat Actor IPs & Geolocation
│   │   ├── honeypot.py                  # Sensor Nodes
│   │   ├── attack_event.py              # Normalized Security Events
│   │   ├── session.py                   # Attacker Sessions
│   │   ├── command.py                   # Captured Shell Commands
│   │   └── alert.py                     # Security Alerts
│   ├── routes/                          # REST API & Page Controllers
│   │   ├── auth_routes.py               # Authentication & Session Check
│   │   ├── dashboard_routes.py          # Dashboard Stats, SSE Live Stream & /api/simulate
│   │   ├── attack_routes.py             # Attack Queries & Detail Views
│   │   ├── attacker_routes.py           # Attacker Profiles & Deep Dive
│   │   ├── session_routes.py            # Session Replay & Forensics
│   │   ├── analytics_routes.py          # Analytics Breakdown & Alert Triage
│   │   └── report_routes.py             # CSV & PDF Report Export
│   ├── services/                        # Business Logic Layer
│   │   ├── attack_service.py            # High-performance Aggregations
│   │   ├── alert_service.py             # Alert Lifecycle Operations
│   │   └── report_service.py            # PDF & CSV Generation Engine
│   └── middleware/                      # Access Control
│       └── authentication.py            # Login Enforcer
│
├── frontend/                            # SOC Blue Team User Interface
│   ├── static/                          # Static Assets
│   │   ├── css/
│   │   │   ├── style.css                # Base Cyber Theme & Design System
│   │   │   ├── dashboard.css            # Cyber Cards, Terminals & Timelines
│   │   │   └── responsive.css           # Mobile & Tablet Adaptations
│   │   └── js/
│   │       ├── charts.js                # Chart.js Visualizations
│   │       ├── dashboard.js             # KPI Polling & Event Rendering
│   │       ├── live_monitor.js          # SSE Stream & Radar Terminal
│   │       └── analytics.js             # Filter & Alert Triage Controller
│   └── templates/                       # Jinja2 Cyber Templates
│       ├── base.html                    # Layout Shell & Navigation
│       ├── login.html                   # High-tech Cyber Auth Portal
│       ├── dashboard.html               # Executive Overview
│       ├── live_monitor.html            # Real-time Radar Terminal
│       ├── attackers.html               # Attacker IP Intelligence
│       ├── attack_details.html          # Normalized Attack Logs
│       ├── sessions.html                # Session Replay & Timeline
│       ├── command_analysis.html        # MITRE ATT&CK Shell Analysis
│       ├── threat_intelligence.html     # Risk Model & Geo Distribution
│       ├── alerts.html                  # Alert Triage Console
│       ├── reports.html                 # Executive PDF & CSV Exports
│       └── settings.html                # Sensor Nodes & System Status
│
├── database/                            # Database Schemas & Seeding
│   ├── schema.sql                       # Production MySQL 8.0 DDL
│   └── seed.py                          # Programmatic High-Fidelity Seeder
│
├── tests/                               # Automated Test Suite (21 Tests)
│   ├── test_collector.py                # Parser & Normalizer Tests
│   ├── test_analytics.py                # Command & Brute Force Tests
│   ├── test_risk_engine.py              # Mathematical Scoring Tests
│   ├── test_api.py                      # REST Endpoint Tests
│   ├── test_database.py                 # Relational Integrity Tests
│   └── test_honeypot_ssh.py             # Real SSH Honeypot & Shell Tests
│
├── deployment/                          # Production Infrastructure
│   ├── nginx/nginx.conf                 # Reverse Proxy & SSE Buffering Config
│   ├── systemd/                         # Systemd Daemon Unit Files
│   ├── backup.sh                        # Automated Database & Log Backup
│   └── production.md                    # Production Hardening Checklist
│
└── docs/                                # Technical Documentation
    ├── architecture.md                  # 6-Layer Architecture & DFDs
    ├── database_design.md               # ER Diagrams & Schema Rationale
    ├── api_documentation.md             # REST API Specifications
    ├── installation_guide.md            # Ubuntu & Windows Deployment
    ├── testing_report.md                # Test Execution & Security Results
    └── user_manual.md                   # SOC Analyst User Guide
```

---

## 🔒 Production Security Hardening

- **Credential Redaction:** Passwords captured in honeypots are never stored plaintext; they are anonymized as `[LEN:length_HASH:salt_sha256]` to prevent sensitive credential exposure.
- **Sandbox Host Safety:** Attacker commands captured inside the honeypot are parsed as string telemetry only; **they are NEVER executed on the host system**.
- **Network Isolation:** Honeypots run in an isolated VLAN / container with egress filtering to prevent adversary pivoting or outbound DDoS abuse.
- **Security Headers:** All HTTP responses include `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, and strict `Content-Security-Policy`.

---

## 🎓 College Viva / Project Presentation Tips

1. **Demonstrate End-to-End Workflow:**
   - Open the **Live Attack Radar** on `/live`.
   - Run `python run.py simulate --count 1` in PowerShell.
   - Point out how Cowrie simulates the SSH connection, the collector tails the log, extracts username enumeration, parses the command (`whoami`, `curl -O malware`), and triggers a high-severity alert instantly.
2. **Highlight the MITRE ATT&CK Integration:**
   - Navigate to `/commands` and show how attacker commands are classified into Tactic IDs like **T1105 (Ingress Tool Transfer)** and **T1053 (Persistence)**.
3. **Showcase Executive PDF Export:**
   - Go to `/reports` and download the **Executive Threat Briefing PDF**, showing professional CISO-level reporting capability.
4. **Explain Risk Scoring:**
   - Explain how the mathematical formula $RiskScore = \min(100, \sum ActivityScores)$ bounds score predictability and allows rule-based triage without false positives.

---

## ⚖️ License
Released under the **MIT License**. Created for cybersecurity education, Blue Team defense research, and threat intelligence operations.

