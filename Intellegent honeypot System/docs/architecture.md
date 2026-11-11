# System Architecture & Technical Specification

## 1. Executive Summary
The **Intelligent Honeypot & Threat Intelligence Platform (IHTIP)** is an enterprise-tier cybersecurity monitoring and deception technology ecosystem. The platform attracts unauthorized intrusion attempts via simulated SSH environments, captures full interactive session telemetry, evaluates attacker behaviors using automated heuristics and MITRE ATT&CK mappings, computes cumulative risk scores, and surfaces actionable intelligence through a Security Operations Center (SOC) dashboard.

## 2. Six-Layer Architecture Model

```
┌────────────────────────────────────────────────────────┐
│              LAYER 1: ATTACK SIMULATION                │
│ Unauthorized Logins · SSH Scans · Credential Stuffing  │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│              LAYER 2: HONEYPOT ENGINE                  │
│ Cowrie SSH/Telnet Daemon · Simulated Shell & FS        │
└───────────────────────────┬────────────────────────────┘
                            │ Raw JSON Logs
┌───────────────────────────▼────────────────────────────┐
│              LAYER 3: DATA COLLECTION                  │
│ Log Watcher · JSON Parser · Zero-Trust Redaction       │
└───────────────────────────┬────────────────────────────┘
                            │ Normalized Security Events
┌───────────────────────────▼────────────────────────────┐
│              LAYER 4: ANALYTICS ENGINE                 │
│ Brute Force · Recon Classification · Risk Engine       │
└───────────────────────────┬────────────────────────────┘
                            │ Structured Records & Alerts
┌───────────────────────────▼────────────────────────────┐
│              LAYER 5: STORAGE LAYER                    │
│ MySQL / SQLAlchemy · 7 Core Tables · Indexed Telemetry │
└───────────────────────────┬────────────────────────────┘
                            │ REST API / SSE Streams
┌───────────────────────────▼────────────────────────────┐
│              LAYER 6: SOC DASHBOARD                    │
│ Flask REST Backend · Cyber Radar UI · Incident Briefs  │
└────────────────────────────────────────────────────────┘
```

## 3. Data Flow Diagram (DFD)

### DFD Level 0 (Context Level)
```
  [ Attacker / Adversary ]
             │
             │ (1) SSH Connection & Login Attempts (Port 2222)
             ▼
┌─────────────────────────┐
│     IHTIP PLATFORM      │ <───── (2) Telemetry Stream (JSON Logs)
│ (Honeypot + Analytics)  │
└────────────┬────────────┘
             │
             │ (3) Actionable Alerts, Metrics & Forensics
             ▼
  [ SOC Security Analyst ]
```

### DFD Level 1 (Process Decomposition)
1. **P1 (Capture):** Cowrie daemon accepts TCP socket, emulates OpenSSH banner, records attempts.
2. **P2 (Normalize):** `LogWatcher` reads `cowrie.json`, masks passwords (`[LEN:x_HASH:y]`), enforces UTC timestamps.
3. **P3 (Enrich):** `IntelligenceService` queries geolocation and IP reputation.
4. **P4 (Analyze & Score):** `AttackDetector` classifies commands into MITRE ATT&CK categories and computes risk score:
   $$RiskScore = \min(100, \sum ActivityScores)$$
5. **P5 (Alert & Store):** Writes normalized events and alerts to MySQL.
6. **P6 (Visualize):** Streams live events to browser via Server-Sent Events (SSE) and serves interactive Chart.js dashboards.

