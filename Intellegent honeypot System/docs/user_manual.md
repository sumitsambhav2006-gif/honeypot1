# SOC Analyst & User Operational Manual

## 1. Logging Into the Platform
1. Open your browser and navigate to `http://localhost:5000/login`.
2. Enter your authorized Blue Team credentials:
   - **Administrator:** `admin` / `admin123`
   - **SOC Analyst:** `analyst` / `analyst123`

## 2. Navigating the Dashboard
- **SOC Overview (`/dashboard`):** Real-time KPI summary, 7-day attack volume graph, and targeted username distribution.
- **Live Attack Radar (`/live`):** Retro-cyber live scrolling terminal updating via Server-Sent Events (SSE). Use the **"Ingest Live Simulation"** button to inject immediate attack scenarios.
- **IP Intelligence (`/attackers`):** Complete catalog of threat actor IPs, geolocation metadata, ASN providers, and threat scores.
- **SSH Attack Events (`/attacks`):** Full searchable table of raw normalized events. Filter by event type (`cowrie.login.failed`, `cowrie.login.success`, etc.).
- **Attacker Sessions (`/sessions`):** Interactive session durations and command volume. Click **"Inspect Timeline"** on any session to replay the adversary's terminal command history.
- **Command Analysis (`/commands`):** Breakdown of shell commands by MITRE ATT&CK tactic (Reconnaissance, File Retrieval, Persistence).
- **Threat Scoring (`/threat-intel`):** Visual explanation of the mathematical risk scoring formula and severity tier distributions.
- **Security Alerts (`/alerts`):** Triage incoming intrusion alerts. Use the dropdown to transition alerts between `open`, `investigating`, and `resolved`.
- **Incident Reports (`/reports`):** One-click download of the **Executive Threat Briefing PDF** or raw CSV logs for Splunk/SIEM analysis.
- **Honeypot Nodes (`/settings`):** Monitor health check statuses across registered honeypot sensors.

