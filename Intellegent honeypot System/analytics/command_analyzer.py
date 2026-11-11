import re
from typing import Dict, Any

# Command classification patterns with Risk Points & MITRE ATT&CK Mapping
COMMAND_RULES = [
    # Destructive Actions
    {
        "category": "Destructive Attempt",
        "pattern": r"(rm\s+-rf|mkfs|dd\s+if=/dev/(zero|urandom)|:(){:|:&};:)",
        "risk_points": 25,
        "mitre_id": "T1485",
        "mitre_tactic": "Impact"
    },
    # Reverse Shells / Defense Evasion
    {
        "category": "Reverse Shell Attempt",
        "pattern": r"(/dev/tcp/|nc\s+-e|pty\.spawn|bash\s+-i|mkfifo\s+/tmp/)",
        "risk_points": 25,
        "mitre_id": "T1059.004",
        "mitre_tactic": "Execution"
    },
    # Suspicious File Retrieval / Malware Ingress
    {
        "category": "Suspicious File Retrieval",
        "pattern": r"\b(wget|curl|ftpget|tftp|busybox\s+wget|fetch)\b",
        "risk_points": 20,
        "mitre_id": "T1105",
        "mitre_tactic": "Ingress Tool Transfer"
    },
    # Persistence & Scheduled Tasks
    {
        "category": "Persistence Attempt",
        "pattern": r"\b(crontab|/etc/cron|authorized_keys|systemctl\s+enable|chkconfig|rc\.local)\b",
        "risk_points": 20,
        "mitre_id": "T1053",
        "mitre_tactic": "Persistence"
    },
    # Privilege Escalation & Shadow access
    {
        "category": "Privilege Escalation Attempt",
        "pattern": r"\b(sudo\s+-l|/etc/shadow|chmod\s+(\+x|777|4755)|chown\s+root)\b",
        "risk_points": 20,
        "mitre_id": "T1068",
        "mitre_tactic": "Privilege Escalation"
    },
    # System & Hardware Discovery
    {
        "category": "System Reconnaissance",
        "pattern": r"\b(whoami|id|cat\s+/proc/cpuinfo|cat\s+/proc/meminfo|lscpu|hostname|uptime)\b",
        "risk_points": 15,
        "mitre_id": "T1082",
        "mitre_tactic": "Discovery"
    },
    # OS & Kernel Discovery
    {
        "category": "OS Discovery",
        "pattern": r"\b(uname|cat\s+/etc/issue|cat\s+/etc/\*release|lsb_release)\b",
        "risk_points": 10,
        "mitre_id": "T1082",
        "mitre_tactic": "Discovery"
    },
    # Network Discovery
    {
        "category": "Network Discovery",
        "pattern": r"\b(ifconfig|ip\s+a|netstat|ss\s+-t|arp\s+-a|route\s+-n|ping\s+-c)\b",
        "risk_points": 15,
        "mitre_id": "T1016",
        "mitre_tactic": "Discovery"
    },
    # Credential Discovery
    {
        "category": "Credential Discovery",
        "pattern": r"\b(cat\s+/etc/passwd|\.bash_history|\.ssh/id_rsa)\b",
        "risk_points": 20,
        "mitre_id": "T1081",
        "mitre_tactic": "Credential Access"
    },
    # Directory & File Exploration
    {
        "category": "Directory Exploration",
        "pattern": r"\b(ls|pwd|dir|find\s+/|cd\s+/tmp|cd\s+/var)\b",
        "risk_points": 10,
        "mitre_id": "T1083",
        "mitre_tactic": "Discovery"
    }
]

class CommandAnalyzer:
    """Analyzes and categorizes raw shell commands, assigning risk points and MITRE ATT&CK tags."""

    @staticmethod
    def analyze(command_str: str) -> Dict[str, Any]:
        """
        Parses command string and returns classification, risk score, and MITRE metadata.
        """
        if not command_str:
            return {
                "category": "General",
                "risk_points": 0,
                "mitre_id": "N/A",
                "mitre_tactic": "None"
            }

        cmd_lower = command_str.lower().strip()

        for rule in COMMAND_RULES:
            if re.search(rule["pattern"], cmd_lower, re.IGNORECASE):
                return {
                    "category": rule["category"],
                    "risk_points": rule["risk_points"],
                    "mitre_id": rule["mitre_id"],
                    "mitre_tactic": rule["mitre_tactic"]
                }

        # Default fallback for unrecognized shell activity
        return {
            "category": "General Execution",
            "risk_points": 5,
            "mitre_id": "T1059",
            "mitre_tactic": "Execution"
        }
