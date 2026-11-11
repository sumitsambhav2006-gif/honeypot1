from typing import Dict, Any
from analytics.command_analyzer import CommandAnalyzer
from analytics.brute_force_detector import BruteForceDetector
from analytics.risk_engine import RiskEngine

class AttackDetector:
    """Central analytics coordinator detecting intrusions, calculating risk, and generating alerts."""

    def __init__(self):
        self.brute_detector = BruteForceDetector()
        self.cmd_analyzer = CommandAnalyzer()

    def process_event(self, normalized_event: Dict[str, Any], session_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Evaluates a normalized event in context, computing risk points and generating alert triggers.
        """
        event_type = normalized_event.get("event_type", "")
        src_ip = normalized_event.get("source_ip", "")
        username = normalized_event.get("username", "")
        cmd_text = normalized_event.get("command", "")
        timestamp = normalized_event.get("timestamp")

        result = {
            "trigger_alert": False,
            "alert_data": None,
            "command_meta": None,
            "risk_evaluation": None
        }

        # 1. Login Failure Handling
        if event_type == "cowrie.login.failed":
            bf_result = self.brute_detector.record_attempt(src_ip, username, timestamp)
            if bf_result["is_brute_force"] or bf_result["is_username_enumeration"]:
                title = "SSH Username Enumeration Detected" if bf_result["is_username_enumeration"] else "SSH Brute-Force Password Attack"
                severity = "High" if bf_result["is_username_enumeration"] and bf_result["is_brute_force"] else "Medium"
                risk_eval = RiskEngine.calculate_score(
                    failed_logins=bf_result["failed_attempts_in_window"],
                    has_multiple_usernames=bf_result["is_username_enumeration"]
                )

                result["trigger_alert"] = True
                result["risk_evaluation"] = risk_eval
                result["alert_data"] = {
                    "severity": severity,
                    "risk_score": risk_eval["risk_score"],
                    "title": title,
                    "description": f"Source IP {src_ip} attempted {bf_result['failed_attempts_in_window']} logins with usernames: {', '.join(bf_result['unique_usernames_tested'][:5])}"
                }

        # 2. Command Execution Handling
        elif event_type == "cowrie.command.input" and cmd_text:
            cmd_meta = self.cmd_analyzer.analyze(cmd_text)
            result["command_meta"] = cmd_meta

            # Calculate risk for this command
            cat = cmd_meta["category"]
            recon_c = 1 if "Reconnaissance" in cat or "Discovery" in cat else 0
            file_c = 1 if "File Retrieval" in cat else 0
            dest_c = 1 if "Destructive" in cat else 0
            pers_c = 1 if "Persistence" in cat else 0
            priv_c = 1 if "Privilege Escalation" in cat else 0
            rev_c = 1 if "Reverse Shell" in cat else 0

            risk_eval = RiskEngine.calculate_score(
                recon_commands_count=recon_c,
                file_retrieval_count=file_c,
                destructive_count=dest_c,
                persistence_count=pers_c,
                priv_esc_count=priv_c,
                reverse_shell_count=rev_c
            )
            result["risk_evaluation"] = risk_eval

            # Trigger alert for severe commands
            if risk_eval["risk_score"] >= 20:
                severity = "Critical" if risk_eval["risk_score"] >= 25 else "High"
                result["trigger_alert"] = True
                result["alert_data"] = {
                    "severity": severity,
                    "risk_score": risk_eval["risk_score"],
                    "title": f"Suspicious Command Execution: {cat}",
                    "description": f"Command executed in session: '{cmd_text}'. MITRE Tactic: {cmd_meta.get('mitre_tactic')} ({cmd_meta.get('mitre_id')})"
                }

        # 3. Successful Login Alert
        elif event_type == "cowrie.login.success":
            result["trigger_alert"] = True
            result["risk_evaluation"] = {"risk_score": 40, "severity": "Medium"}
            result["alert_data"] = {
                "severity": "High",
                "risk_score": 50,
                "title": f"Honeypot Compromise: Interactive Shell Acquired",
                "description": f"Attacker from {src_ip} successfully logged into honeypot as user '{username}'."
            }

        return result

