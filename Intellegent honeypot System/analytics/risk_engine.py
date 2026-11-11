from typing import Dict, Any

class RiskEngine:
    """
    Industry-level Threat Intelligence Risk Engine for IHTIP.
    Calculates deterministic risk scores based on attacker activity weights:
      RiskScore = min(100, sum(ActivityScores))
    
    Classification Matrix:
      0 - 29   : Low
      30 - 59  : Medium
      60 - 79  : High
      80 - 100 : Critical
    """

    ACTIVITY_WEIGHTS = {
        "failed_login": 5,
        "multiple_usernames": 10,
        "reconnaissance": 15,
        "suspicious_file_retrieval": 20,
        "persistence_attempt": 20,
        "privilege_escalation": 20,
        "destructive_command": 25,
        "reverse_shell": 25,
        "tor_or_proxy": 15,
    }

    @staticmethod
    def calculate_score(
        failed_logins: int = 0,
        has_multiple_usernames: bool = False,
        recon_commands_count: int = 0,
        file_retrieval_count: int = 0,
        destructive_count: int = 0,
        persistence_count: int = 0,
        priv_esc_count: int = 0,
        reverse_shell_count: int = 0,
        is_known_proxy: bool = False
    ) -> Dict[str, Any]:
        """
        Calculates cumulative risk score and returns severity category with audit breakdown.
        """
        breakdown = {}
        total = 0

        if failed_logins > 0:
            score = min(25, failed_logins * RiskEngine.ACTIVITY_WEIGHTS["failed_login"])
            total += score
            breakdown["failed_logins"] = score

        if has_multiple_usernames:
            score = RiskEngine.ACTIVITY_WEIGHTS["multiple_usernames"]
            total += score
            breakdown["multiple_usernames_tested"] = score

        if recon_commands_count > 0:
            score = min(30, recon_commands_count * RiskEngine.ACTIVITY_WEIGHTS["reconnaissance"])
            total += score
            breakdown["reconnaissance_commands"] = score

        if file_retrieval_count > 0:
            score = min(40, file_retrieval_count * RiskEngine.ACTIVITY_WEIGHTS["suspicious_file_retrieval"])
            total += score
            breakdown["suspicious_file_retrieval"] = score

        if persistence_count > 0:
            score = min(30, persistence_count * RiskEngine.ACTIVITY_WEIGHTS["persistence_attempt"])
            total += score
            breakdown["persistence_attempts"] = score

        if priv_esc_count > 0:
            score = min(30, priv_esc_count * RiskEngine.ACTIVITY_WEIGHTS["privilege_escalation"])
            total += score
            breakdown["privilege_escalation"] = score

        if destructive_count > 0:
            score = min(50, destructive_count * RiskEngine.ACTIVITY_WEIGHTS["destructive_command"])
            total += score
            breakdown["destructive_attempts"] = score

        if reverse_shell_count > 0:
            score = min(40, reverse_shell_count * RiskEngine.ACTIVITY_WEIGHTS["reverse_shell"])
            total += score
            breakdown["reverse_shell_attempts"] = score

        if is_known_proxy:
            score = RiskEngine.ACTIVITY_WEIGHTS["tor_or_proxy"]
            total += score
            breakdown["anonymizer_or_tor"] = score

        # Bound score between 0 and 100
        final_score = min(100, max(0, total))

        # Severity mapping
        if final_score >= 80:
            severity = "Critical"
        elif final_score >= 60:
            severity = "High"
        elif final_score >= 30:
            severity = "Medium"
        else:
            severity = "Low"

        return {
            "risk_score": final_score,
            "severity": severity,
            "breakdown": breakdown
        }

