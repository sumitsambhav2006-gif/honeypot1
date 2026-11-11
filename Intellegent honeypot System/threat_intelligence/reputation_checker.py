import logging
import requests
from typing import Dict
from config.settings import settings

logger = logging.getLogger(__name__)

# Known malicious ASNs / subnets
KNOWN_HIGH_RISK_PREFIXES = {
    "185.220.": 95,  # Known Tor exit nodes
    "194.26.": 88,   # Bulletproof hosting
    "45.155.": 80,   # Scanning infrastructure
    "114.119.": 82,  # Persistent SSH brute force
}

class ReputationChecker:
    """Calculates threat reputation scores (0-100) using AbuseIPDB / VirusTotal or Threat Heuristics."""

    def __init__(self):
        self.abuse_api_key = settings.ABUSEIPDB_API_KEY
        self.vt_api_key = settings.VIRUSTOTAL_API_KEY
        self.cache: Dict[str, int] = {}

    def get_reputation(self, ip_address: str, failed_logins: int = 0) -> int:
        """
        Returns threat score from 0 (harmless) to 100 (actively malicious).
        """
        if ip_address in ("127.0.0.1", "localhost"):
            return 10

        if ip_address in self.cache:
            return self.cache[ip_address]

        # 1. AbuseIPDB API Check if configured
        if self.abuse_api_key:
            try:
                headers = {"Key": self.abuse_api_key, "Accept": "application/json"}
                params = {"ipAddress": ip_address, "maxAgeInDays": "90"}
                res = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=2.5)
                if res.status_code == 200:
                    score = res.json().get("data", {}).get("abuseConfidenceScore", 50)
                    self.cache[ip_address] = score
                    return score
            except Exception as e:
                logger.debug(f"AbuseIPDB query error for {ip_address}: {e}")

        # 2. Heuristic Scoring based on Subnet and Attack Intensity
        base_score = 40
        for prefix, score in KNOWN_HIGH_RISK_PREFIXES.items():
            if ip_address.startswith(prefix):
                base_score = score
                break

        # Adjust score by observed honeypot aggression
        if failed_logins > 10:
            base_score = min(100, base_score + 25)
        elif failed_logins > 3:
            base_score = min(100, base_score + 10)

        self.cache[ip_address] = base_score
        return base_score

