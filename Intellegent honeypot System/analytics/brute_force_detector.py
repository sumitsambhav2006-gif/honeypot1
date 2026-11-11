import datetime
from collections import defaultdict
from typing import Dict, Any

class BruteForceDetector:
    """Tracks authentication velocity, brute-force frequency, and username enumeration patterns."""

    def __init__(self, time_window_seconds: int = 300, brute_force_threshold: int = 5, enum_threshold: int = 3):
        self.time_window = time_window_seconds
        self.brute_force_threshold = brute_force_threshold
        self.enum_threshold = enum_threshold

        # In-memory tracking: ip -> list of (timestamp, username)
        self.attempts = defaultdict(list)

    def record_attempt(self, ip_address: str, username: str, timestamp: datetime.datetime = None) -> Dict[str, Any]:
        """
        Records a failed login attempt and assesses whether it constitutes brute-force or enumeration.
        """
        if timestamp is None:
            timestamp = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

        # Clean old attempts outside window
        cutoff = timestamp - datetime.timedelta(seconds=self.time_window)
        self.attempts[ip_address] = [
            (ts, u) for ts, u in self.attempts[ip_address] if ts >= cutoff
        ]

        # Append new attempt
        self.attempts[ip_address].append((timestamp, username or "unknown"))

        recent_attempts = self.attempts[ip_address]
        total_failures = len(recent_attempts)
        unique_usernames = set([u for _, u in recent_attempts if u])

        is_brute_force = total_failures >= self.brute_force_threshold
        is_enumeration = len(unique_usernames) >= self.enum_threshold

        detection_result = {
            "source_ip": ip_address,
            "failed_attempts_in_window": total_failures,
            "unique_usernames_tested": list(unique_usernames),
            "is_brute_force": is_brute_force,
            "is_username_enumeration": is_enumeration,
            "risk_bonus": (10 if is_enumeration else 0) + (15 if is_brute_force else 0)
        }

        return detection_result

