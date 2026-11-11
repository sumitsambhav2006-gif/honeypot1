import hashlib
import datetime
from typing import Optional, Dict, Any
from config.security_config import SecurityConfig

class EventNormalizer:
    """Normalizes raw Cowrie JSON events into a unified, secure SOC event schema."""

    def __init__(self, cache_size: int = 10000):
        self.seen_event_hashes = set()
        self.cache_size = cache_size

    def _generate_event_hash(self, event_data: dict) -> str:
        """Generates deterministic hash for duplicate event detection."""
        key_str = f"{event_data.get('session')}_{event_data.get('eventid')}_{event_data.get('timestamp')}_{event_data.get('input')}_{event_data.get('username')}"
        return hashlib.sha256(key_str.encode("utf-8", errors="ignore")).hexdigest()

    def is_duplicate(self, event_data: dict) -> bool:
        """Checks if event has already been ingested within the recent window."""
        e_hash = self._generate_event_hash(event_data)
        if e_hash in self.seen_event_hashes:
            return True

        if len(self.seen_event_hashes) >= self.cache_size:
            # Clear half the cache when limit is reached
            self.seen_event_hashes = set(list(self.seen_event_hashes)[self.cache_size // 2:])

        self.seen_event_hashes.add(e_hash)
        return False

    @staticmethod
    def parse_utc_timestamp(ts_val: Any) -> datetime.datetime:
        """Parses various timestamp formats into a clean UTC datetime object."""
        if isinstance(ts_val, datetime.datetime):
            return ts_val.astimezone(datetime.timezone.utc).replace(tzinfo=None)

        if not ts_val or not isinstance(ts_val, str):
            return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

        # Standard Cowrie format: 2026-11-08T18:54:45.906955Z
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S"
        ):
            try:
                dt = datetime.datetime.strptime(ts_val, fmt)
                return dt
            except ValueError:
                continue

        # Fallback
        return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

    def normalize(self, raw: Dict[str, Any], default_honeypot: str = "SSH-HONEYPOT-PROD-01") -> Optional[Dict[str, Any]]:
        """
        Transforms raw Cowrie JSON dict into standard normalized IHTIP schema.
        Performs data sanitization and credential masking.
        """
        if not raw or not isinstance(raw, dict):
            return None

        event_id = raw.get("eventid", "unknown")
        src_ip = raw.get("src_ip", "").strip()

        # Ignore local or loopback events if misconfigured
        if not src_ip or src_ip == "127.0.0.1" and not raw.get("session"):
            return None

        # Check for duplicate
        if self.is_duplicate(raw):
            return None

        # Redact raw password
        raw_password = raw.get("password")
        masked_pwd = SecurityConfig.mask_credential(raw_password) if raw_password else None

        # Sanitize command / input
        cmd_input = raw.get("input")
        if cmd_input:
            cmd_input = SecurityConfig.sanitize_input(cmd_input)

        username = raw.get("username")
        if username:
            username = SecurityConfig.sanitize_input(username)

        timestamp_dt = self.parse_utc_timestamp(raw.get("timestamp"))

        normalized = {
            "event_type": event_id,
            "source_ip": src_ip,
            "source_port": raw.get("src_port"),
            "dest_port": raw.get("dst_port", 2222),
            "session_id": raw.get("session", "unknown_session"),
            "username": username,
            "password_masked": masked_pwd,
            "command": cmd_input,
            "duration": raw.get("duration", 0),
            "honeypot_name": raw.get("honeypot", default_honeypot),
            "timestamp": timestamp_dt,
            "raw_payload": raw
        }

        return normalized

