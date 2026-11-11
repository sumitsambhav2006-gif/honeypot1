import hashlib
import html
import re

class SecurityConfig:
    # Role Definitions
    ROLE_ADMIN = "admin"
    ROLE_ANALYST = "analyst"
    ROLE_VIEWER = "viewer"

    ROLES = [ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER]

    # Redaction placeholder
    REDACTED_TEXT = "[REDACTED_CREDENTIAL]"

    # Common password mask rules
    @staticmethod
    def mask_credential(password: str) -> str:
        """
        Redacts actual attacker password string into an anonymized metadata hash representation.
        Ensures plaintext attacker passwords or inadvertently typed user credentials are never stored plain.
        """
        if not password:
            return ""
        # Return length indicator + salted short hash for pattern correlation without leaking plaintext
        short_hash = hashlib.sha256(password.encode("utf-8", errors="ignore")).hexdigest()[:8]
        return f"[LEN:{len(password)}_HASH:{short_hash}]"

    @staticmethod
    def sanitize_input(val: str) -> str:
        """Sanitizes user or attacker-controlled text strings against Stored XSS / injection attacks."""
        if not val or not isinstance(val, str):
            return ""
        # Escape HTML entities
        escaped = html.escape(val.strip())
        # Strip dangerous control characters (except common shell symbols)
        return re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', escaped)

    @staticmethod
    def get_security_headers() -> dict:
        """Returns standard SOC-grade HTTP Security Headers."""
        return {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
                "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
                "img-src 'self' data: https:; "
                "connect-src 'self';"
            )
        }

