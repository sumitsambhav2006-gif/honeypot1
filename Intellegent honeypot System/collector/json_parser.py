import json
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class JSONParser:
    """Robust JSON Log Parser for Cowrie Honeypot event streams."""

    @staticmethod
    def parse_line(line: str) -> Optional[Dict[str, Any]]:
        """
        Parses raw text line into a structured JSON dictionary.
        Gracefully handles truncated lines, non-JSON output, and encoding issues.
        """
        if not line:
            return None

        line_str = line.strip()
        if not line_str or not (line_str.startswith("{") and line_str.endswith("}")):
            return None

        try:
            return json.loads(line_str)
        except json.JSONDecodeError as err:
            logger.debug(f"JSON decode failure for line: {line_str[:50]}... Error: {err}")
            return None
        except Exception as err:
            logger.error(f"Unexpected error parsing line: {err}")
            return None

