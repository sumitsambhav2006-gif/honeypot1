from typing import Dict, Any
from threat_intelligence.ip_enrichment import IPEnrichment

class IntelligenceService:
    """Singleton service providing threat intelligence enrichment across all platform layers."""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(IntelligenceService, cls).__new__(cls)
            cls._instance.enricher = IPEnrichment()
        return cls._instance

    def get_ip_intel(self, ip_address: str, failed_logins: int = 0) -> Dict[str, Any]:
        return self.enricher.enrich(ip_address, failed_logins=failed_logins)

intelligence_service = IntelligenceService()

