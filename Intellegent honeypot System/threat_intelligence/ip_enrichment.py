from typing import Dict, Any
from threat_intelligence.geolocation import GeolocationService
from threat_intelligence.reputation_checker import ReputationChecker

class IPEnrichment:
    """Enriches raw IP with Geolocation, ISP, ASN, and Threat Reputation."""

    def __init__(self):
        self.geo_service = GeolocationService()
        self.rep_service = ReputationChecker()

    def enrich(self, ip_address: str, failed_logins: int = 0) -> Dict[str, Any]:
        geo = self.geo_service.lookup(ip_address)
        reputation = self.rep_service.get_reputation(ip_address, failed_logins=failed_logins)

        return {
            "source_ip": ip_address,
            "country": geo.get("country", "Unknown"),
            "country_code": geo.get("country_code", "XX"),
            "city": geo.get("city", "Unknown"),
            "latitude": geo.get("latitude", 0.0),
            "longitude": geo.get("longitude", 0.0),
            "asn": geo.get("asn", "Unknown ASN"),
            "isp": geo.get("isp", "Unknown ISP"),
            "reputation": reputation,
            "threat_level": "CRITICAL" if reputation >= 80 else ("HIGH" if reputation >= 60 else ("MEDIUM" if reputation >= 30 else "LOW"))
        }

