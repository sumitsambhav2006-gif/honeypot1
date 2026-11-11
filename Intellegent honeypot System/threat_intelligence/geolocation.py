import logging
import requests
from typing import Dict, Any

logger = logging.getLogger(__name__)

# Known Threat Subnet / Autonomous System Heuristics (Offline Fast Lookup)
OFFLINE_SUBNET_CACHE = {
    "185.220.": {"country": "Germany", "code": "DE", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821, "asn": "AS205100", "isp": "Tor Exit Node Network"},
    "194.26.": {"country": "Russia", "code": "RU", "city": "Moscow", "lat": 55.7558, "lon": 37.6173, "asn": "AS49505", "isp": "Hostkey B.V. Bulletproof"},
    "45.155.": {"country": "Netherlands", "code": "NL", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041, "asn": "AS51852", "isp": "Private Layer Inc."},
    "114.119.": {"country": "China", "code": "CN", "city": "Beijing", "lat": 39.9042, "lon": 116.4074, "asn": "AS4134", "isp": "Chinanet Backbone"},
    "198.51.": {"country": "United States", "code": "US", "city": "Ashburn", "lat": 39.0438, "lon": -77.4874, "asn": "AS14618", "isp": "Amazon AWS Cloud"},
    "103.251.": {"country": "India", "code": "IN", "city": "Mumbai", "lat": 19.0760, "lon": 72.8777, "asn": "AS133694", "isp": "Bharti Airtel Ltd"},
    "178.128.": {"country": "Singapore", "code": "SG", "city": "Singapore", "lat": 1.3521, "lon": 103.8198, "asn": "AS14061", "isp": "DigitalOcean ASN"},
    "91.240.": {"country": "Ukraine", "code": "UA", "city": "Kyiv", "lat": 50.4501, "lon": 30.5234, "asn": "AS200052", "isp": "Delta-X ISP"},
}

class GeolocationService:
    """Enriches IP addresses with Geographic and ISP telemetry data."""

    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout
        self.cache: Dict[str, Dict[str, Any]] = {}

    def lookup(self, ip_address: str) -> Dict[str, Any]:
        """Looks up geographic coordinates, country, and ISP for target IP."""
        if not ip_address or ip_address in ("127.0.0.1", "localhost", "::1"):
            return {
                "country": "Localhost (Self Test)",
                "country_code": "LO",
                "city": "Loopback Interface",
                "latitude": 0.0,
                "longitude": 0.0,
                "asn": "AS-LOCAL",
                "isp": "Local Red Team Simulation"
            }

        if ip_address.startswith(("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.")):
            return {
                "country": "Private LAN Network",
                "country_code": "LAN",
                "city": "Internal Subnet",
                "latitude": 0.0,
                "longitude": 0.0,
                "asn": "AS-PRIVATE",
                "isp": "Local Area Network"
            }

        # Check memory cache
        if ip_address in self.cache:
            return self.cache[ip_address]

        # Check offline fast cache
        for prefix, data in OFFLINE_SUBNET_CACHE.items():
            if ip_address.startswith(prefix):
                normalized = {
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("code", "XX"),
                    "city": data.get("city", "Unknown"),
                    "latitude": data.get("lat", 0.0),
                    "longitude": data.get("lon", 0.0),
                    "asn": data.get("asn", "Unknown ASN"),
                    "isp": data.get("isp", "Unknown ISP")
                }
                self.cache[ip_address] = normalized
                return normalized

        # Online Lookup with fallback
        try:
            url = f"http://ip-api.com/json/{ip_address}?fields=status,country,countryCode,city,lat,lon,as,isp"
            res = requests.get(url, timeout=self.timeout)
            if res.status_code == 200:
                data = res.json()
                if data.get("status") == "success":
                    result = {
                        "country": data.get("country", "Unknown"),
                        "country_code": data.get("countryCode", "XX"),
                        "city": data.get("city", "Unknown"),
                        "latitude": data.get("lat"),
                        "longitude": data.get("lon"),
                        "asn": data.get("as", "Unknown ASN"),
                        "isp": data.get("isp", "Unknown ISP")
                    }
                    self.cache[ip_address] = result
                    return result
        except Exception as e:
            logger.debug(f"Geolocation online lookup failed for {ip_address}: {e}")

        # Default fallback
        fallback = {
            "country": "Unknown",
            "country_code": "XX",
            "city": "Unknown",
            "latitude": 0.0,
            "longitude": 0.0,
            "asn": "Unknown ASN",
            "isp": "Unknown ISP"
        }
        self.cache[ip_address] = fallback
        return fallback

