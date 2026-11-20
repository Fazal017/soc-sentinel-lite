"""Static IP -> country lookup for the *sample* data set only.

All addresses used here are documentation / TEST-NET ranges
(RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
They are not real hosts and must never be treated as live attribution.

In a production SIEM this would be replaced by a GeoIP database
(e.g. MaxMind GeoLite2). The mapping exists so the impossible-travel
rule (R005) can be demonstrated deterministically, offline.
"""

SAMPLE_GEO = {
    # 203.0.113.0/24 — "Pakistan" in the sample scenario
    "203.0.113.10": "PK",
    "203.0.113.45": "PK",
    "203.0.113.99": "PK",
    # 198.51.100.0/24 — "United States" in the sample scenario
    "198.51.100.10": "US",
    "198.51.100.23": "US",
    "198.51.100.77": "US",
    # 192.0.2.0/24 — "Germany" in the sample scenario
    "192.0.2.77": "DE",
    "192.0.2.15": "DE",
}

COUNTRY_NAMES = {"PK": "Pakistan", "US": "United States", "DE": "Germany"}


def country_for(ip: str | None) -> str | None:
    """Return the sample country code for an IP, or None if unknown."""
    if not ip:
        return None
    return SAMPLE_GEO.get(ip)


def country_name(code: str | None) -> str:
    return COUNTRY_NAMES.get(code or "", code or "Unknown")
