"""
logic/darkweb_e.py
==================
Dark Web & Breach History — Pillar 3: Dark Web Risk

Strategy:
  - Query HIBP public /breaches endpoint (no API key needed).
  - Filter breaches where vendor name or domain appears in breach Name/Domain.
  - Apply penalty per breach using standards.py, capped at MAX_BREACH_PENALTY.
  - Return breach titles, count, and penalty score.
"""

import requests
from logic.standards import RiskBenchmarks


_BREACH_CACHE: dict = {}  # Module-level cache to avoid repeat HIBP calls


class DarkWebScanner:
    """Checks for public data breaches associated with a vendor."""

    def __init__(self, vendor_name: str = "", domain: str = ""):
        self.vendor_name = vendor_name.strip().lower()
        self.domain = domain.strip().lower()
        for prefix in ["https://", "http://", "www."]:
            if self.domain.startswith(prefix):
                self.domain = self.domain[len(prefix):]

    def _fetch_all_breaches(self) -> list:
        """
        Fetch the full public HIBP breach list (cached in memory).
        This endpoint returns ALL public breaches — no API key required.
        """
        global _BREACH_CACHE
        if "breaches" in _BREACH_CACHE:
            return _BREACH_CACHE["breaches"]

        try:
            res = requests.get(
                "https://haveibeenpwned.com/api/v3/breaches",
                timeout=8,
                headers={
                    "User-Agent": "VendorRiskAI/1.0 (Vendor Risk Assessment Tool)",
                    "Accept": "application/json"
                }
            )
            res.raise_for_status()
            breaches = res.json()
            _BREACH_CACHE["breaches"] = breaches
            return breaches
        except Exception:
            return []

    def check_leaks(self) -> dict:
        """
        Check if vendor appears in any known public data breaches.
        Returns: {matches: list, leak_count: int, penalty: float}
        """
        all_breaches = self._fetch_all_breaches()

        if not all_breaches:
            return {
                "matches": [],
                "leak_count": 0,
                "penalty": 0,
                "error": "Could not reach HIBP API"
            }

        # Search terms for matching
        vendor_root = self.vendor_name.split(".")[0] if "." in self.vendor_name else self.vendor_name
        domain_root = self.domain.split(".")[0] if self.domain else ""

        matches = []
        for breach in all_breaches:
            breach_name = breach.get("Name", "").lower()
            breach_domain = breach.get("Domain", "").lower()
            breach_title = breach.get("Title", "")

            name_match = (
                (vendor_root and vendor_root in breach_name) or
                (vendor_root and vendor_root in breach_domain) or
                (domain_root and domain_root in breach_name) or
                (domain_root and domain_root in breach_domain)
            )

            if name_match:
                matches.append({
                    "title": breach_title,
                    "domain": breach.get("Domain", ""),
                    "breach_date": breach.get("BreachDate", ""),
                    "pwn_count": breach.get("PwnCount", 0),
                    "data_classes": breach.get("DataClasses", [])[:5]  # Top 5 data types
                })

        leak_count = len(matches)
        # Severity-weighted penalty: more accounts exposed = higher risk
        penalty = min(
            leak_count * RiskBenchmarks.PENALTY_PER_BREACH,
            RiskBenchmarks.MAX_BREACH_PENALTY
        )

        return {
            "matches": matches,
            "leak_count": leak_count,
            "penalty": round(penalty, 1)
        }

    def run_audit(self) -> dict:
        """Run dark web audit and return structured results."""
        result = self.check_leaks()

        matches = result.get("matches", [])
        leak_count = result.get("leak_count", 0)
        penalty = result.get("penalty", 0)

        dw_score = max(0, 100 - int(penalty * 2.5))

        reasons = []
        if leak_count == 0:
            reasons.append("✅ No known public data breaches found")
        else:
            reasons.append(f"❌ {leak_count} public breach(es) associated with this vendor")
            for m in matches[:3]:  # Show top 3 breaches
                reasons.append(f"  • {m['title']} ({m['breach_date']}, {m['pwn_count']:,} accounts)")

        return {
            "dw_score": dw_score,
            "penalty_points": penalty,
            "leaks_found": leak_count,
            "breach_details": [m["title"] for m in matches],
            "breach_metadata": matches[:5],
            "risk_level": RiskBenchmarks.get_risk_level((penalty / RiskBenchmarks.RISK_BUDGET) * 100),
            "reasons": reasons,
            "error": result.get("error")
        }