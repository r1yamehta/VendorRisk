"""
logic/compliance.py
===================
Compliance Certification Scanner — Pillar 6: Compliance Risk

Strategy:
  - Scrape multiple pages: homepage, /privacy, /security, /trust, /compliance
  - Scan for known compliance certification keywords
  - Bonus checks: HTTPS presence, cookie consent, privacy policy
  - Score using standards.py benchmarks
"""

import requests
from logic.standards import RiskBenchmarks


class ComplianceScanner:
    """Scans a vendor's public web pages for compliance certifications."""

    def __init__(self, domain: str = ""):
        self.domain = domain.strip().lower()
        for prefix in ["https://", "http://", "www."]:
            if self.domain.startswith(prefix):
                self.domain = self.domain[len(prefix):]

    def _fetch_page_text(self, url: str) -> str:
        """Fetch a web page and return uppercase text for keyword scanning."""
        try:
            res = requests.get(
                url,
                timeout=6,
                headers={"User-Agent": "VendorRiskAI/1.0"},
                allow_redirects=True
            )
            if res.status_code == 200:
                return res.text.upper()
        except Exception:
            pass
        return ""

    def scan_for_certifications(self) -> dict:
        """
        Scan multiple pages for compliance keywords.
        Returns: {found: list, penalty: float}
        """
        if not self.domain:
            return {"found": [], "penalty": RiskBenchmarks.PENALTY_NO_COMPLIANCE}

        pages_to_check = [
            f"https://{self.domain}",
            f"https://{self.domain}/privacy",
            f"https://{self.domain}/security",
            f"https://{self.domain}/trust",
            f"https://{self.domain}/compliance",
            f"https://{self.domain}/legal",
        ]

        all_text = ""
        for url in pages_to_check:
            text = self._fetch_page_text(url)
            if text:
                all_text += text
                if len(all_text) > 500_000:  # Cap at 500KB total
                    break

        if not all_text:
            return {"found": [], "penalty": RiskBenchmarks.PENALTY_NO_COMPLIANCE}

        found = []
        for cert in RiskBenchmarks.KNOWN_CERTIFICATIONS:
            # Check both exact and normalized forms
            variants = [cert.upper(), cert.replace(" ", "").upper(), cert.replace("-", "").upper()]
            if any(v in all_text for v in variants):
                found.append(cert)

        # Additional signals
        bonus_signals = []
        if "COOKIE" in all_text and ("CONSENT" in all_text or "GDPR" in all_text):
            bonus_signals.append("Cookie consent mechanism")
        if "PRIVACY POLICY" in all_text or "PRIVACY NOTICE" in all_text:
            bonus_signals.append("Privacy policy present")
        if "DATA PROCESSING AGREEMENT" in all_text or " DPA " in all_text:
            bonus_signals.append("Data Processing Agreement (DPA)")
        if "BUG BOUNTY" in all_text or "VULNERABILITY DISCLOSURE" in all_text:
            bonus_signals.append("Bug bounty / vulnerability disclosure program")

        # Calculate penalty: start at max, reduce per cert
        cert_count = len(found)
        bonus_count = len(bonus_signals)

        if cert_count == 0 and bonus_count == 0:
            penalty = float(RiskBenchmarks.PENALTY_NO_COMPLIANCE)
        else:
            reduction = (cert_count * RiskBenchmarks.BONUS_PER_CERT) + (bonus_count * 2)
            penalty = max(0, RiskBenchmarks.PENALTY_NO_COMPLIANCE - reduction)

        return {
            "found": found,
            "bonus_signals": bonus_signals,
            "penalty": round(penalty, 1)
        }

    def run_audit(self) -> dict:
        """Run compliance audit and return structured results."""
        scan = self.scan_for_certifications()
        found = scan.get("found", [])
        bonus = scan.get("bonus_signals", [])
        penalty = scan.get("penalty", RiskBenchmarks.PENALTY_NO_COMPLIANCE)

        comp_score = max(0, 100 - int(penalty * 3))

        reasons = []
        if found:
            reasons.append(f"Certifications found: {', '.join(found)}")
        else:
            reasons.append("No compliance certifications detected on public pages")
        if bonus:
            reasons.extend(bonus)

        return {
            "comp_score": comp_score,
            "penalty_points": penalty,
            "certifications": found,
            "bonus_signals": bonus,
            "risk_level": RiskBenchmarks.get_risk_level((penalty / RiskBenchmarks.RISK_BUDGET) * 100),
            "reasons": reasons
        }