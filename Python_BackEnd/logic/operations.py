"""
logic/operations.py
===================
Operational Maturity Analysis — Pillar 2: Operational Risk

Strategy:
  - Check /.well-known/security.txt (security policy presence)
  - Verify HTTPS is active and valid (SSL certificate check)
  - Measure HTTP response time (latency proxy for uptime quality)
  - Bonus: check for robots.txt (signals organized web presence)
  - Score using standards.py comparability factor.
"""

import requests
import time
import ssl
import socket

from logic.standards import RiskBenchmarks


class OperationalAnalyzer:
    """Analyzes operational maturity of a vendor via their domain."""

    def __init__(self, domain: str = ""):
        self.domain = domain.strip().lower()
        for prefix in ["https://", "http://", "www."]:
            if self.domain.startswith(prefix):
                self.domain = self.domain[len(prefix):]

    def check_security_txt(self) -> dict:
        """
        Check for /.well-known/security.txt — the industry standard for
        responsible disclosure policies.
        Returns: {found: bool, url: str, penalty: float}
        """
        if not self.domain:
            return {"found": False, "url": "", "penalty": RiskBenchmarks.PENALTY_NO_SECURITY_TXT}

        for path in ["/.well-known/security.txt", "/security.txt"]:
            url = f"https://{self.domain}{path}"
            try:
                res = requests.get(url, timeout=5, headers={"User-Agent": "VendorRiskAI/1.0"})
                if res.status_code == 200 and "contact" in res.text.lower():
                    return {"found": True, "url": url, "penalty": 0}
            except Exception:
                continue

        return {
            "found": False,
            "url": f"https://{self.domain}/.well-known/security.txt",
            "penalty": RiskBenchmarks.PENALTY_NO_SECURITY_TXT
        }

    def check_https(self) -> dict:
        """
        Verify that the vendor domain has a valid HTTPS connection.
        Returns: {valid: bool, penalty: float}
        """
        if not self.domain:
            return {"valid": False, "penalty": RiskBenchmarks.PENALTY_NO_HTTPS}

        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    return {"valid": True, "penalty": 0, "cert_subject": str(cert.get("subject", ""))}
        except ssl.SSLCertVerificationError:
            return {"valid": False, "penalty": RiskBenchmarks.PENALTY_NO_HTTPS, "error": "Invalid SSL certificate"}
        except Exception:
            # Try plain HTTP to see if it's up at all
            try:
                requests.get(f"http://{self.domain}", timeout=5)
                return {"valid": False, "penalty": RiskBenchmarks.PENALTY_NO_HTTPS, "error": "HTTP only, no HTTPS"}
            except Exception:
                return {"valid": False, "penalty": RiskBenchmarks.PENALTY_NO_HTTPS, "error": "Domain unreachable"}

    def check_response_time(self) -> dict:
        """
        Measure HTTP response time as a proxy for uptime quality.
        Returns: {response_ms: float, penalty: float}
        """
        if not self.domain:
            return {"response_ms": -1, "penalty": RiskBenchmarks.PENALTY_HIGH_LATENCY}

        try:
            start = time.time()
            res = requests.get(
                f"https://{self.domain}",
                timeout=10,
                headers={"User-Agent": "VendorRiskAI/1.0"},
                allow_redirects=True
            )
            elapsed_ms = (time.time() - start) * 1000

            penalty = 0
            if elapsed_ms > RiskBenchmarks.STD_MAX_RESPONSE_MS * 3:
                penalty = RiskBenchmarks.PENALTY_HIGH_LATENCY * 2
            elif elapsed_ms > RiskBenchmarks.STD_MAX_RESPONSE_MS:
                penalty = RiskBenchmarks.PENALTY_HIGH_LATENCY

            return {
                "response_ms": round(elapsed_ms, 0),
                "status_code": res.status_code,
                "penalty": penalty
            }
        except requests.exceptions.Timeout:
            return {"response_ms": -1, "penalty": RiskBenchmarks.PENALTY_HIGH_LATENCY * 2, "error": "Request timed out"}
        except Exception:
            return {"response_ms": -1, "penalty": RiskBenchmarks.PENALTY_HIGH_LATENCY, "error": "Unreachable"}

    def calculate_penalty(self, security_txt: dict, https: dict, response: dict) -> tuple:
        """Aggregate all operational penalties and build reasons list."""
        penalty = 0.0
        reasons = []

        # Security.txt
        penalty += security_txt.get("penalty", 0)
        if security_txt.get("found"):
            reasons.append("✅ Security disclosure policy (security.txt) found")
        else:
            reasons.append(f"⚠️ No security.txt — missing responsible disclosure policy (+{security_txt.get('penalty', 0)} pts)")

        # HTTPS
        penalty += https.get("penalty", 0)
        if https.get("valid"):
            reasons.append("✅ Valid HTTPS / SSL certificate confirmed")
        else:
            err = https.get("error", "No HTTPS")
            reasons.append(f"❌ {err} (+{https.get('penalty', 0)} pts)")

        # Response time
        penalty += response.get("penalty", 0)
        rms = response.get("response_ms", -1)
        if rms < 0:
            reasons.append(f"❌ Domain unreachable or timeout (+{response.get('penalty', 0)} pts)")
        elif rms > RiskBenchmarks.STD_MAX_RESPONSE_MS:
            reasons.append(f"⚠️ Slow response time ({rms:.0f}ms vs {RiskBenchmarks.STD_MAX_RESPONSE_MS}ms standard)")
        else:
            reasons.append(f"✅ Fast response time ({rms:.0f}ms)")

        return round(penalty, 1), reasons

    def run_analysis(self) -> dict:
        """Run operational analysis and return structured results."""
        security_txt = self.check_security_txt()
        https_check = self.check_https()
        response_check = self.check_response_time()

        penalty, reasons = self.calculate_penalty(security_txt, https_check, response_check)

        # Traditional 0-100 score for backward compatibility
        operational_score = max(0, 100 - int(penalty * 2.5))

        return {
            "operational_score": operational_score,
            "penalty_points": penalty,
            "risk_level": RiskBenchmarks.get_risk_level((penalty / RiskBenchmarks.RISK_BUDGET) * 100),
            "reasons": reasons,
            "checks": {
                "security_txt": security_txt,
                "https": https_check,
                "response_time": response_check
            }
        }