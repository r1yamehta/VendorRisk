"""
logic/cyber_engine.py
=====================
Software Composition Analysis (SCA) — Pillar 1: Cyber Risk

Strategy:
  - Tech Stack: Use 'webtech' (open-source, Wappalyzer fingerprint DB) to
    detect technologies from HTTP headers and HTML content. Zero cost.
  - Vulnerabilities: Query OSV.dev (free, no key) by package name + ecosystem.
  - CVE Lookup: Query NVD NIST API (free) for vendor-wide CVE count & severity.
  - Scoring: Severity-weighted penalty points referenced against standards.py.
"""

import requests
import os
import time

try:
    import webtech
    WEBTECH_AVAILABLE = True
except ImportError:
    WEBTECH_AVAILABLE = False

from logic.standards import RiskBenchmarks


class CyberScanner:
    def __init__(self, domain: str = "", vendor_name: str = ""):
        self.domain = domain.strip().lower()
        # Normalize domain — strip http/https/www if present
        for prefix in ["https://", "http://", "www."]:
            if self.domain.startswith(prefix):
                self.domain = self.domain[len(prefix):]
        self.vendor_name = vendor_name.strip()
        self.std = RiskBenchmarks()

    # ── Tech Stack Detection ───────────────────────────────────────────────

    def get_tech_stack(self) -> list:
        """
        Detect tech stack using 'webtech' (open-source Wappalyzer fingerprints).
        Falls back to manual header analysis if webtech is unavailable.
        """
        if not self.domain:
            return []

        url = f"https://{self.domain}"

        # Method 1: webtech library
        if WEBTECH_AVAILABLE:
            try:
                wt = webtech.WebTech(options={"silent": True})
                report = wt.start_from_url(url, timeout=10)
                technologies = []
                for tech in report.tech:
                    technologies.append({
                        "name": tech.name,
                        "version": tech.version or "",
                        "categories": tech.categories if hasattr(tech, 'categories') else []
                    })
                return technologies
            except Exception:
                pass  # Fall through to manual detection

        # Method 2: Manual HTTP header fingerprinting
        return self._manual_header_detection(url)

    def _manual_header_detection(self, url: str) -> list:
        """Fallback: detect technologies from HTTP response headers."""
        detected = []
        try:
            res = requests.get(url, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
            headers = {k.lower(): v for k, v in res.headers.items()}

            # Server header
            if "server" in headers:
                detected.append({"name": headers["server"].split("/")[0], "version":
                                  headers["server"].split("/")[1] if "/" in headers["server"] else ""})
            # X-Powered-By
            if "x-powered-by" in headers:
                detected.append({"name": headers["x-powered-by"], "version": ""})
            # Content-Type hints
            if "cloudflare" in str(headers).lower():
                detected.append({"name": "Cloudflare", "version": ""})
            # HTML-based detection
            content = res.text.lower()
            frontend_signals = {
                "react": "React", "angular": "Angular", "vue.js": "Vue.js",
                "jquery": "jQuery", "wordpress": "WordPress", "drupal": "Drupal",
                "bootstrap": "Bootstrap", "next.js": "Next.js"
            }
            for signal, name in frontend_signals.items():
                if signal in content:
                    detected.append({"name": name, "version": ""})

        except Exception:
            pass
        return detected

    # ── Ecosystem Detection ────────────────────────────────────────────────

    def detect_ecosystem(self, tech_name: str) -> str | None:
        """Maps technology name to its OSV.dev ecosystem identifier."""
        name = tech_name.lower()
        ecosystem_map = {
            "pypi": ["django", "flask", "fastapi", "tornado", "pyramid", "celery"],
            "npm": ["react", "angular", "vue", "express", "next.js", "nuxt",
                    "svelte", "jquery", "lodash", "webpack", "babel"],
            "packagist": ["wordpress", "laravel", "drupal", "symfony", "magento"],
            "rubygems": ["rails", "sinatra", "jekyll"],
            "go": ["gin", "echo", "fiber", "beego"],
            "maven": ["spring", "hibernate", "struts", "log4j"],
        }
        for ecosystem, techs in ecosystem_map.items():
            if any(t in name for t in techs):
                return ecosystem.capitalize() if ecosystem not in ("npm", "pypi") else \
                       ("npm" if ecosystem == "npm" else "PyPI")
        return None

    # ── OSV.dev Vulnerability Lookup ───────────────────────────────────────

    def check_osv_vulnerabilities(self, tech_stack: list) -> tuple[int, list]:
        """Query OSV.dev for vulnerabilities per technology in the stack."""
        total_penalty = 0
        details = []

        for tech in tech_stack:
            ecosystem = self.detect_ecosystem(tech.get("name", ""))
            if not ecosystem:
                continue

            payload = {
                "package": {
                    "name": tech["name"],
                    "ecosystem": ecosystem
                }
            }
            if tech.get("version"):
                payload["version"] = tech["version"]

            try:
                res = requests.post(
                    "https://api.osv.dev/v1/query",
                    json=payload,
                    timeout=8
                )
                res.raise_for_status()
                vulns = res.json().get("vulns", [])

                # Severity-weighted scoring
                tech_penalty = 0
                for vuln in vulns:
                    severity = self._get_osv_severity(vuln)
                    if severity == "CRITICAL":
                        tech_penalty += RiskBenchmarks.PENALTY_PER_CRITICAL_CVE
                    elif severity == "HIGH":
                        tech_penalty += RiskBenchmarks.PENALTY_PER_HIGH_CVE
                    elif severity == "MEDIUM":
                        tech_penalty += RiskBenchmarks.PENALTY_PER_MEDIUM_CVE
                    else:
                        tech_penalty += RiskBenchmarks.PENALTY_PER_LOW_CVE

                total_penalty += tech_penalty
                details.append({
                    "technology": tech["name"],
                    "version": tech.get("version", "unknown"),
                    "vuln_count": len(vulns),
                    "penalty_points": round(tech_penalty, 1)
                })

            except Exception:
                continue

        return round(total_penalty, 1), details

    def _get_osv_severity(self, vuln: dict) -> str:
        """Extract CVSS severity level from an OSV vulnerability entry."""
        try:
            for severity in vuln.get("severity", []):
                score_str = severity.get("score", "")
                if "CVSS:3" in score_str or "CVSS:4" in score_str:
                    # Parse base score from CVSS vector or use direct rating
                    rating = severity.get("type", "")
                    if "CRITICAL" in rating.upper():
                        return "CRITICAL"
                    elif "HIGH" in rating.upper():
                        return "HIGH"
            # Check database_specific for rating
            db = vuln.get("database_specific", {})
            rating = db.get("severity", "").upper()
            if rating in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                return rating
        except Exception:
            pass
        return "MEDIUM"  # Default to medium if unknown

    # ── NVD NIST CVE Lookup ───────────────────────────────────────────────

    def check_nvd_cves(self) -> tuple[int, float, int]:
        """
        Query NVD NIST API for CVEs related to this vendor.
        Returns: (total_count, avg_severity, critical_count)
        """
        if not self.vendor_name:
            return 0, 0.0, 0
        try:
            url = (
                f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                f"?keywordSearch={requests.utils.quote(self.vendor_name)}"
                f"&resultsPerPage=50"
            )
            res = requests.get(url, timeout=12, headers={"User-Agent": "VendorRiskAI/1.0"})
            res.raise_for_status()
            data = res.json()

            total = data.get("totalResults", 0)
            vulns = data.get("vulnerabilities", [])
            scores = []
            critical_count = 0

            for v in vulns:
                metrics = v.get("cve", {}).get("metrics", {})
                base_score = (
                    metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore") or
                    metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {}).get("baseScore") or
                    5.0
                )
                scores.append(base_score)
                if base_score >= 9.0:
                    critical_count += 1

            avg = round(sum(scores) / len(scores), 2) if scores else 0.0
            return total, avg, critical_count

        except Exception:
            return 0, 0.0, 0

    # ── Penalty Calculation ────────────────────────────────────────────────

    def calculate_penalty(self, osv_penalty: float, nvd_total: int,
                          nvd_avg_severity: float, nvd_critical: int) -> float:
        """
        Calculate total cyber penalty points using comparability logic.
        Combines OSV.dev tech-specific vulns + NVD vendor-wide CVEs.
        """
        penalty = 0.0

        # OSV penalty (from tech stack vulnerabilities)
        penalty += min(osv_penalty, 25)  # Cap OSV contribution at 25 pts

        # NVD penalty (vendor-wide CVEs vs standard)
        excess_cves = max(0, nvd_total - RiskBenchmarks.STD_MAX_CVES)
        cve_penalty = min(excess_cves * 0.5, 20)  # Cap at 20 pts
        penalty += cve_penalty

        # Severity bonus penalty
        penalty += min(nvd_critical * 2, 10)  # Up to 10 pts for critical CVEs

        return round(penalty, 1)

    # ── Main Entry Point ───────────────────────────────────────────────────

    def run_audit(self) -> dict:
        """Run the full cyber audit and return structured results."""
        # 1. Tech stack detection
        tech_stack = self.get_tech_stack()

        # 2. OSV vulnerability scan
        osv_penalty, vuln_details = self.check_osv_vulnerabilities(tech_stack)

        # 3. NVD CVE lookup (parallel-friendly, but run sequentially here)
        nvd_total, nvd_avg, nvd_critical = self.check_nvd_cves()

        # 4. Penalty calculation
        total_penalty = self.calculate_penalty(
            osv_penalty, nvd_total, nvd_avg, nvd_critical
        )

        # 5. Traditional 0-100 score (for backward compatibility with scoring_engine)
        cyber_score = max(0, 100 - int(total_penalty * 1.25))

        return {
            "cyber_score": cyber_score,
            "penalty_points": total_penalty,
            "tech_stack": tech_stack,
            "vulnerability_count": nvd_total,
            "vulnerability_details": vuln_details,
            "nvd_data": {
                "total_cves": nvd_total,
                "avg_severity": nvd_avg,
                "critical_count": nvd_critical
            },
            "webtech_available": WEBTECH_AVAILABLE
        }