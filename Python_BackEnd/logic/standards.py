"""
logic/standards.py
==================
Defines the Industry Standard Risk Benchmarks — the "Safe Zone" anchor.

The core philosophy:
  - We define a RISK_BUDGET (80 penalty points = maximum tolerable risk).
  - Each module calculates "Penalty Points" for the vendor.
  - Final Score = (Total Penalty Points / RISK_BUDGET) * 100  → fill_percent
  - fill_percent drives the Heat-Bar color: Green → Yellow → Red
"""


class RiskBenchmarks:
    """Industry-standard baseline values for comparative risk assessment."""

    # ── Cyber Benchmarks ───────────────────────────────────────────────────
    STD_MAX_CVES = 10           # Acceptable CVE count for a "Low Risk" vendor
    PENALTY_PER_CRITICAL_CVE = 8    # Points per CRITICAL severity CVE
    PENALTY_PER_HIGH_CVE = 5        # Points per HIGH severity CVE
    PENALTY_PER_MEDIUM_CVE = 2      # Points per MEDIUM severity CVE
    PENALTY_PER_LOW_CVE = 0.5       # Points per LOW severity CVE

    # ── Operational Benchmarks ─────────────────────────────────────────────
    STD_UPTIME = 99.9           # Industry-standard SLA uptime percentage
    STD_MAX_RESPONSE_MS = 500   # Acceptable HTTP response time in milliseconds
    PENALTY_NO_SECURITY_TXT = 10    # Missing /.well-known/security.txt
    PENALTY_NO_HTTPS = 15           # No valid HTTPS
    PENALTY_HIGH_LATENCY = 5        # Response time > STD_MAX_RESPONSE_MS

    # ── Financial Benchmarks ───────────────────────────────────────────────
    STD_YEARS_ACTIVE = 3        # Minimum years to be considered "established"
    PENALTY_YOUNG_COMPANY = 12  # < STD_YEARS_ACTIVE
    PENALTY_VERY_YOUNG = 20     # < 1 year active
    PENALTY_NEGATIVE_REVENUE = 10   # Declining revenue growth

    # ── Reputation Benchmarks ──────────────────────────────────────────────
    STD_SENTIMENT_THRESHOLD = 0.05  # Neutral VADER compound score boundary
    PENALTY_NEGATIVE_NEWS = 15      # Predominantly negative news sentiment
    PENALTY_MIXED_NEWS = 7          # Mixed/uncertain news sentiment

    # ── Compliance Benchmarks ──────────────────────────────────────────────
    KNOWN_CERTIFICATIONS = ["ISO 27001", "SOC 2", "GDPR", "HIPAA", "PCI DSS",
                            "ISO 9001", "NIST", "FedRAMP", "CCPA"]
    PENALTY_NO_COMPLIANCE = 18  # No compliance signals found
    BONUS_PER_CERT = 5          # Reduction in penalty per cert found (cap: 18)

    # ── Dark Web Benchmarks ────────────────────────────────────────────────
    PENALTY_PER_BREACH = 10     # Points per public breach found
    MAX_BREACH_PENALTY = 30     # Cap on breach penalties

    # ── Composite Risk Budget ──────────────────────────────────────────────
    RISK_BUDGET = 80            # The comparative anchor (100% fill = 80 pts)

    @classmethod
    def get_heat_color(cls, fill_percent: float) -> str:
        """
        Returns a hex color code based on risk fill percentage.
        Green (safe) → Yellow (caution) → Red (critical)
        """
        fill = max(0, min(100, fill_percent))
        if fill <= 30:
            return "#22c55e"    # Tailwind green-500
        elif fill <= 50:
            return "#84cc16"    # Tailwind lime-500
        elif fill <= 65:
            return "#eab308"    # Tailwind yellow-500
        elif fill <= 80:
            return "#f97316"    # Tailwind orange-500
        else:
            return "#ef4444"    # Tailwind red-500

    @classmethod
    def get_status_text(cls, fill_percent: float) -> str:
        """Returns a human-readable risk status label."""
        fill = max(0, min(100, fill_percent))
        if fill <= 30:
            return "Low Risk — Vendor meets industry standards"
        elif fill <= 50:
            return "Moderate Risk — Minor gaps detected"
        elif fill <= 65:
            return "Elevated Risk — Review recommended"
        elif fill <= 80:
            return "High Risk — Significant exposure found"
        else:
            return "Critical Risk — Immediate action required"

    @classmethod
    def get_risk_level(cls, fill_percent: float) -> str:
        """Returns Low / Medium / High / Critical classification."""
        fill = max(0, min(100, fill_percent))
        if fill <= 35:
            return "Low"
        elif fill <= 60:
            return "Medium"
        elif fill <= 80:
            return "High"
        else:
            return "Critical"
