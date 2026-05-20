"""
scoring_engine.py — VendorRisk Risk Scoring & Benchmarks
=========================================================

Merged from: standards.py + scoring_engine.py

Risk Benchmarks:
  - Defines the RISK_BUDGET (80 penalty points = maximum tolerable risk).
  - Each module calculates "Penalty Points" for the vendor.
  - Final Score = (Total Penalty Points / RISK_BUDGET) * 100 → fill_percent
  - fill_percent drives the Heat-Bar color: Green → Yellow → Red

Scoring Engine:
  - Each module returns penalty_points (not just a raw 0-100 score).
  - We sum all penalty points across the Six Pillars.
  - fill_percent = (total_penalty / RISK_BUDGET) * 100
  - Output: fill_percent, color (hex), status_text, risk_level, breakdown

Backward Compatibility:
  - Also returns risk_score (traditional 0-100) for existing frontend.
"""

# Add import for comparative analysis
from logic.comparative_analyzer import ComparativeAnalyzer


# ══════════════════════════════════════════════════════════════════════════
# Risk Benchmarks (previously standards.py)
# ══════════════════════════════════════════════════════════════════════════

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
    RISK_BUDGET = 80            # The comparative anchor

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


# ══════════════════════════════════════════════════════════════════════════
# Risk Aggregator (Scoring Engine)
# ══════════════════════════════════════════════════════════════════════════


class RiskAggregator:
    """
    Aggregates penalty points from all Six Pillars into a final
    Comparative Risk Report using the Risk Budget methodology.
    """

    # Pillar weights for penalty contribution (must sum to 1.0)
    PILLAR_WEIGHTS = {
        "cyber":      0.30,
        "operations": 0.20,
        "financial":  0.15,
        "reputation": 0.15,
        "compliance": 0.10,
        "dark_web":   0.10,
    }

    def __init__(
        self,
        cyber_data: dict,
        operations_data: dict,
        reputation_data: dict,
        compliance_data: dict,
        financial_data: dict,
        dark_web_data: dict = None,
    ):
        self.cyber = cyber_data
        self.operations = operations_data
        self.reputation = reputation_data
        self.compliance = compliance_data
        self.financial = financial_data
        self.dark_web = dark_web_data or {}

    # ── Penalty Extraction ─────────────────────────────────────────────────

    def _get_penalty(self, pillar_data: dict, score_key: str) -> float:
        """
        Extract penalty points from a pillar's data dict.
        Prefers the 'penalty_points' key; falls back to inverting the score.
        """
        if "penalty_points" in pillar_data:
            return float(pillar_data["penalty_points"])

        # Backward compatibility: convert old 0-100 score to penalty
        score = float(pillar_data.get(score_key, 50))
        # Invert: score=100 → 0 penalty, score=0 → max penalty
        return round((100 - score) / 100 * RiskBenchmarks.RISK_BUDGET * 0.5, 1)

    def get_pillar_penalties(self) -> dict:
        """Extract penalty points from each pillar."""
        return {
            "cyber":      self._get_penalty(self.cyber,      "cyber_score"),
            "operations": self._get_penalty(self.operations, "operational_score"),
            "financial":  self._get_penalty(self.financial,  "financial_score"),
            "reputation": self._get_penalty(self.reputation, "reputation_score"),
            "compliance": self._get_penalty(self.compliance, "compliance_score"),
            "dark_web":   self._get_penalty(self.dark_web,   "dw_score"),
        }

    # ── Composite Scoring ──────────────────────────────────────────────────

    def calculate_weighted_penalty(self, penalties: dict) -> float:
        """
        Apply pillar weights to normalize different penalty scales.
        Each pillar is weighted by its risk contribution factor.
        """
        weighted = 0.0
        for pillar, weight in self.PILLAR_WEIGHTS.items():
            raw_penalty = penalties.get(pillar, 0)
            # Scale each pillar's contribution into the RISK_BUDGET space
            weighted += raw_penalty * weight * (RiskBenchmarks.RISK_BUDGET / 20)

        return round(min(weighted, RiskBenchmarks.RISK_BUDGET * 1.5), 1)

    def calculate_fill_percent(self, total_penalty: float) -> float:
        """
        Core comparability formula:
        fill_percent = (total_penalty / RISK_BUDGET) * 100
        Clamped to [0, 100].
        """
        raw = (total_penalty / RiskBenchmarks.RISK_BUDGET) * 100
        return round(min(max(raw, 0), 100), 1)

    # ── Traditional Score (Backward Compat) ───────────────────────────────

    def get_traditional_scores(self) -> dict:
        """Return classic 0-100 scores from each pillar for the frontend."""
        return {
            "cyber":      self.cyber.get("cyber_score", 50),
            "operations": self.operations.get("operational_score", 50),
            "reputation": self.reputation.get("reputation_score", 50),
            "compliance": self.compliance.get("compliance_score") or self.compliance.get("comp_score", 50),
            "financial":  self.financial.get("financial_score", 50),
            "dark_web":   self.dark_web.get("dw_score", 100),
        }

    def calculate_traditional_score(self) -> float:
        """Weighted average of traditional 0-100 scores."""
        scores = self.get_traditional_scores()
        weights = {
            "cyber": 0.30, "operations": 0.20, "reputation": 0.15,
            "compliance": 0.10, "financial": 0.15, "dark_web": 0.10
        }
        total = sum(scores[p] * weights[p] for p in weights)
        return round(total, 1)

    def add_comparative_analysis(self, vendor_name: str, industry: str, cve_count: int) -> dict:
        """
        Add comparative analysis to the risk report.
        This runs alongside the existing penalty-based scoring.
        """
        try:
            comparative = ComparativeAnalyzer.get_full_comparison(vendor_name, industry, cve_count)
            return comparative
        except Exception as e:
            print(f"⚠️ Comparative analysis error: {e}")
            return {
                "available": False,
                "error": str(e),
                "risk_level": "Medium",
                "status_text": "Comparative analysis temporarily unavailable",
                "color": "#eab308"
            }

    # ── Report Generation ──────────────────────────────────────────────────

    def generate_report(self) -> dict:
        """
        Generate the full Comparative Risk Report.
        Now includes peer comparison.
        """
        penalties = self.get_pillar_penalties()
        total_penalty = self.calculate_weighted_penalty(penalties)
        fill_percent = self.calculate_fill_percent(total_penalty)

        color = RiskBenchmarks.get_heat_color(fill_percent)
        status_text = RiskBenchmarks.get_status_text(fill_percent)
        risk_level = RiskBenchmarks.get_risk_level(fill_percent)

        traditional_score = self.calculate_traditional_score()

        # ── NEW: Add comparative analysis ──
        # Extract vendor name and industry from the data
        vendor_name = self.cyber.get("vendor_name", "Unknown")
        industry = self.financial.get("industry", "General")
        cve_count = self.cyber.get("vulnerability_count", 0)

        comparative_analysis = self.add_comparative_analysis(vendor_name, industry, cve_count)

        return {
            # ── Existing Outputs ──
            "fill_percent": fill_percent,
            "color": color,
            "status_text": status_text,
            "risk_level": risk_level,
            "total_penalty": total_penalty,
            "risk_budget": RiskBenchmarks.RISK_BUDGET,
            "risk_score": traditional_score,
            "summary": status_text,

            # ── Pillar Breakdown ──
            "pillar_penalties": penalties,
            "pillar_scores": self.get_traditional_scores(),
            "breakdown": {
                "cyber": self.cyber,
                "operations": self.operations,
                "reputation": self.reputation,
                "compliance": self.compliance,
                "financial": self.financial,
                "dark_web": self.dark_web,
            },

            # ── NEW: Comparative Analysis ──
            "comparative": comparative_analysis
        }
