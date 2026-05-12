"""
logic/scoring_engine.py
=======================
The Analytical Brain — Comparative Risk Aggregator

New Logic (Comparability Factor):
  - Each module returns penalty_points (not just a raw 0-100 score).
  - We sum all penalty points across the Six Pillars.
  - fill_percent = (total_penalty / RISK_BUDGET) * 100
  - This ratio drives the Heat-Bar: Green → Yellow → Red
  - Output: fill_percent, color (hex), status_text, risk_level, breakdown

Backward Compatibility:
  - Also returns risk_score (traditional 0-100) for existing frontend.
"""

from logic.standards import RiskBenchmarks


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

    # ── Report Generation ──────────────────────────────────────────────────

    def generate_report(self) -> dict:
        """
        Generate the full Comparative Risk Report.

        Key outputs:
          - fill_percent: 0-100, drives the Heat-Bar
          - color: hex color code (green → red)
          - status_text: human-readable risk label
          - risk_level: Low / Medium / High / Critical
          - risk_score: classic 0-100 (backward compatible)
        """
        penalties = self.get_pillar_penalties()
        total_penalty = self.calculate_weighted_penalty(penalties)
        fill_percent = self.calculate_fill_percent(total_penalty)

        color = RiskBenchmarks.get_heat_color(fill_percent)
        status_text = RiskBenchmarks.get_status_text(fill_percent)
        risk_level = RiskBenchmarks.get_risk_level(fill_percent)

        # Traditional score (inverted from fill_percent for compatibility)
        traditional_score = self.calculate_traditional_score()

        return {
            # ── New Comparative Outputs ──
            "fill_percent": fill_percent,
            "color": color,
            "status_text": status_text,
            "risk_level": risk_level,
            "total_penalty": total_penalty,
            "risk_budget": RiskBenchmarks.RISK_BUDGET,

            # ── Backward Compatible ──
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
            }
        }