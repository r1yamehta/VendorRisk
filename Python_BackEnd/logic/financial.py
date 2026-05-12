"""
logic/financial.py
==================
Financial Stability Analysis — Pillar 4: Financial Risk

Strategy:
  - Use yfinance to look up a ticker by company name.
  - Extract: founding year (age), market cap, revenue growth, profit margins.
  - For private companies (no ticker found), apply conservative defaults.
  - Score using standards.py comparability factor.
"""

import os
from datetime import datetime

try:
    import yfinance as yf
    YFINANCE_AVAILABLE = True
except ImportError:
    YFINANCE_AVAILABLE = False

from logic.standards import RiskBenchmarks


# Common company-to-ticker mapping for well-known vendors
KNOWN_TICKERS = {
    "microsoft": "MSFT", "google": "GOOGL", "alphabet": "GOOGL",
    "amazon": "AMZN", "apple": "AAPL", "meta": "META", "facebook": "META",
    "netflix": "NFLX", "salesforce": "CRM", "adobe": "ADBE",
    "oracle": "ORCL", "ibm": "IBM", "intel": "INTC", "cisco": "CSCO",
    "paypal": "PYPL", "visa": "V", "mastercard": "MA",
    "crowdstrike": "CRWD", "cloudflare": "NET", "okta": "OKTA",
    "zoom": "ZM", "dropbox": "DBX", "box": "BOX",
    "twilio": "TWLO", "atlassian": "TEAM",
    "shopify": "SHOP", "spotify": "SPOT",
    "uber": "UBER", "lyft": "LYFT", "airbnb": "ABNB", "doordash": "DASH",
    "palo alto": "PANW", "fortinet": "FTNT", "qualys": "QLYS",
    "rapid7": "RPD", "tenable": "TENB",
    "servicenow": "NOW", "workday": "WDAY", "sap": "SAP",
    "mongodb": "MDB", "snowflake": "SNOW",
    "datadog": "DDOG", "splunk": "SPLK", "elastic": "ESTC",
}


class FinancialAnalyzer:
    """Analyzes a vendor's financial stability using yfinance data."""

    def __init__(self, vendor_name: str = "", domain: str = ""):
        self.vendor_name = vendor_name.strip().lower()
        self.domain = domain.strip().lower()
        self._ticker_data = None

    def _resolve_ticker(self) -> str | None:
        """Find the stock ticker symbol for the vendor."""
        for key, ticker in KNOWN_TICKERS.items():
            if key in self.vendor_name or key in self.domain:
                return ticker
        domain_root = self.domain.split(".")[0] if self.domain else ""
        if domain_root in KNOWN_TICKERS:
            return KNOWN_TICKERS[domain_root]
        return None

    def _fetch_ticker_info(self, ticker: str) -> dict:
        """Fetch company info from yfinance."""
        if not YFINANCE_AVAILABLE:
            return {}
        try:
            t = yf.Ticker(ticker)
            info = t.info
            if not info.get("longName") and not info.get("shortName"):
                return {}
            self._ticker_data = t
            return info
        except Exception:
            return {}

    def _calculate_years_active(self, info: dict) -> float:
        """Infer company age from yfinance data."""
        current_year = datetime.now().year
        for field in ["founded", "foundingYear"]:
            year = info.get(field)
            if year and isinstance(year, (int, float)) and 1800 < year <= current_year:
                return current_year - int(year)
        try:
            if self._ticker_data:
                hist = self._ticker_data.history(period="max")
                if not hist.empty:
                    ipo_year = hist.index[0].year
                    return (current_year - ipo_year) + 5
        except Exception:
            pass
        return -1

    def calculate_penalty(self, info: dict, years_active: float) -> tuple:
        """Calculate financial penalty points."""
        penalty = 0.0
        reasons = []

        # Business age
        if years_active < 0:
            penalty += 8
            reasons.append("Company age unknown (likely private)")
        elif years_active < 1:
            penalty += RiskBenchmarks.PENALTY_VERY_YOUNG
            reasons.append("Very new company (<1 year) — high longevity risk")
        elif years_active < RiskBenchmarks.STD_YEARS_ACTIVE:
            penalty += RiskBenchmarks.PENALTY_YOUNG_COMPANY
            reasons.append(f"Limited operating history ({years_active:.0f} years vs {RiskBenchmarks.STD_YEARS_ACTIVE}yr standard)")
        else:
            reasons.append(f"Established company ({years_active:.0f} years active)")

        # Market cap
        market_cap = info.get("marketCap", 0) or 0
        if market_cap > 0:
            if market_cap < 50_000_000:
                penalty += 12
                reasons.append("Micro-cap company — financial stability risk")
            elif market_cap < 500_000_000:
                penalty += 6
                reasons.append("Small-cap company — moderate financial risk")
            elif market_cap > 10_000_000_000:
                reasons.append("Large-cap company — strong financial foundation")
        else:
            penalty += 5
            reasons.append("Market cap unavailable (private company assumed)")

        # Revenue growth
        revenue_growth = info.get("revenueGrowth")
        if revenue_growth is not None:
            pct = revenue_growth * 100
            if pct < -10:
                penalty += RiskBenchmarks.PENALTY_NEGATIVE_REVENUE + 5
                reasons.append(f"Strong revenue decline ({pct:.1f}%)")
            elif pct < 0:
                penalty += RiskBenchmarks.PENALTY_NEGATIVE_REVENUE
                reasons.append(f"Negative revenue growth ({pct:.1f}%)")
            elif pct > 20:
                reasons.append(f"Strong revenue growth ({pct:.1f}%)")
            else:
                reasons.append(f"Stable revenue ({pct:.1f}% growth)")

        # Profit margins
        profit_margin = info.get("profitMargins")
        if profit_margin is not None:
            margin_pct = profit_margin * 100
            if margin_pct < -20:
                penalty += 8
                reasons.append(f"Deep losses (margin: {margin_pct:.1f}%)")
            elif margin_pct < 0:
                penalty += 4
                reasons.append(f"Operating at a loss (margin: {margin_pct:.1f}%)")
            else:
                reasons.append(f"Profitable (margin: {margin_pct:.1f}%)")

        return round(penalty, 1), reasons

    def run_analysis(self) -> dict:
        """Run financial analysis and return structured results."""
        ticker = self._resolve_ticker()
        info = {}
        years_active = -1
        ticker_symbol = None

        if ticker and YFINANCE_AVAILABLE:
            info = self._fetch_ticker_info(ticker)
            if info:
                ticker_symbol = ticker
                years_active = self._calculate_years_active(info)

        penalty, reasons = self.calculate_penalty(info, years_active)
        financial_score = max(0, 100 - int(penalty * 2))

        return {
            "financial_score": financial_score,
            "penalty_points": penalty,
            "risk_level": RiskBenchmarks.get_risk_level((penalty / RiskBenchmarks.RISK_BUDGET) * 100),
            "reasons": reasons,
            "data_source": {
                "ticker": ticker_symbol,
                "company_name": info.get("longName") or info.get("shortName") or "Unknown",
                "years_active": round(years_active, 1) if years_active >= 0 else "Unknown",
                "market_cap": info.get("marketCap"),
                "revenue_growth": info.get("revenueGrowth"),
                "profit_margins": info.get("profitMargins"),
                "yfinance_available": YFINANCE_AVAILABLE
            }
        }