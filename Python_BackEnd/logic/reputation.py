"""
logic/reputation.py
===================
News Sentiment Analysis — Pillar 5: Reputational Risk

Strategy:
  - Fetch top 10 news headlines via NewsAPI.org (free dev tier, 100 req/day).
  - Run VADER sentiment analysis on each headline (local, no API key needed).
  - Aggregate compound sentiment scores → penalty points.
  - Graceful fallback if NEWSAPI_KEY missing or quota exceeded.
"""

import os
import requests

try:
    from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
    VADER_AVAILABLE = True
except ImportError:
    VADER_AVAILABLE = False

from logic.standards import RiskBenchmarks


class ReputationAnalyzer:
    """Analyzes vendor reputation using live news sentiment."""

    def __init__(self, vendor_name: str = "", domain: str = ""):
        self.vendor_name = vendor_name.strip()
        self.domain = domain.strip()
        self.news_api_key = os.getenv("NEWSAPI_KEY", "")
        self.analyzer = SentimentIntensityAnalyzer() if VADER_AVAILABLE else None

    def fetch_headlines(self) -> list:
        """
        Fetch recent news headlines for the vendor via NewsAPI.org.
        Returns a list of headline strings.
        """
        if not self.news_api_key or self.news_api_key == "your_newsapi_key_here":
            return []

        query = self.vendor_name or self.domain.split(".")[0]
        if not query:
            return []

        try:
            url = "https://newsapi.org/v2/everything"
            params = {
                "q": f'"{query}"',
                "language": "en",
                "sortBy": "publishedAt",
                "pageSize": 15,
                "apiKey": self.news_api_key,
            }
            res = requests.get(url, params=params, timeout=8)
            res.raise_for_status()
            articles = res.json().get("articles", [])
            headlines = [
                f"{a.get('title', '')} {a.get('description', '')}".strip()
                for a in articles
                if a.get("title") and "[Removed]" not in a.get("title", "")
            ]
            return headlines[:15]
        except Exception:
            return []

    def analyze_sentiment(self, headlines: list) -> dict:
        """
        Run VADER sentiment on a list of headlines.
        Returns aggregate stats.
        """
        if not headlines or not self.analyzer:
            return {"compound": 0.0, "positive": 0, "negative": 0, "neutral": 0, "total": 0}

        compounds = []
        pos_count = neg_count = neu_count = 0

        for headline in headlines:
            scores = self.analyzer.polarity_scores(headline)
            compound = scores["compound"]
            compounds.append(compound)
            if compound >= RiskBenchmarks.STD_SENTIMENT_THRESHOLD:
                pos_count += 1
            elif compound <= -RiskBenchmarks.STD_SENTIMENT_THRESHOLD:
                neg_count += 1
            else:
                neu_count += 1

        avg_compound = sum(compounds) / len(compounds) if compounds else 0.0

        return {
            "compound": round(avg_compound, 4),
            "positive": pos_count,
            "negative": neg_count,
            "neutral": neu_count,
            "total": len(headlines)
        }

    def calculate_penalty(self, sentiment: dict) -> tuple:
        """
        Map sentiment analysis results to penalty points.
        Returns (penalty_points, reasons)
        """
        penalty = 0.0
        reasons = []
        compound = sentiment.get("compound", 0.0)
        total = sentiment.get("total", 0)

        if total == 0:
            # No news data — apply neutral score
            reasons.append("No recent news data available (API key required or quota exceeded)")
            return 0.0, reasons

        neg = sentiment.get("negative", 0)
        pos = sentiment.get("positive", 0)
        neg_ratio = neg / total if total > 0 else 0

        if compound <= -0.3 or neg_ratio > 0.5:
            penalty += RiskBenchmarks.PENALTY_NEGATIVE_NEWS
            reasons.append(f"Predominantly negative news sentiment (score: {compound:.3f})")
        elif compound <= -0.05 or neg_ratio > 0.25:
            penalty += RiskBenchmarks.PENALTY_MIXED_NEWS
            reasons.append(f"Mixed/cautious news sentiment (score: {compound:.3f})")
        elif compound >= 0.1:
            reasons.append(f"Positive news coverage (score: {compound:.3f})")
        else:
            reasons.append(f"Neutral news sentiment (score: {compound:.3f})")

        # Extra penalty if mostly negative headlines dominate
        if neg > pos * 2 and total >= 5:
            penalty += 5
            reasons.append(f"High negative headline ratio ({neg}/{total} negative articles)")

        return round(penalty, 1), reasons

    def run_analysis(self) -> dict:
        """Run reputation analysis and return structured results."""
        headlines = self.fetch_headlines()
        sentiment = self.analyze_sentiment(headlines)
        penalty, reasons = self.calculate_penalty(sentiment)

        reputation_score = max(0, 100 - int(penalty * 2.5))

        return {
            "reputation_score": reputation_score,
            "penalty_points": penalty,
            "risk_level": RiskBenchmarks.get_risk_level((penalty / RiskBenchmarks.RISK_BUDGET) * 100),
            "reasons": reasons,
            "sentiment": sentiment,
            "headlines_analyzed": len(headlines),
            "vader_available": VADER_AVAILABLE,
            "newsapi_configured": bool(self.news_api_key and self.news_api_key != "your_newsapi_key_here")
        }