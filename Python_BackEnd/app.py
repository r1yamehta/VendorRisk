"""
app.py — VendorRisk AI Python Engine
=====================================
Flask API server — The Orchestrator.

Routes:
  GET  /                    → Health check
  GET  /health              → Detailed health status
  GET  /analyze?vendor=...  → Full risk analysis (all Six Pillars)

Architecture:
  - Parallel execution via ThreadPoolExecutor (cuts latency ~3x)
  - All engines accept domain + vendor_name params
  - Returns Heat-Bar data (fill_percent, color, status_text) + full breakdown
"""
from flask import Flask, request, jsonify
from flask_cors import CORS

from dotenv import load_dotenv
import os
import sys
import time
import concurrent.futures

# Ensure logic package is on the path
sys.path.insert(0, os.path.dirname(__file__))

# Load environment variables from .env
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

# Import all logic modules
from logic.cyber_engine import CyberScanner
from logic.operations import OperationalAnalyzer
from logic.financial import FinancialAnalyzer
from logic.reputation import ReputationAnalyzer
from logic.compliance import ComplianceScanner
from logic.darkweb_e import DarkWebScanner
from logic.scoring_engine import RiskAggregator
from logic.standards import RiskBenchmarks

# ── App Setup ─────────────────────────────────────────────────────────────

app = Flask(__name__)
CORS(app)


# ── Utility ───────────────────────────────────────────────────────────────

def normalize_domain(vendor_input: str) -> tuple[str, str]:
    """
    From a vendor input (name or domain), extract:
      - domain: the bare domain (e.g. 'cloudflare.com')
      - vendor_name: clean company name (e.g. 'cloudflare')

    Examples:
      'Cloudflare'        → ('cloudflare.com', 'cloudflare')
      'cloudflare.com'    → ('cloudflare.com', 'cloudflare')
      'https://microsoft.com' → ('microsoft.com', 'microsoft')
    """
    raw = vendor_input.strip().lower()

    # Strip protocol
    for prefix in ["https://", "http://"]:
        if raw.startswith(prefix):
            raw = raw[len(prefix):]

    # Strip trailing slash or path
    raw = raw.split("/")[0]

    # Strip www
    if raw.startswith("www."):
        raw = raw[4:]

    # If it looks like a domain (has a dot), use as-is
    if "." in raw:
        domain = raw
        vendor_name = raw.split(".")[0]
    else:
        # It's a company name — try to construct a domain
        vendor_name = raw
        domain = f"{raw}.com"

    return domain, vendor_name


# ── Parallel Engine Runners ───────────────────────────────────────────────

def run_cyber(domain: str, vendor_name: str) -> dict:
    try:
        scanner = CyberScanner(domain=domain, vendor_name=vendor_name)
        return scanner.run_audit()
    except Exception as e:
        return {"cyber_score": 50, "penalty_points": 10, "error": str(e),
                "tech_stack": [], "vulnerability_count": 0, "vulnerability_details": []}


def run_operations(domain: str) -> dict:
    try:
        analyzer = OperationalAnalyzer(domain=domain)
        return analyzer.run_analysis()
    except Exception as e:
        return {"operational_score": 50, "penalty_points": 10, "error": str(e), "reasons": []}


def run_financial(vendor_name: str, domain: str) -> dict:
    try:
        analyzer = FinancialAnalyzer(vendor_name=vendor_name, domain=domain)
        return analyzer.run_analysis()
    except Exception as e:
        return {"financial_score": 50, "penalty_points": 8, "error": str(e), "reasons": []}


def run_reputation(vendor_name: str, domain: str) -> dict:
    try:
        analyzer = ReputationAnalyzer(vendor_name=vendor_name, domain=domain)
        return analyzer.run_analysis()
    except Exception as e:
        return {"reputation_score": 50, "penalty_points": 5, "error": str(e), "reasons": []}


def run_compliance(domain: str) -> dict:
    try:
        scanner = ComplianceScanner(domain=domain)
        return scanner.run_audit()
    except Exception as e:
        return {"comp_score": 50, "penalty_points": 9, "error": str(e), "certifications": []}


def run_darkweb(vendor_name: str, domain: str) -> dict:
    try:
        scanner = DarkWebScanner(vendor_name=vendor_name, domain=domain)
        return scanner.run_audit()
    except Exception as e:
        return {"dw_score": 100, "penalty_points": 0, "error": str(e), "leaks_found": 0}


# ── Routes ────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    return jsonify({
        "service": "VendorRisk AI — Python Risk Engine",
        "version": "2.0.0",
        "status": "running",
        "port": 5000,
        "endpoints": {
            "analyze": "GET /analyze?vendor=<domain_or_name>",
            "health":  "GET /health"
        }
    })


@app.route("/health")
def health():
    """Detailed health check with dependency status."""
    # Check optional dependencies
    try:
        import yfinance
        yfinance_ok = True
    except ImportError:
        yfinance_ok = False

    try:
        import webtech
        webtech_ok = True
    except ImportError:
        webtech_ok = False

    try:
        from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
        vader_ok = True
    except ImportError:
        vader_ok = False

    newsapi_key = os.getenv("NEWSAPI_KEY", "")
    newsapi_configured = bool(newsapi_key and newsapi_key != "your_newsapi_key_here")

    return jsonify({
        "status": "healthy",
        "engine": "VendorRisk AI Python Risk Engine v2.0",
        "dependencies": {
            "yfinance": "✅ installed" if yfinance_ok else "❌ missing — run: pip install yfinance",
            "webtech": "✅ installed" if webtech_ok else "❌ missing — run: pip install webtech",
            "vaderSentiment": "✅ installed" if vader_ok else "❌ missing — run: pip install vaderSentiment",
            "newsapi": "✅ key configured" if newsapi_configured else "⚠️ key missing — add NEWSAPI_KEY to .env",
        },
        "apis": {
            "osv_dev": "✅ free, no key required",
            "nvd_nist": "✅ free, no key required",
            "hibp_breaches": "✅ free public endpoint",
            "newsapi": "✅ configured" if newsapi_configured else "⚠️ not configured",
        }
    })


@app.route("/analyze", methods=["GET"])
def analyze():
    """
    Full vendor risk analysis across Six Pillars.

    Query params:
      vendor: domain (e.g. 'cloudflare.com') or company name (e.g. 'microsoft')

    Returns:
      JSON with fill_percent, color, status_text + full pillar breakdown
    """
    vendor_input = request.args.get("vendor", "").strip()

    if not vendor_input:
        return jsonify({
            "success": False,
            "error": "Missing 'vendor' parameter. Usage: /analyze?vendor=cloudflare.com"
        }), 400

    domain, vendor_name = normalize_domain(vendor_input)

    print(f"\n{'='*60}")
    print(f"🔍 Analyzing vendor: {vendor_name} | domain: {domain}")
    print(f"{'='*60}")

    start_time = time.time()

    # ── Parallel Execution ────────────────────────────────────────────────
    # Run all six pillars concurrently using a thread pool
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        futures = {
            "cyber":      executor.submit(run_cyber, domain, vendor_name),
            "operations": executor.submit(run_operations, domain),
            "financial":  executor.submit(run_financial, vendor_name, domain),
            "reputation": executor.submit(run_reputation, vendor_name, domain),
            "compliance": executor.submit(run_compliance, domain),
            "dark_web":   executor.submit(run_darkweb, vendor_name, domain),
        }

        results = {}
        for pillar, future in futures.items():
            try:
                results[pillar] = future.result(timeout=30)
                score_key = {
                    "cyber": "cyber_score", "operations": "operational_score",
                    "financial": "financial_score", "reputation": "reputation_score",
                    "compliance": "comp_score", "dark_web": "dw_score"
                }.get(pillar, "score")
                score = results[pillar].get(score_key, results[pillar].get("penalty_points", "?"))
                print(f"  ✅ {pillar.capitalize()}: {score}")
            except concurrent.futures.TimeoutError:
                print(f"  ⚠️  {pillar.capitalize()}: timed out")
                results[pillar] = {"error": "Timed out", "penalty_points": 10}
            except Exception as e:
                print(f"  ❌ {pillar.capitalize()}: {str(e)}")
                results[pillar] = {"error": str(e), "penalty_points": 10}

    elapsed = round(time.time() - start_time, 2)
    print(f"\n⏱  Total analysis time: {elapsed}s")

    # Normalize compliance data key for aggregator
    compliance_for_aggregator = {
        "compliance_score": results["compliance"].get("comp_score", 50),
        **results["compliance"]
    }

    # ── Aggregate ─────────────────────────────────────────────────────────
    try:
        aggregator = RiskAggregator(
            cyber_data=results["cyber"],
            operations_data=results["operations"],
            financial_data=results["financial"],
            reputation_data=results["reputation"],
            compliance_data=compliance_for_aggregator,
            dark_web_data=results["dark_web"],
        )
        final_report = aggregator.generate_report()
    except Exception as e:
        print(f"❌ Aggregation error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": "Risk aggregation failed",
            "details": str(e)
        }), 500

    # ── Response ──────────────────────────────────────────────────────────
    return jsonify({
        "success": True,
        "vendor": vendor_name,
        "domain": domain,
        "analysis_time_seconds": elapsed,

        # ── Heat-Bar Output (New) ──
        "fill_percent": final_report["fill_percent"],
        "color": final_report["color"],
        "status_text": final_report["status_text"],
        "risk_level": final_report["risk_level"],
        "total_penalty": final_report["total_penalty"],
        "risk_budget": RiskBenchmarks.RISK_BUDGET,

        # ── Backward Compatible ──
        "riskScore": final_report["risk_score"],
        "final_result": final_report,

        # ── Raw Pillar Data ──
        "raw_data": {
            "cyber":      results["cyber"],
            "operations": results["operations"],
            "financial":  results["financial"],
            "reputation": results["reputation"],
            "compliance": results["compliance"],
            "dark_web":   results["dark_web"],
        }
    })


# ── Entry Point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════╗
║   🛡️  VendorRisk AI — Python Risk Engine v2.0           ║
╠══════════════════════════════════════════════════════════╣
║   Port:    5000                                          ║
║   Mode:    Development                                   ║
╠══════════════════════════════════════════════════════════╣
║   Six Pillars:                                           ║
║   ✅ Cyber (webtech + OSV.dev + NVD)                    ║
║   ✅ Operations (security.txt + HTTPS + latency)        ║
║   ✅ Financial (yfinance — real market data)            ║
║   ✅ Reputation (NewsAPI + VADER sentiment)             ║
║   ✅ Compliance (multi-page keyword scan)               ║
║   ✅ Dark Web (HIBP public breach list)                 ║
╠══════════════════════════════════════════════════════════╣
║   Logic:  Comparability Factor (Risk Budget = 80)        ║
║   Output: fill_percent + hex color + status_text         ║
╚══════════════════════════════════════════════════════════╝
    """)
    app.run(debug=True, port=5000, host="localhost")