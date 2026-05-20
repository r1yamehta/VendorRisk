def run_cyber(domain: str, vendor_name: str) -> dict:
    try:
        scanner = CyberScanner(domain=domain, vendor_name=vendor_name)
        result = scanner.run_audit()
        result["vendor_name"] = vendor_name  # ← ADD THIS LINE
        return result
    except Exception as e:
        return {"cyber_score": 50, "penalty_points": 10, "error": str(e),
                "tech_stack": [], "vulnerability_count": 0, "vulnerability_details": [],
                "vendor_name": vendor_name}  # ← ADD THIS


def run_operations(domain: str) -> dict:
    try:
        analyzer = OperationalAnalyzer(domain=domain)
        return analyzer.run_analysis()
    except Exception as e:
        return {"operational_score": 50, "penalty_points": 10, "error": str(e), "reasons": []}


def run_financial(vendor_name: str, domain: str) -> dict:
    try:
        analyzer = FinancialAnalyzer(vendor_name=vendor_name, domain=domain)
        result = analyzer.run_analysis()
        # Try to infer industry from ticker or default
        result["industry"] = "General"  # ← ADD THIS (or map from ticker)
        return result
    except Exception as e:
        return {"financial_score": 50, "penalty_points": 8, "error": str(e), 
                "reasons": [], "industry": "General"}  # ← ADD THIS
