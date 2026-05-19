"""
comparative_analyzer.py
=======================
Compares a vendor against all vendors in the database to calculate
percentile rankings and generate comparative risk assessments.
"""

from typing import Dict, List, Optional
from logic.vendor_repository import VendorRepository


class ComparativeAnalyzer:
    """
    Provides comparative risk assessment by benchmarking a vendor
    against the entire population of vendors in the database.
    """
    
    # Risk level mapping based on percentile
    # Higher percentile = BETTER (fewer CVEs than peers)
    PERCENTILE_TO_RISK = {
        (90, 101): {
            "level": "Low",
            "status": "Excellent",
            "description": "Better than 90% of vendors",
            "color": "#22c55e",  # Green
            "recommendation": "Continue standard monitoring"
        },
        (70, 90): {
            "level": "Low",
            "status": "Good",
            "description": "Better than {percentile}% of vendors",
            "color": "#84cc16",  # Lime
            "recommendation": "Standard annual review recommended"
        },
        (40, 70): {
            "level": "Medium",
            "status": "Average",
            "description": "Similar to {percentile}% of vendors",
            "color": "#eab308",  # Yellow
            "recommendation": "Regular quarterly monitoring recommended"
        },
        (15, 40): {
            "level": "High",
            "status": "Elevated",
            "description": "Worse than {percentile}% of vendors",
            "color": "#f97316",  # Orange
            "recommendation": "Immediate security review required"
        },
        (0, 15): {
            "level": "Critical",
            "status": "Critical",
            "description": "Worse than {percentile}% of vendors",
            "color": "#ef4444",  # Red
            "recommendation": "Urgent action required - consider alternatives"
        }
    }
    
    @classmethod
    def calculate_percentile(cls, current_value: int, all_values: List[int]) -> float:
        """
        Calculate what percentile this value falls into.
        Returns 0-100 where higher = better (fewer CVEs than peers).
        
        Example: current=45, all=[5,12,23,45,67,89]
                 Vendors with fewer: 3 (5,12,23)
                 Percentile = (3/6) × 100 = 50%
        """
        if not all_values:
            return 50  # Default to middle if no data
        
        # Count vendors with FEWER CVEs (lower is better)
        fewer_count = sum(1 for v in all_values if v < current_value)
        equal_count = sum(1 for v in all_values if v == current_value)
        
        total = len(all_values)
        
        if total == 0:
            return 50
        
        # Percentile of vendors that are BETTER (have fewer CVEs)
        percentile = (fewer_count / total) * 100
        
        return round(percentile, 1)
    
    @classmethod
    def get_risk_from_percentile(cls, percentile: float) -> Dict:
        """
        Map percentile to risk level, status text, color, and recommendation.
        """
        for (low, high), risk_info in cls.PERCENTILE_TO_RISK.items():
            if low <= percentile < high:
                # Make a copy and format the description
                result = risk_info.copy()
                result["description"] = result["description"].format(percentile=round(100 - percentile))
                result["percentile"] = percentile
                return result
        
        # Fallback
        return {
            "level": "Medium",
            "status": "Unknown",
            "description": f"Comparative data available",
            "color": "#eab308",
            "recommendation": "Monitor regularly",
            "percentile": percentile
        }
    
    @classmethod
    def compare_global(cls, vendor_name: str, cve_count: int) -> Dict:
        """
        Compare a vendor against ALL vendors in database.
        Returns global ranking and risk assessment.
        """
        # Get all CVE counts from database
        all_cves = VendorRepository.get_all_cve_counts()
        
        if len(all_cves) < 2:
            return {
                "available": False,
                "message": f"Need at least 2 vendors for comparison. Currently have {len(all_cves)}.",
                "vendors_count": len(all_cves),
                "suggestion": "Analyze more vendors to enable comparative scoring."
            }
        
        # Calculate percentile
        percentile = cls.calculate_percentile(cve_count, all_cves)
        risk_info = cls.get_risk_from_percentile(percentile)
        
        # Get statistics for context
        stats = VendorRepository.get_statistics()
        
        # Calculate how many vendors are better/worse
        better_count = sum(1 for v in all_cves if v < cve_count)
        worse_count = sum(1 for v in all_cves if v > cve_count)
        equal_count = sum(1 for v in all_cves if v == cve_count)
        
        return {
            "available": True,
            "vendors_count": len(all_cves),
            "percentile": percentile,
            "risk_level": risk_info["level"],
            "status_text": f"{risk_info['status']} — {risk_info['description']}",
            "color": risk_info["color"],
            "recommendation": risk_info["recommendation"],
            "comparison": {
                "better_count": better_count,
                "worse_count": worse_count,
                "equal_count": equal_count,
                "better_percentage": round((better_count / len(all_cves)) * 100, 1) if all_cves else 0,
                "worse_percentage": round((worse_count / len(all_cves)) * 100, 1) if all_cves else 0
            },
            "statistics": stats
        }
    
    @classmethod
    def compare_by_industry(cls, vendor_name: str, industry: str, cve_count: int) -> Dict:
        """
        Compare a vendor against peers in the SAME industry.
        Falls back to global comparison if not enough peers.
        """
        # Get industry-specific CVE counts
        industry_cves = VendorRepository.get_all_cve_counts(industry)
        
        if len(industry_cves) < 2:
            # Not enough data for industry comparison
            global_result = cls.compare_global(vendor_name, cve_count)
            return {
                "available": False,
                "industry": industry,
                "peer_count": len(industry_cves),
                "message": f"Only {len(industry_cves)} vendors in '{industry}' industry. Using global comparison.",
                "fallback_to_global": True,
                "global_comparison": global_result if global_result.get("available") else None
            }
        
        # Calculate industry-specific percentile
        percentile = cls.calculate_percentile(cve_count, industry_cves)
        risk_info = cls.get_risk_from_percentile(percentile)
        
        # Get industry statistics
        stats = VendorRepository.get_statistics(industry)
        
        # Calculate better/worse counts
        better_count = sum(1 for v in industry_cves if v < cve_count)
        worse_count = sum(1 for v in industry_cves if v > cve_count)
        
        return {
            "available": True,
            "industry": industry,
            "peer_count": len(industry_cves),
            "percentile": percentile,
            "risk_level": risk_info["level"],
            "status_text": f"{risk_info['status']} — {risk_info['description']}",
            "color": risk_info["color"],
            "recommendation": risk_info["recommendation"],
            "comparison": {
                "better_count": better_count,
                "worse_count": worse_count,
                "better_percentage": round((better_count / len(industry_cves)) * 100, 1),
                "worse_percentage": round((worse_count / len(industry_cves)) * 100, 1)
            },
            "statistics": stats
        }
    
    @classmethod
    def get_full_comparison(cls, vendor_name: str, industry: str, cve_count: int) -> Dict:
        """
        Get complete comparative analysis including both global and industry views.
        This is the main method to call from the scoring engine.
        """
        global_result = cls.compare_global(vendor_name, cve_count)
        industry_result = cls.compare_by_industry(vendor_name, industry, cve_count)
        
        # Determine which risk level to use (prefer industry if available)
        if industry_result.get("available"):
            primary_risk = industry_result
            primary_type = "industry"
        elif global_result.get("available"):
            primary_risk = global_result
            primary_type = "global"
        else:
            primary_risk = {
                "available": False,
                "risk_level": "Medium",
                "status_text": "Insufficient data for comparison",
                "color": "#eab308",
                "recommendation": "Analyze more vendors to enable comparative scoring"
            }
            primary_type = "none"
        
        return {
            "available": global_result.get("available") or industry_result.get("available"),
            "primary_comparison_type": primary_type,
            "risk_level": primary_risk.get("risk_level", "Medium"),
            "status_text": primary_risk.get("status_text", "Comparative analysis unavailable"),
            "color": primary_risk.get("color", "#eab308"),
            "recommendation": primary_risk.get("recommendation", "Continue monitoring"),
            "global": global_result,
            "industry": industry_result,
            "database_stats": VendorRepository.get_industry_list()
        }
