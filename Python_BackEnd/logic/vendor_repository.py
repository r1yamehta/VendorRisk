"""
vendor_repository.py
====================
Database access layer for Python backend.
Reads vendor data from shared vendors.db to enable comparative analysis.
"""

import sqlite3
import os
from typing import List, Dict, Optional
from pathlib import Path


class VendorRepository:
    """Handles all database read operations for vendor comparison."""
    
    # Database path (relative to Python_BackEnd folder)
    DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), '..', 'BACKENDD', 'database', 'vendors.db')
    
    @classmethod
    def _get_connection(cls) -> Optional[sqlite3.Connection]:
        """
        Establish connection to shared vendors.db.
        Returns None if connection fails.
        """
        try:
            # Resolve absolute path for better error messages
            abs_path = os.path.abspath(cls.DB_PATH)
            
            # Check if file exists
            if not os.path.exists(abs_path):
                print(f"⚠️ Database not found at: {abs_path}")
                return None
            
            conn = sqlite3.connect(abs_path)
            conn.row_factory = sqlite3.Row  # Return dict-like rows
            return conn
        except Exception as e:
            print(f"❌ Database connection error: {e}")
            return None
    
    @classmethod
    def get_all_vendors(cls) -> List[Dict]:
        """
        Fetch all vendors from database.
        Returns list of vendor dictionaries.
        """
        conn = cls._get_connection()
        if not conn:
            return []
        
        try:
            cursor = conn.execute("""
                SELECT 
                    id, 
                    name, 
                    industry, 
                    risk_score, 
                    risk_level,
                    vulnerabilities,
                    critical_count,
                    avg_severity,
                    date
                FROM vendors 
                ORDER BY created_at DESC
            """)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except Exception as e:
            print(f"❌ Query error: {e}")
            return []
        finally:
            conn.close()
    
    @classmethod
    def get_vendor_by_id(cls, vendor_id: int) -> Optional[Dict]:
        """Fetch a single vendor by ID."""
        conn = cls._get_connection()
        if not conn:
            return None
        
        try:
            cursor = conn.execute(
                "SELECT id, name, industry, vulnerabilities, risk_score FROM vendors WHERE id = ?",
                (vendor_id,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None
        except Exception as e:
            print(f"❌ Query error: {e}")
            return None
        finally:
            conn.close()
    
    @classmethod
    def get_all_cve_counts(cls, industry: Optional[str] = None) -> List[int]:
        """
        Get list of CVE counts from all vendors (or filtered by industry).
        Returns empty list if no data.
        """
        conn = cls._get_connection()
        if not conn:
            return []
        
        try:
            if industry:
                cursor = conn.execute(
                    "SELECT vulnerabilities FROM vendors WHERE industry = ? AND vulnerabilities IS NOT NULL",
                    (industry,)
                )
            else:
                cursor = conn.execute(
                    "SELECT vulnerabilities FROM vendors WHERE vulnerabilities IS NOT NULL"
                )
            
            rows = cursor.fetchall()
            return [row['vulnerabilities'] for row in rows if row['vulnerabilities'] is not None]
        except Exception as e:
            print(f"❌ Query error: {e}")
            return []
        finally:
            conn.close()
    
    @classmethod
    def get_all_risk_scores(cls) -> List[int]:
        """Get list of all risk scores for distribution analysis."""
        conn = cls._get_connection()
        if not conn:
            return []
        
        try:
            cursor = conn.execute("SELECT risk_score FROM vendors WHERE risk_score IS NOT NULL")
            rows = cursor.fetchall()
            return [row['risk_score'] for row in rows]
        except Exception as e:
            print(f"❌ Query error: {e}")
            return []
        finally:
            conn.close()
    
    @classmethod
    def get_statistics(cls, industry: Optional[str] = None) -> Dict:
        """
        Calculate statistical summary of vendor data.
        Returns min, max, median, mean, and count.
        """
        cve_counts = cls.get_all_cve_counts(industry)
        
        if not cve_counts:
            return {
                "count": 0,
                "min": 0,
                "max": 0,
                "median": 0,
                "mean": 0,
                "has_data": False
            }
        
        sorted_counts = sorted(cve_counts)
        count = len(sorted_counts)
        
        # Calculate median
        if count % 2 == 0:
            median = (sorted_counts[count//2 - 1] + sorted_counts[count//2]) / 2
        else:
            median = sorted_counts[count//2]
        
        return {
            "count": count,
            "min": sorted_counts[0],
            "max": sorted_counts[-1],
            "median": round(median, 1),
            "mean": round(sum(sorted_counts) / count, 1),
            "has_data": count >= 3  # Need at least 3 for meaningful comparison
        }
    
    @classmethod
    def get_industry_list(cls) -> List[Dict]:
        """Get list of all industries with vendor counts."""
        conn = cls._get_connection()
        if not conn:
            return []
        
        try:
            cursor = conn.execute("""
                SELECT 
                    industry, 
                    COUNT(*) as count,
                    AVG(vulnerabilities) as avg_cves,
                    AVG(risk_score) as avg_risk
                FROM vendors 
                WHERE industry IS NOT NULL
                GROUP BY industry
                ORDER BY count DESC
            """)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except Exception as e:
            print(f"❌ Query error: {e}")
            return []
        finally:
            conn.close()
