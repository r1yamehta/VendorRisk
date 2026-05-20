app.get('/api/stats', async (req, res) => {
    try {
        if (!db) return res.json({ total: 0, high: 0, medium: 0, low: 0 });
        const total = await db.get('SELECT COUNT(*) as count FROM vendors');
        const high = await db.get('SELECT COUNT(*) as count FROM vendors WHERE risk_level = "High"');
        const medium = await db.get('SELECT COUNT(*) as count FROM vendors WHERE risk_level = "Medium"');
        const low = await db.get('SELECT COUNT(*) as count FROM vendors WHERE risk_level = "Low"');
        res.json({ 
            total: total?.count || 0, 
            high: high?.count || 0, 
            medium: medium?.count || 0, 
            low: low?.count || 0 
        });
    } catch (error) {
        res.json({ total: 0, high: 0, medium: 0, low: 0 });
    }
});

// ⚠️ NEW: Get comparative statistics about the database
app.get('/api/comparative-stats', async (req, res) => {
    try {
        if (!db) {
            return res.json({ success: false, error: 'Database not connected' });
        }
        
        // Get total vendor count
        const totalResult = await db.get('SELECT COUNT(*) as count FROM vendors');
        const totalVendors = totalResult?.count || 0;
        
        // Get vendors by industry
        const byIndustry = await db.all(`
            SELECT 
                industry, 
                COUNT(*) as count,
                AVG(vulnerabilities) as avg_cves,
                AVG(risk_score) as avg_risk,
                MIN(risk_score) as min_risk,
                MAX(risk_score) as max_risk
            FROM vendors 
            WHERE industry IS NOT NULL AND industry != ''
            GROUP BY industry
            ORDER BY count DESC
        `);
        
        // Get risk level distribution
        const riskDistribution = await db.all(`
            SELECT 
                risk_level, 
                COUNT(*) as count,
                ROUND(CAST(COUNT(*) AS FLOAT) / (SELECT COUNT(*) FROM vendors) * 100, 1) as percentage
            FROM vendors 
            WHERE risk_level IS NOT NULL
            GROUP BY risk_level
        `);
        
        // Get CVE distribution percentiles
        const allCVEs = await db.all(`
            SELECT vulnerabilities FROM vendors WHERE vulnerabilities IS NOT NULL ORDER BY vulnerabilities ASC
        `);
        
        const cveValues = allCVEs.map(v => v.vulnerabilities);
        const percentiles = {
            p10: cveValues[Math.floor(cveValues.length * 0.1)] || 0,
            p25: cveValues[Math.floor(cveValues.length * 0.25)] || 0,
            p50: cveValues[Math.floor(cveValues.length * 0.5)] || 0,
            p75: cveValues[Math.floor(cveValues.length * 0.75)] || 0,
            p90: cveValues[Math.floor(cveValues.length * 0.9)] || 0,
        };
        
        // Get recent activity (last 7 days)
        const weekAgo = new Date();
        weekAgo.setDate(weekAgo.getDate() - 7);
        const recentActivity = await db.get(`
            SELECT COUNT(*) as count FROM vendors WHERE created_at > datetime(?)
        `, [weekAgo.toISOString()]);
        
        res.json({
            success: true,
            data: {
                total_vendors: totalVendors,
                by_industry: byIndustry,
                risk_distribution: riskDistribution,
                cve_percentiles: percentiles,
                recent_activity: {
                    last_7_days: recentActivity?.count || 0
                },
                comparative_ready: totalVendors >= 3,
                message: totalVendors < 3 ? 
                    `Need at least 3 vendors for meaningful comparison. Currently have ${totalVendors}.` : 
                    'Comparative data available'
            }
        });
        
    } catch (error) {
        console.error('Comparative stats error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});
