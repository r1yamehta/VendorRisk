const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const path = require('path');
const fs = require('fs');
const axios = require('axios');

const app = express();
const PORT = 5001;

app.use(cors());
app.use(express.json());

console.log('✅ Server starting...');

// Vendor database
const REAL_VENDORS = {
    'microsoft': { industry: 'SaaS', verified: true, aliases: ['ms', 'azure'] },
    'google': { industry: 'SaaS', verified: true, aliases: ['alphabet', 'gcp'] },
    'amazon': { industry: 'SaaS', verified: true, aliases: ['aws'] },
    'apple': { industry: 'SaaS', verified: true, aliases: [] },
    'paypal': { industry: 'FinTech', verified: true, aliases: [] },
    'oracle': { industry: 'SaaS', verified: true, aliases: [] },
    'ibm': { industry: 'SaaS', verified: true, aliases: [] },
    'salesforce': { industry: 'SaaS', verified: true, aliases: [] },
    'adobe': { industry: 'SaaS', verified: true, aliases: [] },
    'stripe': { industry: 'FinTech', verified: true, aliases: [] },
    'visa': { industry: 'Finance', verified: true, aliases: [] },
    'mastercard': { industry: 'Finance', verified: true, aliases: [] },
    'crowdstrike': { industry: 'Cybersecurity', verified: true, aliases: [] },
    'cloudflare': { industry: 'Cybersecurity', verified: true, aliases: [] },
    'netflix': { industry: 'SaaS', verified: true, aliases: [] },
    'spotify': { industry: 'SaaS', verified: true, aliases: [] },
    'uber': { industry: 'SaaS', verified: true, aliases: [] },
    'zoom': { industry: 'SaaS', verified: true, aliases: [] },
    'slack': { industry: 'SaaS', verified: true, aliases: [] },
    'atlassian': { industry: 'SaaS', verified: true, aliases: ['jira', 'confluence'] }
};

function validateVendor(vendorName) {
    const normalized = vendorName.toLowerCase().trim();
    
    if (REAL_VENDORS[normalized]) {
        return { valid: true, vendor: REAL_VENDORS[normalized], name: normalized };
    }
    
    for (const [key, value] of Object.entries(REAL_VENDORS)) {
        if (value.aliases && value.aliases.some(alias => normalized.includes(alias) || alias.includes(normalized))) {
            return { valid: true, vendor: value, name: key };
        }
    }
    
    for (const [key, value] of Object.entries(REAL_VENDORS)) {
        if (normalized.includes(key) || key.includes(normalized)) {
            return { valid: true, vendor: value, name: key };
        }
    }
    
    const suggestions = Object.keys(REAL_VENDORS).slice(0, 10).map(v => v.charAt(0).toUpperCase() + v.slice(1));
    return { valid: false, message: `"${vendorName}" is not recognized`, suggestions: suggestions };
}

function calculateRiskScore(nvdData, industry) {
    const vulnCount = nvdData.totalResults || 0;
    
    let cvssScores = [];
    let criticalCount = 0;
    let highCount = 0;
    
    if (nvdData.vulnerabilities && nvdData.vulnerabilities.length > 0) {
        cvssScores = nvdData.vulnerabilities.map(v => {
            const metrics = v.cve?.metrics;
            const score = metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ||
                         metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore || 5;
            if (score >= 9.0) criticalCount++;
            else if (score >= 7.0) highCount++;
            return score;
        });
    }
    
    const avgSeverity = cvssScores.length > 0 ? cvssScores.reduce((a,b) => a + b, 0) / cvssScores.length : 5.5;
    
    let countScore = vulnCount === 0 ? 5 : (vulnCount < 10 ? 10 : (vulnCount < 50 ? 15 : (vulnCount < 100 ? 20 : 25)));
    let severityScore = (avgSeverity / 10) * 25;
    let criticalScore = criticalCount > 10 ? 20 : (criticalCount > 5 ? 15 : (criticalCount > 0 ? 10 : 5));
    let recentScore = highCount > 0 ? 10 : 5;
    
    const industryMultipliers = { 
        'Finance': 1.4, 'Healthcare': 1.35, 'Government': 1.45, 
        'FinTech': 1.3, 'Cybersecurity': 1.2, 'SaaS': 1.0, 
        'Retail': 1.1, 'Manufacturing': 0.9, 'Education': 0.85 
    };
    let industryScore = 15 * ((industryMultipliers[industry] || 1.0) - 0.7);
    
    let finalScore = Math.min(100, Math.max(0, Math.round(countScore + severityScore + criticalScore + recentScore + industryScore)));
    let riskLevel = finalScore >= 70 ? 'High' : (finalScore >= 40 ? 'Medium' : 'Low');
    
    return {
        score: finalScore, level: riskLevel,
        details: { totalVulns: vulnCount, avgSeverity: avgSeverity.toFixed(1), criticalCount, highCount },
        factors: { 
            countScore: Math.round(countScore), 
            severityScore: Math.round(severityScore), 
            criticalScore: Math.round(criticalScore), 
            recentScore: Math.round(recentScore), 
            industryScore: Math.round(industryScore) 
        }
    };
}

// Database setup
let db = null;

async function setupDatabase() {
    try {
        const dbDir = path.join(__dirname, 'database');
        if (!fs.existsSync(dbDir)) {
            fs.mkdirSync(dbDir, { recursive: true });
            console.log('✅ Created database folder');
        }
        
        const dbPath = path.join(dbDir, 'vendors.db');
        
        db = await open({
            filename: dbPath,
            driver: sqlite3.Database
        });
        
        // Create main vendors table
        await db.exec(`
            CREATE TABLE IF NOT EXISTS vendors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                industry TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                vulnerabilities INTEGER DEFAULT 0,
                avg_severity REAL DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                factor_breakdown TEXT,
                date TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // ⚠️ NEW: Create vendor history table for tracking changes
        await db.exec(`
            CREATE TABLE IF NOT EXISTS vendor_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vendor_id INTEGER,
                risk_score INTEGER,
                risk_level TEXT,
                vulnerabilities INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (vendor_id) REFERENCES vendors(id)
            )
        `);
        
        // ⚠️ NEW: Create risk alerts table
        await db.exec(`
            CREATE TABLE IF NOT EXISTS risk_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vendor_id INTEGER,
                vendor_name TEXT,
                alert_type TEXT,
                message TEXT,
                severity TEXT,
                is_read INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        console.log('✅ Database ready with monitoring tables');
        return true;
    } catch (error) {
        console.error('❌ Database error:', error.message);
        return false;
    }
}

// ⚠️ NEW: Function to create alert
async function createAlert(vendorId, vendorName, alertType, message, severity) {
    if (!db) return;
    try {
        await db.run(
            `INSERT INTO risk_alerts (vendor_id, vendor_name, alert_type, message, severity)
             VALUES (?, ?, ?, ?, ?)`,
            [vendorId, vendorName, alertType, message, severity]
        );
        console.log(`🔔 Alert created for ${vendorName}: ${message}`);
    } catch (error) {
        console.error('Alert creation error:', error);
    }
}

// ⚠️ NEW: Save vendor history snapshot
async function saveVendorHistory(vendorId, riskScore, riskLevel, vulnerabilities) {
    if (!db) return;
    try {
        await db.run(
            `INSERT INTO vendor_history (vendor_id, risk_score, risk_level, vulnerabilities)
             VALUES (?, ?, ?, ?)`,
            [vendorId, riskScore, riskLevel, vulnerabilities]
        );
    } catch (error) {
        console.error('History save error:', error);
    }
}

// ⚠️ NEW: Check for new vulnerabilities (Real-time monitoring)
app.post('/api/monitor/check', async (req, res) => {
    try {
        const { vendorId, vendorName } = req.body;
        
        console.log(`🔍 Checking vendor: ${vendorName}`);
        
        // Fetch latest CVE data from NVD
        const response = await axios.get(
            `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(vendorName)}&resultsPerPage=20`,
            { timeout: 10000 }
        );
        
        const newVulnCount = response.data.totalResults || 0;
        
        // Get current vendor data from database
        const currentVendor = await db.get('SELECT * FROM vendors WHERE id = ?', [vendorId]);
        
        if (!currentVendor) {
            return res.json({ success: false, error: 'Vendor not found' });
        }
        
        const oldVulnCount = currentVendor.vulnerabilities || 0;
        const newVulnerabilities = newVulnCount - oldVulnCount;
        
        // Check for new critical vulnerabilities
        let hasNewCritical = false;
        if (response.data.vulnerabilities) {
            for (const vuln of response.data.vulnerabilities) {
                const metrics = vuln.cve?.metrics;
                const score = metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ||
                             metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore || 0;
                if (score >= 9.0) {
                    hasNewCritical = true;
                    break;
                }
            }
        }
        
        // Create alerts if new vulnerabilities found
        if (newVulnerabilities > 0) {
            await createAlert(
                vendorId, vendorName, 'NEW_VULNERABILITIES',
                `${newVulnerabilities} new vulnerability(s) detected for ${vendorName}`,
                newVulnerabilities > 5 ? 'Critical' : 'Warning'
            );
        }
        
        if (hasNewCritical) {
            await createAlert(
                vendorId, vendorName, 'CRITICAL_CVE',
                `New critical vulnerability detected for ${vendorName}. Immediate attention required!`,
                'Critical'
            );
        }
        
        // Update vendor data if changed
        if (newVulnerabilities !== 0) {
            // Recalculate risk score with new data
            const riskResult = calculateRiskScore(response.data, currentVendor.industry);
            
            await db.run(
                `UPDATE vendors SET 
                    vulnerabilities = ?, 
                    risk_score = ?, 
                    risk_level = ?,
                    critical_count = ?
                 WHERE id = ?`,
                [newVulnCount, riskResult.score, riskResult.level, riskResult.details.criticalCount, vendorId]
            );
            
            // Save to history
            await saveVendorHistory(vendorId, riskResult.score, riskResult.level, newVulnCount);
        }
        
        res.json({
            success: true,
            newVulnerabilities: Math.max(0, newVulnerabilities),
            hasNewCritical: hasNewCritical,
            totalVulns: newVulnCount,
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        console.error('Monitor check error:', error);
        res.json({ success: false, error: error.message });
    }
});

// ⚠️ NEW: Get all alerts
app.get('/api/alerts', async (req, res) => {
    try {
        if (!db) return res.json({ success: true, data: [] });
        const alerts = await db.all(`
            SELECT * FROM risk_alerts 
            ORDER BY created_at DESC 
            LIMIT 20
        `);
        res.json({ success: true, data: alerts });
    } catch (error) {
        res.json({ success: true, data: [] });
    }
});

// ⚠️ NEW: Mark alert as read
app.put('/api/alerts/:id/read', async (req, res) => {
    try {
        await db.run('UPDATE risk_alerts SET is_read = 1 WHERE id = ?', [req.params.id]);
        res.json({ success: true });
    } catch (error) {
        res.json({ success: false });
    }
});

// ⚠️ NEW: Get vendor risk history (for trend analysis)
app.get('/api/vendor/:id/history', async (req, res) => {
    try {
        const history = await db.all(`
            SELECT risk_score, risk_level, vulnerabilities, created_at 
            FROM vendor_history 
            WHERE vendor_id = ? 
            ORDER BY created_at DESC 
            LIMIT 10
        `, [req.params.id]);
        res.json({ success: true, data: history });
    } catch (error) {
        res.json({ success: false, data: [] });
    }
});

// ⚠️ NEW: Get risk summary (for dashboard stats)
app.get('/api/risk-summary', async (req, res) => {
    try {
        const highRisk = await db.get('SELECT COUNT(*) as count FROM vendors WHERE risk_level = "High"');
        const mediumRisk = await db.get('SELECT COUNT(*) as count FROM vendors WHERE risk_level = "Medium"');
        const lowRisk = await db.get('SELECT COUNT(*) as count FROM vendors WHERE risk_level = "Low"');
        const unreadAlerts = await db.get('SELECT COUNT(*) as count FROM risk_alerts WHERE is_read = 0');
        
        res.json({
            success: true,
            data: {
                high: highRisk?.count || 0,
                medium: mediumRisk?.count || 0,
                low: lowRisk?.count || 0,
                unreadAlerts: unreadAlerts?.count || 0
            }
        });
    } catch (error) {
        res.json({ success: true, data: { high: 0, medium: 0, low: 0, unreadAlerts: 0 } });
    }
});

// API Routes (Existing)
app.get('/api/test', (req, res) => {
    res.json({ message: 'Backend working!', status: 'online', timestamp: new Date().toISOString() });
});

app.post('/api/analyze', async (req, res) => {
    try {
        let { vendorName, industry } = req.body;
        
        if (!vendorName || !industry) {
            return res.status(400).json({ success: false, error: 'Missing vendorName or industry' });
        }
        
        const validation = validateVendor(vendorName);
        if (!validation.valid) {
            return res.status(400).json({ success: false, error: validation.message, suggestions: validation.suggestions });
        }
        
        const verifiedName = validation.name.charAt(0).toUpperCase() + validation.name.slice(1);
        console.log(`📊 Analyzing: ${verifiedName} (${industry})`);
        
        let nvdData = { totalResults: 0, vulnerabilities: [] };
        try {
            const response = await axios.get(
                `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(verifiedName)}&resultsPerPage=30`,
                { timeout: 10000 }
            );
            nvdData = response.data;
            console.log(`📊 Found ${nvdData.totalResults || 0} vulnerabilities`);
        } catch(e) { 
            console.log('⚠️ NVD API fallback used');
        }
        
        const riskResult = calculateRiskScore(nvdData, industry);
        
        let vendorId = null;
        if (db) {
            const result = await db.run(
                `INSERT INTO vendors (name, industry, risk_score, risk_level, vulnerabilities, avg_severity, critical_count, factor_breakdown, date)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [verifiedName, industry, riskResult.score, riskResult.level, 
                 riskResult.details.totalVulns, riskResult.details.avgSeverity, 
                 riskResult.details.criticalCount, JSON.stringify(riskResult.factors), new Date().toLocaleDateString()]
            );
            vendorId = result.lastID;
            
            // ⚠️ NEW: Save initial history
            await saveVendorHistory(vendorId, riskResult.score, riskResult.level, riskResult.details.totalVulns);
            
            console.log(`✅ Saved ${verifiedName} to database`);
        }
        
        res.json({
            success: true, 
            vendorName: verifiedName, 
            industry: industry,
            riskScore: riskResult.score, 
            riskLevel: riskResult.level,
            vulnerabilities: riskResult.details.totalVulns, 
            avgSeverity: riskResult.details.avgSeverity,
            criticalCount: riskResult.details.criticalCount, 
            highCount: riskResult.details.highCount,
            factorBreakdown: riskResult.factors
        });
        
    } catch (error) {
        console.error('❌ Analysis error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/vendors', async (req, res) => {
    try {
        if (!db) return res.json({ success: true, data: [] });
        const vendors = await db.all('SELECT * FROM vendors ORDER BY id DESC');
        res.json({ success: true, data: vendors });
    } catch (error) {
        console.error('Fetch error:', error);
        res.json({ success: true, data: [] });
    }
});

app.delete('/api/vendors/:id', async (req, res) => {
    try {
        if (db) {
            await db.run('DELETE FROM vendors WHERE id = ?', [req.params.id]);
            console.log(`🗑️ Deleted vendor ID: ${req.params.id}`);
        }
        res.json({ success: true });
    } catch (error) {
        res.json({ success: false });
    }
});

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

// Start server
async function startServer() {
    await setupDatabase();
    app.listen(PORT, () => {
        const vendorCount = Object.keys(REAL_VENDORS).length;
        console.log(`
    ╔═══════════════════════════════════════════════════════╗
    ║   🛡️  VendorRisk Backend Running (with Monitoring)    ║
    ╠═══════════════════════════════════════════════════════╣
    ║   Port: ${PORT}                                           ║
    ║   Database: ${db ? '✅ Connected' : '⚠️ Memory Mode'}        ║
    ╠═══════════════════════════════════════════════════════╣
    ║   Features:                                           ║
    ║   - ✅ Vendor Validation (${vendorCount} vendors)         ║
    ║   - ✅ Multi-Factor Risk Scoring (5 factors)          ║
    ║   - ✅ Real NVD Data Integration                      ║
    ║   - ✅ Real-time Monitoring (NEW!)                    ║
    ║   - ✅ Risk Alerts System (NEW!)                      ║
    ║   - ✅ Vendor History Tracking (NEW!)                 ║
    ╚═══════════════════════════════════════════════════════╝
        `);
    });
}

startServer();