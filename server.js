const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Rate limiting
const keyGenLimit = rateLimit({
    windowMs: 24 * 60 * 60 * 1000, // 24 hours
    max: 1, // Limit each IP to 1 key generation per 24 hours
    message: { 
        success: false, 
        error: 'Key generation limit reached. You can only generate 1 key per 24 hours.' 
    },
    standardHeaders: true,
    legacyHeaders: false,
});

const keyValidateLimit = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 50, // Limit each IP to 50 validation requests per 15 minutes
    message: { 
        success: false, 
        error: 'Too many validation requests. Please try again later.' 
    }
});

// Database file path (in production, use a proper database)
const DB_FILE = path.join(__dirname, 'keys_database.json');

// Initialize database
async function initializeDatabase() {
    try {
        await fs.access(DB_FILE);
    } catch (error) {
        // File doesn't exist, create it
        await fs.writeFile(DB_FILE, JSON.stringify({ keys: {} }), 'utf8');
        console.log('Database file created');
    }
}

// Read database
async function readDatabase() {
    try {
        const data = await fs.readFile(DB_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('Error reading database:', error);
        return { keys: {} };
    }
}

// Write database
async function writeDatabase(data) {
    try {
        await fs.writeFile(DB_FILE, JSON.stringify(data, null, 2), 'utf8');
    } catch (error) {
        console.error('Error writing database:', error);
        throw error;
    }
}

// Generate secure key
function generateSecureKey() {
    const segments = [];
    for (let i = 0; i < 4; i++) {
        segments.push(crypto.randomBytes(3).toString('hex').toUpperCase());
    }
    return 'FREE_' + segments.join('-');
}

// Clean expired keys (run periodically)
async function cleanExpiredKeys() {
    try {
        const db = await readDatabase();
        const now = Date.now();
        const validKeys = {};
        
        let expiredCount = 0;
        for (const [key, data] in Object.entries(db.keys)) {
            if (now - data.generatedAt < 24 * 60 * 60 * 1000) { // 24 hours
                validKeys[key] = data;
            } else {
                expiredCount++;
            }
        }
        
        if (expiredCount > 0) {
            await writeDatabase({ keys: validKeys });
            console.log(`Cleaned ${expiredCount} expired keys`);
        }
    } catch (error) {
        console.error('Error cleaning expired keys:', error);
    }
}

// Validate tasks completion (mock validation - in production, verify with actual APIs)
function validateTasksCompletion(tasksData) {
    // In a real implementation, you would:
    // 1. Verify YouTube subscription/like via YouTube API
    // 2. Verify Discord join via Discord API
    // For now, we'll use simple validation based on provided data
    
    const { task1Completed, task2Completed, timestamp } = tasksData;
    const now = Date.now();
    
    // Check if tasks were completed recently (within last 30 minutes)
    if (!timestamp || now - timestamp > 30 * 60 * 1000) {
        return false;
    }
    
    return task1Completed && task2Completed;
}

// Routes

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Generate key endpoint
app.post('/api/generate-key', keyGenLimit, async (req, res) => {
    try {
        const { tasksData, userFingerprint } = req.body;
        
        // Validate required data
        if (!tasksData || !userFingerprint) {
            return res.status(400).json({
                success: false,
                error: 'Missing required data'
            });
        }
        
        // Validate tasks completion
        if (!validateTasksCompletion(tasksData)) {
            return res.status(400).json({
                success: false,
                error: 'Tasks not completed or expired'
            });
        }
        
        const db = await readDatabase();
        const clientIP = req.ip || req.connection.remoteAddress;
        const now = Date.now();
        
        // Check if IP or fingerprint already generated a key in last 24 hours
        for (const [key, data] of Object.entries(db.keys)) {
            if ((data.ip === clientIP || data.fingerprint === userFingerprint) && 
                (now - data.generatedAt < 24 * 60 * 60 * 1000)) {
                return res.status(429).json({
                    success: false,
                    error: 'You have already generated a key. Wait 24 hours before generating another.',
                    existingKey: key,
                    expiresAt: data.generatedAt + (24 * 60 * 60 * 1000)
                });
            }
        }
        
        // Generate new key
        const newKey = generateSecureKey();
        
        // Store key in database
        db.keys[newKey] = {
            generatedAt: now,
            ip: clientIP,
            fingerprint: userFingerprint,
            used: false,
            usageCount: 0,
            lastUsed: null
        };
        
        await writeDatabase(db);
        
        console.log(`Key generated: ${newKey} for IP: ${clientIP}`);
        
        res.json({
            success: true,
            key: newKey,
            expiresAt: now + (24 * 60 * 60 * 1000),
            message: 'Key generated successfully! Valid for 24 hours.'
        });
        
    } catch (error) {
        console.error('Error generating key:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Validate key endpoint
app.post('/api/validate-key', keyValidateLimit, async (req, res) => {
    try {
        const { key, userFingerprint } = req.body;
        
        if (!key || !userFingerprint) {
            return res.status(400).json({
                success: false,
                error: 'Missing key or user fingerprint'
            });
        }
        
        const db = await readDatabase();
        const now = Date.now();
        
        // Check if key exists
        if (!db.keys[key]) {
            return res.status(401).json({
                success: false,
                error: 'Invalid key'
            });
        }
        
        const keyData = db.keys[key];
        
        // Check if key is expired
        if (now - keyData.generatedAt >= 24 * 60 * 60 * 1000) {
            // Remove expired key
            delete db.keys[key];
            await writeDatabase(db);
            
            return res.status(401).json({
                success: false,
                error: 'Key has expired'
            });
        }
        
        // Update usage statistics
        keyData.used = true;
        keyData.usageCount += 1;
        keyData.lastUsed = now;
        await writeDatabase(db);
        
        const timeLeft = (keyData.generatedAt + (24 * 60 * 60 * 1000)) - now;
        const hoursLeft = Math.floor(timeLeft / (60 * 60 * 1000));
        const minutesLeft = Math.floor((timeLeft % (60 * 60 * 1000)) / (60 * 1000));
        
        console.log(`Key validated: ${key} (${keyData.usageCount} uses)`);
        
        res.json({
            success: true,
            message: `Key is valid! Expires in ${hoursLeft}h ${minutesLeft}m`,
            expiresAt: keyData.generatedAt + (24 * 60 * 60 * 1000),
            usageCount: keyData.usageCount,
            timeLeft: {
                hours: hoursLeft,
                minutes: minutesLeft
            }
        });
        
    } catch (error) {
        console.error('Error validating key:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Admin endpoint to list keys (add proper authentication in production)
app.get('/api/admin/keys', async (req, res) => {
    try {
        // Add proper authentication here
        const authHeader = req.headers.authorization;
        if (!authHeader || authHeader !== 'Bearer your-admin-secret-token') {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        
        const db = await readDatabase();
        const now = Date.now();
        
        const keyStats = Object.entries(db.keys).map(([key, data]) => ({
            key: key.substring(0, 10) + '...',
            generatedAt: new Date(data.generatedAt).toISOString(),
            expired: (now - data.generatedAt) >= 24 * 60 * 60 * 1000,
            used: data.used,
            usageCount: data.usageCount,
            lastUsed: data.lastUsed ? new Date(data.lastUsed).toISOString() : null
        }));
        
        res.json({
            totalKeys: keyStats.length,
            keys: keyStats
        });
        
    } catch (error) {
        console.error('Error fetching admin data:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Start server
async function startServer() {
    await initializeDatabase();
    
    // Clean expired keys every hour
    setInterval(cleanExpiredKeys, 60 * 60 * 1000);
    
    app.listen(PORT, () => {
        console.log(`🚀 Key System API Server running on port ${PORT}`);
        console.log(`📊 Health check: http://localhost:${PORT}/health`);
        console.log(`🔑 Generate key: POST http://localhost:${PORT}/api/generate-key`);
        console.log(`✅ Validate key: POST http://localhost:${PORT}/api/validate-key`);
    });
}

startServer().catch(console.error);

module.exports = app;
