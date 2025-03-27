// server.js - Express backend for browser fingerprinting

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const redis = require('redis');
const mysql = require('mysql2/promise');
const crypto = require('crypto');
const stringSimilarity = require('string-similarity');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// const LOCAL_IP = '172.21.19.159';
// Middleware
app.use(cors({ origin: "*" }));
app.use(bodyParser.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});


// Redis client setup
const redisClient = redis.createClient({
  url: process.env.REDIS_URL || 'redis://localhost:6379'
});

(async () => {
  try {
    await redisClient.connect();
    console.log('✅ Connected to Redis');
  } catch (err) {
    console.error('❌ Redis connection error:', err);
  }
})();

// MySQL connection setup
const mysqlPool = mysql.createPool({
  host: process.env.MYSQL_HOST || 'localhost',
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWORD || '12345678',
  database: process.env.MYSQL_DATABASE || 'fingerprint_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Initialize database tables
async function initializeDatabase() {
  try {
    const connection = await mysqlPool.getConnection();
    await connection.query(`
      CREATE TABLE IF NOT EXISTS fingerprints (
        id INT AUTO_INCREMENT PRIMARY KEY,
        fingerprint_hash VARCHAR(64) NOT NULL,
        user_agent TEXT,
        platform VARCHAR(255),
        cookie VARCHAR(255),
        canvas VARCHAR(64),
        webgl VARCHAR(64),
        public_ip VARCHAR(45),
        intranet_ip TEXT,
        color_depth VARCHAR(20),
        screen_resolution VARCHAR(50),
        timezone VARCHAR(50),
        language VARCHAR(50),
        fonts TEXT,
        plugins TEXT,
        local_storage BOOLEAN,
        indexed_db BOOLEAN,
        open_database BOOLEAN,
        do_not_track VARCHAR(10),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_visit TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        visit_count INT DEFAULT 1
      )
    `);
    connection.release();
    console.log('✅ Database initialized');
  } catch (err) {
    console.error('❌ Database initialization error:', err);
  }
}

initializeDatabase();

// AHP Feature weights from paper
const weights = {
  user_agent: 0.195,
  platform: 0.065,
  cookie: 0.043,
  canvas: 0.075,
  webgl: 0.065,
  public_ip: 0.033,
  intranet_ip: 0.033,
  color_depth: 0.033,
  screen_resolution: 0.033,
  timezone: 0.045,
  language: 0.11,
  fonts: 0.065,
  plugins: 0.04,
  local_storage: 0.033,
  indexed_db: 0.033,
  open_database: 0.033,
  do_not_track: 0.065
};

const thresholds = {
  user_agent: 0.8,
  fonts: 0.7,
  plugins: 0.7,
  default: 1.0
};

const FINGERPRINT_THRESHOLD = 0.75;

function calculateSimilarity(str1, str2) {
  if (!str1 || !str2) return 0;
  return stringSimilarity.compareTwoStrings(String(str1), String(str2));
}

async function compareFingerprints(newFp, storedFp) {
  if (newFp.fingerprint_hash === storedFp.fingerprint_hash) return true;

  if (newFp.cookie && storedFp.cookie && newFp.cookie === storedFp.cookie) return true;
  if (newFp.canvas && storedFp.canvas && newFp.canvas === storedFp.canvas) return true;

  if (newFp.public_ip === storedFp.public_ip &&
      newFp.intranet_ip && storedFp.intranet_ip &&
      newFp.intranet_ip.split('||').some(ip => storedFp.intranet_ip.includes(ip))) {
    return true;
  }

  const longFeatures = ['user_agent', 'fonts', 'plugins'];
  let judgeList = [];
  let totalWeight = 0;

  for (const feature in weights) {
    const threshold = thresholds[feature] || thresholds.default;
    if (!newFp[feature] || !storedFp[feature]) continue;

    totalWeight += weights[feature];
    let similarity = 0;

    if (longFeatures.includes(feature)) {
      similarity = calculateSimilarity(newFp[feature], storedFp[feature]);
      judgeList.push(similarity >= threshold ? weights[feature] : 0);
    } else {
      similarity = newFp[feature] === storedFp[feature] ? 1 : 0;
      judgeList.push(similarity * weights[feature]);
    }
  }

  const similarityScore = judgeList.reduce((sum, val) => sum + val, 0) / totalWeight;
  return similarityScore >= FINGERPRINT_THRESHOLD;
}

function sanitizeFingerprintData(fpData) {
  return {
    fingerprint_hash: fpData.fingerprint_hash,
    user_agent: String(fpData.user_agent || ''),
    platform: String(fpData.platform || ''),
    cookie: fpData.cookie || null,
    canvas: String(fpData.canvas || ''),
    webgl: String(fpData.webgl || ''),
    public_ip: String(fpData.public_ip || ''),
    intranet_ip: String(fpData.intranet_ip || ''),
    color_depth: String(fpData.color_depth || ''),
    screen_resolution: String(fpData.screen_resolution || ''),
    timezone: String(fpData.timezone || ''),
    language: String(fpData.language || ''),
    fonts: Array.isArray(fpData.fonts) ? fpData.fonts.join(', ') : String(fpData.fonts || ''),
    plugins: Array.isArray(fpData.plugins) ? fpData.plugins.join(', ') : String(fpData.plugins || ''),
    local_storage: fpData.local_storage ? 1 : 0,
    indexed_db: fpData.indexed_db ? 1 : 0,
    open_database: fpData.open_database ? 1 : 0,
    do_not_track: fpData.do_not_track || null
  };
}

app.post('/api/fingerprint', async (req, res) => {
  try {
    const rawData = req.body;
    const fpHash = crypto.createHash('sha256')
      .update(JSON.stringify(rawData))
      .digest('hex');

    rawData.fingerprint_hash = fpHash;
    const fpData = sanitizeFingerprintData(rawData);

    const cached = await redisClient.get(`fp:${fpHash}`);
    if (cached) {
      const parsed = JSON.parse(cached);
      const connection = await mysqlPool.getConnection();
      await connection.query(
        'UPDATE fingerprints SET visit_count = visit_count + 1, last_visit = NOW() WHERE id = ?',
        [parsed.id]
      );
      connection.release();

      return res.json({
        isNewVisitor: false,
        lastVisit: parsed.last_visit,
        visitCount: parsed.visit_count + 1
      });
    }

    const connection = await mysqlPool.getConnection();
    const [rows] = await connection.query('SELECT * FROM fingerprints');

    let matchFound = false;
    let matchedFp = null;

    for (const stored of rows) {
      if (await compareFingerprints(fpData, stored)) {
        matchFound = true;
        matchedFp = stored;
        break;
      }
    }

    if (matchFound) {
      await connection.query(
        'UPDATE fingerprints SET visit_count = visit_count + 1, last_visit = NOW() WHERE id = ?',
        [matchedFp.id]
      );

      await redisClient.set(`fp:${fpHash}`, JSON.stringify({
        id: matchedFp.id,
        last_visit: matchedFp.last_visit,
        visit_count: matchedFp.visit_count + 1
      }), { EX: 86400 });

      connection.release();

      return res.json({
        isNewVisitor: false,
        lastVisit: matchedFp.last_visit,
        visitCount: matchedFp.visit_count + 1
      });
    }

    const [insertResult] = await connection.query('INSERT INTO fingerprints SET ?', fpData);
    connection.release();

    await redisClient.set(`fp:${fpHash}`, JSON.stringify({
      id: insertResult.insertId,
      last_visit: new Date(),
      visit_count: 1
    }), { EX: 86400 });

    return res.json({
      isNewVisitor: true,
      visitCount: 1
    });

  } catch (error) {
    console.error('❌ Error processing fingerprint:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
