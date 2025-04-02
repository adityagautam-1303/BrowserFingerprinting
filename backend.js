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


app.use(cors({ origin: "*" }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});



const redisClient = redis.createClient({
  username: 'default',
  password: 'XQqscuhOE5uIwLW9U9RrHCagRrWjbntJ',
  socket: {
      host: 'redis-18020.c124.us-central1-1.gce.redns.redis-cloud.com',
      port: 18020
  }
});


(async () => {
  try {
    await redisClient.connect();
    console.log('✅ Connected to Redis');
  } catch (err) {
    console.error('❌ Redis connection error:', err);
  }
})();


const mysqlPool = mysql.createPool({
  host: 'bepq8mqhgapuxh61kegn-mysql.services.clever-cloud.com',
  user: 'ud3ombl3zt3gcbgh',
  password: 'X8WvBRQkm7X3ELSTayOQ',
  database: 'bepq8mqhgapuxh61kegn',
  waitForConnections: true,
  connectionLimit: 5,
  queueLimit: 0
});


async function initializeDatabase() {
  try {
    const connection = await mysqlPool.getConnection();
    await connection.query(`
      CREATE TABLE IF NOT EXISTS fingerprints (
        id INT AUTO_INCREMENT PRIMARY KEY,
        fingerprint_hash VARCHAR(64) NOT NULL,
        user_agent TEXT,
        platform VARCHAR(255),
        canvas VARCHAR(64),
        webgl VARCHAR(64),
        public_ip VARCHAR(45),
        color_depth VARCHAR(20),
        screen_resolution VARCHAR(50),
        timezone VARCHAR(50),
        language VARCHAR(50),
        fonts TEXT,
        plugins TEXT,
        local_storage BOOLEAN,
        indexed_db BOOLEAN,
        open_database BOOLEAN,
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


const weights = {
  user_agent: 0.227,
  platform: 0.076,
  canvas: 0.087,
  webgl: 0.076,
  public_ip: 0.038,
  color_depth: 0.038,
  screen_resolution: 0.038,
  timezone: 0.052,
  language: 0.128,
  fonts: 0.076,
  plugins: 0.047,
  local_storage: 0.038,
  indexed_db: 0.038,
  open_database: 0.038,
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

  return similarityScore ;
}

function sanitizeFingerprintData(fpData) {
  return {
    fingerprint_hash: fpData.fingerprint_hash,
    user_agent: String(fpData.userAgent || ''),
    platform: String(fpData.platform || ''),
    canvas: String(fpData.canvas || ''),
    webgl: String(fpData.webgl || ''),
    public_ip: String(fpData.public_ip || ''),
    color_depth: String(fpData.color_depth || ''),
    screen_resolution: String(fpData.screen_resolution || ''),
    timezone: String(fpData.timezone || ''),
    language: String(fpData.language || ''),
    fonts: Array.isArray(fpData.fonts) ? fpData.fonts.join(', ') : String(fpData.fonts || ''),
    plugins: Array.isArray(fpData.plugins) ? fpData.plugins.join(', ') : String(fpData.plugins || ''),
    local_storage: fpData.local_storage ? 1 : 0,
    indexed_db: fpData.indexed_db ? 1 : 0,
    open_database: fpData.open_database ? 1: 0,
  };
}


app.post('/api/fingerprint', async (req, res) => {
  try {
    const rawData = req.body;
    const fpHash = crypto.createHash('sha256').update(JSON.stringify(rawData)).digest('hex');
    rawData.fingerprint_hash = fpHash;
    const fpData = sanitizeFingerprintData(rawData);


    const cached = await redisClient.get(`fp:${fpHash}`);

    let similarity_result=0;
    if (cached) {
      const parsed = JSON.parse(cached);
      const connection = await mysqlPool.getConnection();
      const last_visits = await connection.query('SELECT last_visit FROM fingerprints WHERE id = ?',
        [parsed.id]);
      await connection.query(
        'UPDATE fingerprints SET visit_count = visit_count + 1, last_visit = NOW() WHERE id = ?',
        [parsed.id]
      );
      similarity_result = 1;
      const visits= await connection.query('SELECT visit_count FROM fingerprints WHERE id = ?',
        [parsed.id]);

      const last_visits1 = await connection.query('SELECT last_visit FROM fingerprints WHERE id = ?',
          [parsed.id]);

      connection.release();

      await redisClient.set(`fp:${fpHash}`, JSON.stringify({
        id: parsed.id,
      }), { EX: 86400 });

      return res.json({
        isNewVisitor: false,
        lastVisit: last_visits[0][0].last_visit,
        visitCount: visits[0][0].visit_count,
        similarity: similarity_result
      });
    }

    const connection = await mysqlPool.getConnection();
    const [rows] = await connection.query('SELECT * FROM fingerprints');

    let matchFound = false;
    let matchedFp = null; 
    

    for (const stored of rows) {

      if (await compareFingerprints(fpData, stored) >= FINGERPRINT_THRESHOLD) {
        const similarity = await compareFingerprints(fpData,stored);
        similarity_result = similarity;
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
      }), { EX: 86400 });


      connection.release();

      return res.json({
        isNewVisitor: false,
        lastVisit: matchedFp.last_visit,
        visitCount: matchedFp.visit_count + 1,
        similarity: similarity_result
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