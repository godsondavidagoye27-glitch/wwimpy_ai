process.on('uncaughtException', (err) => {
  console.error('🚨 Uncaught Exception:', err);
  process.exit(1);
});

process.on('unhandledRejection', (err) => {
  console.error('🚨 Unhandled Rejection:', err);
  process.exit(1);
});
// ========== DEPENDENCIES ==========
const express = require('express');
const axios = require('axios');
const path = require('path');
const dotenv = require('dotenv');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const sqlite3 = require('sqlite3').verbose();
const { OAuth2Client } = require('google-auth-library');

dotenv.config();

// ========== SETUP ==========
const app = express();
const PORT = process.env.PORT || 3000;

// Env keys
const OPENAI_KEY = process.env.OPENAI_API_KEY;
const OPENROUTER_KEY = process.env.OPENROUTER_API_KEY;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || null;

// ========== MIDDLEWARE ==========
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public'))); // ✅ Serve static files from /public

// Logger
app.use((req, res, next) => {
  console.log(new Date().toISOString(), req.method, req.path);
  next();
});

// Rate limiter
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
});

// ========== DATABASE ==========
const DB_PATH = path.join(__dirname, 'wimpy.db');
const db = new sqlite3.Database(DB_PATH);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT,
    role TEXT,
    text TEXT,
    html TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS ip_quota (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    window_start INTEGER,
    count INTEGER
  )`);
});

const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

if (GOOGLE_CLIENT_ID) {
  const masked = GOOGLE_CLIENT_ID.replace(/^(.{6}).+(.{6})$/, '$1...$2');
  console.log('Google Client ID loaded:', masked);
} else {
  console.log('Google Client ID not configured.');
}

// ✅ ADDED HERE — BEFORE ANY USAGE
async function verifyIdToken(idToken) {
  if (!googleClient) throw new Error('Google client not configured');
  const ticket = await googleClient.verifyIdToken({ idToken, audience: GOOGLE_CLIENT_ID });
  const payload = ticket.getPayload();
  return payload; // includes email, name, sub
}
// ========== IP QUOTA MIDDLEWARE ==========
const maxPerMinuteDB = parseInt(process.env.MAX_PER_MINUTE || '60', 10);
function ipQuotaMiddleware(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const windowStart = Math.floor(Date.now() / 60000);
  db.get('SELECT id, count FROM ip_quota WHERE ip = ? AND window_start = ?', [ip, windowStart], (err, row) => {
    if (err) return next();
    if (!row) {
      db.run('INSERT INTO ip_quota (ip, window_start, count) VALUES (?, ?, 1)', [ip, windowStart]);
      return next();
    }
    if (row.count >= maxPerMinuteDB) return res.status(429).json({ error: 'IP quota exceeded' });
    db.run('UPDATE ip_quota SET count = count + 1 WHERE ip = ? AND window_start = ?', [ip, windowStart]);
    return next();
  });
}

// ========== ROOT ROUTE — ✅ FIXES "Cannot GET /" ==========
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>WIMPY AI</title>
      <style>
        body { 
          background: #0a0a0a; 
          color: #0ff; 
          font-family: 'Courier New', monospace; 
          padding: 2rem;
          margin: 0;
        }
        h1 { 
          color: gold; 
          text-shadow: 0 0 10px gold; 
          margin-bottom: 1rem;
        }
        .status { color: lime; }
        .mode { color: red; }
      </style>
    </head>
    <body>
      <h1>⚡ WIMPY AI</h1>
      <p>✅ Server is live!</p>
      <p>Theme: <span style="color: gold;">Cyberpunk Gold & Green</span></p>
      <p>Ready for <span class="status">serious</span> or <span class="mode">unhinged</span> mode.</p>
      <p>Endpoints: <code>/api/chat</code>, <code>/api/history</code></p>
    </body>
    </html>
  `);
});

// ========== API ROUTES ==========
// Preflight & method restriction
app.options('/api/chat', (req, res) => res.sendStatus(204));
app.all('/api/chat', apiLimiter, (req, res, next) => {
  if (req.method === 'POST') return next();
  res.status(405).json({ error: 'Method Not Allowed. Use POST /api/chat' });
});

function validMessages(messages) {
  if (!Array.isArray(messages)) return false;
  return messages.every(m => m && typeof m.role === 'string' && (m.content || m.text));
}

// POST /api/chat
app.post('/api/chat', apiLimiter, ipQuotaMiddleware, async (req, res) => {
  if (!OPENAI_KEY && !OPENROUTER_KEY) {
    return res.status(500).json({ error: 'No API key configured' });
  }

  const { model, messages } = req.body;
  if (!validMessages(messages)) {
    return res.status(400).json({ error: 'Invalid messages format' });
  }

  try {
    let resp;
    const headers = { 'Content-Type': 'application/json' };
    
    if (OPENROUTER_KEY) {
      headers.Authorization = `Bearer ${OPENROUTER_KEY}`;
      resp = await axios.post('https://openrouter.ai/api/v1/chat/completions', {
        model: model || 'openchat/openchat-7b:free',
        messages,
      }, { headers });
    } else {
      headers.Authorization = `Bearer ${OPENAI_KEY}`;
      resp = await axios.post('https://api.openai.com/v1/chat/completions', {
        model: model || 'gpt-4o-mini',
        messages,
        max_tokens: 1000,
      }, { headers });
    }
    return res.json(resp.data);
  } catch (err) {
    const status = err.response?.status || 500;
    const data = err.response?.data || { error: err.message };
    return res.status(status).json(data);
  }
});

// POST /api/history
app.post('/api/history', apiLimiter, ipQuotaMiddleware, async (req, res) => {
  try {
    // (your existing logic — unchanged)
    const auth = req.headers.authorization;
    let verifiedEmail = null;
    if (auth?.startsWith('Bearer ')) {
      const token = auth.slice(7);
      try { verifiedEmail = (await verifyIdToken(token)).email; } 
      catch (e) { return res.status(401).json({ error: 'Invalid ID token' }); }
    }

    const { user, items } = req.body;
    const targetUser = verifiedEmail || user;
    if (!targetUser || !Array.isArray(items)) return res.status(400).json({ error: 'Invalid payload' });

    const stmt = db.prepare('INSERT INTO chats (user, role, text, html) VALUES (?, ?, ?, ?)');
    db.serialize(() => {
      items.forEach(it => stmt.run(targetUser, it.role || 'user', it.text || '', it.html || null));
      stmt.finalize(err => {
        if (err) return res.status(500).json({ error: 'DB write failed' });
        return res.json({ ok: true });
      });
    });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/history
app.get('/api/history', apiLimiter, ipQuotaMiddleware, (req, res) => {
  const auth = req.headers.authorization;
  let verifiedEmail = null;
  if (auth?.startsWith('Bearer ')) {
    const token = auth.slice(7);
    try { verifiedEmail = (await verifyIdToken(token)).email; } 
    catch (e) { return res.status(401).json({ error: 'Invalid ID token' }); }
  }

  const user = verifiedEmail || req.query.user || 'local';
  const limit = Math.min(parseInt(req.query.limit || '200', 10), 1000);
  const offset = Math.max(parseInt(req.query.offset || '0', 10), 0);

  db.all('SELECT id, role, text, html, created_at FROM chats WHERE user = ? ORDER BY id ASC LIMIT ? OFFSET ?', 
    [user, limit, offset], 
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'DB read failed' });
      return res.json({ items: rows });
    }
  );
});

// POST /api/verify-google
app.post('/api/verify-google', apiLimiter, async (req, res) => {
  const token = req.body.id_token || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null);
  if (!token) return res.status(400).json({ error: 'Missing id_token' });
  try {
    const payload = await verifyIdToken(token);
    return res.json({ ok: true, payload });
  } catch (e) {
    return res.status(401).json({ error: 'Invalid ID token', detail: e.message });
  }
});

// DELETE /api/history
app.delete('/api/history', apiLimiter, ipQuotaMiddleware, (req, res) => {
  const auth = req.headers.authorization;
  let verifiedEmail = null;
  if (auth?.startsWith('Bearer ')) {
    const token = auth.slice(7);
    try { verifiedEmail = (await verifyIdToken(token)).email; } 
    catch (e) { return res.status(401).json({ error: 'Invalid ID token' }); }
  }
  const user = verifiedEmail || req.body.user;
  if (!user) return res.status(400).json({ error: 'User required' });
  
  db.run('DELETE FROM chats WHERE user = ?', [user], function(err) {
    if (err) return res.status(500).json({ error: 'DB delete failed' });
    return res.json({ ok: true, deleted: this.changes });
  });
});

// ========== START SERVER ==========
app.listen(PORT, () => {
  console.log(`🚀 WIMPY AI running on http://localhost:${PORT}`);
  console.log(`✅ Root route: GET /`);
  console.log(`✅ API endpoints: /api/chat, /api/history, /api/verify-google`);
});
