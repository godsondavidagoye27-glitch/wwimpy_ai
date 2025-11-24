const express = require('express');
const axios = require('axios');
const path = require('path');
const dotenv = require('dotenv');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const sqlite3 = require('sqlite3').verbose();
const {OAuth2Client} = require('google-auth-library');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const OPENAI_KEY = process.env.OPENAI_API_KEY;
const OPENROUTER_KEY = process.env.OPENROUTER_API_KEY;

// basic rate limiter
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // limit each IP to 30 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(cors());
app.use(express.json({ limit: '1mb' }));

// Serve static files from current directory
app.use(express.static(path.join(__dirname, '.')));

// Simple request logger for debugging
app.use((req, res, next) => {
  console.log(new Date().toISOString(), req.method, req.path);
  next();
});

// Handle preflight for /api/chat explicitly
app.options('/api/chat', (req, res) => {
  res.sendStatus(204);
});

// Respond to non-POST methods on /api/chat with a clear JSON 405
app.all('/api/chat', apiLimiter, (req, res, next) => {
  if (req.method === 'POST') return next();
  res.status(405).json({ error: 'Method Not Allowed. Use POST /api/chat' });
});

// Initialize SQLite DB
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

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || null;
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

if (GOOGLE_CLIENT_ID) {
  const masked = GOOGLE_CLIENT_ID.replace(/^(.{6}).+(.{6})$/, '$1...$2');
  console.log('Google Client ID loaded:', masked);
} else {
  console.log('Google Client ID not configured.');
}

// Validation helper
function validMessages(messages) {
  if (!Array.isArray(messages)) return false;
  return messages.every(m => m && typeof m.role === 'string' && (m.content || m.text));
}

// Verify Google ID token (returns payload with email)
async function verifyIdToken(idToken) {
  if (!googleClient) throw new Error('Google client not configured');
  const ticket = await googleClient.verifyIdToken({ idToken, audience: GOOGLE_CLIENT_ID });
  const payload = ticket.getPayload();
  return payload; // includes email, name, sub
}

// IP quota middleware using DB: limit to maxPerMinute per IP
const maxPerMinuteDB = parseInt(process.env.MAX_PER_MINUTE || '60', 10);
async function ipQuotaMiddleware(req, res, next) {
  try {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    const windowStart = Math.floor(Date.now() / 60000); // minute window
    db.get('SELECT id, count, window_start FROM ip_quota WHERE ip = ? AND window_start = ?', [ip, windowStart], (err, row) => {
      if (err) return next();
      if (!row) {
        db.run('INSERT INTO ip_quota (ip, window_start, count) VALUES (?, ?, ?)', [ip, windowStart, 1]);
        return next();
      }
      if (row.count >= maxPerMinuteDB) return res.status(429).json({ error: 'IP quota exceeded' });
      db.run('UPDATE ip_quota SET count = count + 1 WHERE id = ?', [row.id]);
      return next();
    });
  } catch (e) {
    return next();
  }
}

// Chat proxy with rate limiting and validation
app.post('/api/chat', apiLimiter, ipQuotaMiddleware, async (req, res) => {
  if (!OPENAI_KEY && !OPENROUTER_KEY) return res.status(500).json({ error: 'Server misconfigured: no API key provided (OPENAI_API_KEY or OPENROUTER_API_KEY)' });

  const { model, messages } = req.body;
  if (!validMessages(messages)) return res.status(400).json({ error: 'Invalid messages format' });

  try {
    let resp;
    if (OPENROUTER_KEY) {
      // Use OpenRouter
      resp = await axios.post('https://openrouter.ai/api/v1/chat/completions', {
        model: model || 'openchat/openchat-7b:free',
        messages,
      }, {
        headers: {
          'Authorization': `Bearer ${OPENROUTER_KEY}`,
          'Content-Type': 'application/json'
        }
      });
    } else if (OPENAI_KEY) {
      // Use OpenAI
      resp = await axios.post('https://api.openai.com/v1/chat/completions', {
        model: model || 'gpt-4o-mini',
        messages,
        max_tokens: 1000,
      }, {
        headers: {
          'Authorization': `Bearer ${OPENAI_KEY}`,
          'Content-Type': 'application/json'
        }
      });
    } else {
      return res.status(500).json({ error: 'Server misconfigured: no API key provided (OPENAI_API_KEY or OPENROUTER_API_KEY)' });
    }

    return res.json(resp.data);
  } catch (err) {
    console.error('Proxy error:', err.response ? err.response.data : err.message);
    const status = err.response ? err.response.status : 500;
    const data = err.response ? err.response.data : { error: err.message };
    return res.status(status).json(data);
  }
});

// Save chat history (expects { user: string, items: [ { role, text, html } ] })
// Persist history: requires verified Google ID token (Authorization: Bearer <id_token>) or allows 'local' user without token
app.post('/api/history', apiLimiter, ipQuotaMiddleware, async (req, res) => {
  try {
    const auth = req.headers.authorization;
    let verifiedEmail = null;
    if (auth && auth.startsWith('Bearer ')) {
      const token = auth.slice(7);
      try {
        const payload = await verifyIdToken(token);
        verifiedEmail = payload.email;
      } catch (e) {
        return res.status(401).json({ error: 'Invalid ID token' });
      }
    }

    const { user, items } = req.body;
    const targetUser = verifiedEmail || user;
    if (!targetUser || !Array.isArray(items)) return res.status(400).json({ error: 'Invalid payload' });

    const stmt = db.prepare('INSERT INTO chats (user, role, text, html) VALUES (?, ?, ?, ?)');
    db.serialize(() => {
      items.forEach(it => {
        stmt.run(targetUser, it.role || 'user', it.text || '', it.html || null);
      });
      stmt.finalize(err => {
        if (err) return res.status(500).json({ error: 'DB write failed' });
        return res.json({ ok: true });
      });
    });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// Fetch history: GET /api/history?user=email
// GET /api/history?limit=50&offset=0  - requires Authorization bearer id_token or allows local via user=local
app.get('/api/history', apiLimiter, ipQuotaMiddleware, async (req, res) => {
  try {
    const auth = req.headers.authorization;
    let verifiedEmail = null;
    if (auth && auth.startsWith('Bearer ')) {
      const token = auth.slice(7);
      try {
        const payload = await verifyIdToken(token);
        verifiedEmail = payload.email;
      } catch (e) {
        return res.status(401).json({ error: 'Invalid ID token' });
      }
    }

    const user = verifiedEmail || req.query.user || 'local';
    const limit = Math.min(parseInt(req.query.limit || '200', 10), 1000);
    const offset = Math.max(parseInt(req.query.offset || '0', 10), 0);

    db.all('SELECT id, role, text, html, created_at FROM chats WHERE user = ? ORDER BY id ASC LIMIT ? OFFSET ?', [user, limit, offset], (err, rows) => {
      if (err) return res.status(500).json({ error: 'DB read failed' });
      return res.json({ items: rows });
    });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// Verify ID token endpoint (useful for testing from client)
app.post('/api/verify-google', apiLimiter, async (req, res) => {
  try {
    const token = req.body.id_token || (req.headers.authorization && req.headers.authorization.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null);
    if (!token) return res.status(400).json({ error: 'Missing id_token' });
    try {
      const payload = await verifyIdToken(token);
      return res.json({ ok: true, payload });
    } catch (e) {
      return res.status(401).json({ error: 'Invalid ID token', detail: e.message });
    }
  } catch (e) {
    return res.status(500).json({ error: 'Server error' });
  }
});

app.listen(PORT, () => {
  console.log(`WIMPY proxy server running on http://localhost:${PORT}`);
});

// DELETE /api/history - clear user's history (requires ID token or user param if local)
app.delete('/api/history', apiLimiter, ipQuotaMiddleware, async (req, res) => {
  try {
    const auth = req.headers.authorization;
    let verifiedEmail = null;
    if (auth && auth.startsWith('Bearer ')) {
      const token = auth.slice(7);
      try {
        const payload = await verifyIdToken(token);
        verifiedEmail = payload.email;
      } catch (e) {
        return res.status(401).json({ error: 'Invalid ID token' });
      }
    }
    const user = verifiedEmail || req.body.user;
    if (!user) return res.status(400).json({ error: 'User required' });
    db.run('DELETE FROM chats WHERE user = ?', [user], function(err) {
      if (err) return res.status(500).json({ error: 'DB delete failed' });
      return res.json({ ok: true, deleted: this.changes });
    });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

const express = require('express');
const path = require('path');

const app = express();

// 👇 ADD THIS — serve static files (optional but recommended)
app.use(express.static('public')); // serves files from /public folder

// 👇 ADD THIS — fallback route for /
app.get('/', (req, res) => {
  // Option A: Simple message (quick test)
  res.send(`
    <html>
      <body style="background: #0a0a0a; color: #0ff; font-family: monospace; padding: 2rem;">
        <h1>⚡ WIMPY AI</h1>
        <p>✅ Server is live!</p>
        <p>Theme: <span style="color: gold;">Cyberpunk Gold & Green</span></p>
        <p>Ready for <span style="color: lime;">serious</span> or <span style="color: red;">unhinged</span> mode.</p>
      </body>
    </html>
  `);
});

// Optional: catch-all for SPA (if you're building a frontend app)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 🔑 Start server on Render's port
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Wimpy AI running on port ${PORT}`);
});

