// server.js — SentinelAI Backend
// Run: npm install && node server.js
// Requires: Node.js 18+, npm packages listed below

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import Anthropic from '@anthropic-ai/sdk';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const path = reqire("path");
app.use(express.static(__dirname));
app.get("/",(req,res) => {
  res.sendFile(path.join(__dirname,"index.html"));
});
const PORT = process.env.PORT || 3001;

// ── Anthropic Client ───────────────────────────────────────────────────────
const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY, // set in environment
});

// ── Middleware ─────────────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.FRONTEND_ORIGIN || 'http://localhost:3000' }));
app.use(express.json({ limit: '2mb' }));

// Rate limiting
const apiLimiter = rateLimit({ windowMs: 60_000, max: 60, standardHeaders: true });
const aiLimiter  = rateLimit({ windowMs: 60_000, max: 10, standardHeaders: true, message: { error: 'AI rate limit exceeded. Try again in a minute.' } });
app.use('/api', apiLimiter);
app.use('/api/ai', aiLimiter);

// ── In-Memory User Store (replace with DB in production) ──────────────────
// Passwords stored as plain text here for demo; use bcrypt in production
const USERS = [
  { id: 'u1', email: 'admin@example.com',    password: 'Admin123!',  role: 'admin',  name: 'Admin' },
  { id: 'u2', email: 'admin@yourcompany.com', password: 'Admin123!',  role: 'admin',  name: 'SysAdmin' },
  { id: 'u3', email: 'analyst@corp.com',      password: 'Analyst1!',  role: 'client', name: 'analyst' },
  { id: 'u4', email: 'client@example.com',    password: 'Client123!', role: 'client', name: 'client' },
];

// Simple session store (use Redis/DB in production)
const sessions = new Map(); // token → { userId, expiresAt }

function generateToken() {
  return Array.from({ length: 32 }, () => Math.random().toString(36)[2]).join('');
}

function createSession(userId) {
  const token = generateToken();
  sessions.set(token, { userId, expiresAt: Date.now() + 8 * 60 * 60 * 1000 }); // 8h
  return token;
}

function getSessionUser(token) {
  if (!token) return null;
  const session = sessions.get(token);
  if (!session || session.expiresAt < Date.now()) {
    sessions.delete(token);
    return null;
  }
  return USERS.find(u => u.id === session.userId) || null;
}

// ── Auth Middleware ────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const user  = getSessionUser(token);
  if (!user) return res.status(401).json({ error: 'Unauthorized' });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
    next();
  });
}

// ── POST /api/auth/login ───────────────────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const user = USERS.find(u => u.email.toLowerCase() === email.toLowerCase().trim());
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const token = createSession(user.id);
  res.json({
    token,
    user: { id: user.id, name: user.name, email: user.email, role: user.role,
            initials: user.name[0].toUpperCase() },
  });
});

// ── POST /api/auth/logout ─────────────────────────────────────────────────
app.post('/api/auth/logout', requireAuth, (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  sessions.delete(token);
  res.json({ ok: true });
});

// ── GET /api/auth/me ──────────────────────────────────────────────────────
app.get('/api/auth/me', requireAuth, (req, res) => {
  const { id, name, email, role } = req.user;
  res.json({ id, name, email, role, initials: name[0].toUpperCase() });
});

// ── POST /api/ai/analyze  (requires auth) ─────────────────────────────────
// Body: { messages: [{role,content}], metrics: {...}, threats: [...] }
app.post('/api/ai/analyze', requireAuth, async (req, res) => {
  const { messages = [], metrics = {}, threats = [] } = req.body;

  const threatSummary = threats.slice(0, 5).map(t =>
    `- ${t.sev.toUpperCase()}: ${t.title} from ${t.ip} (${t.country})`
  ).join('\n');

  const systemPrompt = `You are SentinelAI, an expert cybersecurity analyst AI. You help security teams analyze threats, prioritize incidents, and respond effectively. You are concise, professional, and explain things clearly.

Current security state:
- Critical threats: ${metrics.critical ?? 0}
- High severity events: ${metrics.high ?? 0}
- False positives filtered: ${metrics.fp ?? 0}
- Total events analyzed: ${metrics.total ?? 0}

Recent threats:
${threatSummary || 'No threats recorded yet.'}

Keep responses concise (2–4 paragraphs max). Use specific technical details. Explain attack patterns so non-experts can understand. ${req.user.role === 'admin' ? 'This user is an ADMIN — include system-level recommendations and remediation commands.' : 'This user is a client analyst — focus on impact and plain-language explanations.'}`;

  try {
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1000,
      system: systemPrompt,
      messages: messages.slice(-6),
    });

    const reply = response.content?.[0]?.text || 'Unable to analyze at this time.';
    res.json({ reply });
  } catch (err) {
    console.error('[AI] Error:', err.message);
    res.status(500).json({ error: 'AI analysis temporarily unavailable.', details: err.message });
  }
});

// ── POST /api/threats/filter-fp  (false positive filtering) ───────────────
// Body: { threats: [{title, sev, cat, ip, fp},...] }
app.post('/api/threats/filter-fp', requireAuth, async (req, res) => {
  const { threats = [] } = req.body;
  if (!threats.length) return res.json({ results: [] });

  const prompt = `You are a cybersecurity false-positive filter. Analyze these security events and decide which are genuine threats vs false positives.

Events (JSON):
${JSON.stringify(threats.slice(0, 10), null, 2)}

For each event by index, respond ONLY with JSON array like:
[{"index":0,"fp":false,"reason":"..."},...]
No markdown, no extra text. Reason must be ≤ 15 words.`;

  try {
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 600,
      messages: [{ role: 'user', content: prompt }],
    });
    const raw = response.content?.[0]?.text || '[]';
    const results = JSON.parse(raw.replace(/```json|```/g, '').trim());
    res.json({ results });
  } catch (err) {
    console.error('[FP filter] Error:', err.message);
    res.status(500).json({ error: 'FP filter unavailable.' });
  }
});

// ── POST /api/threats/explain  (explain single threat) ────────────────────
// Body: { threat: {title, sev, cat, ip, country, path, user, fp} }
app.post('/api/threats/explain', requireAuth, async (req, res) => {
  const { threat } = req.body;
  if (!threat) return res.status(400).json({ error: 'threat object required' });

  const prompt = `Explain this security event in 2–3 sentences for a ${req.user.role === 'admin' ? 'senior security engineer' : 'non-technical analyst'}:
Title: ${threat.title}
Severity: ${threat.sev}
Category: ${threat.cat}
Source IP: ${threat.ip}
Country: ${threat.country}
Path/Port: ${threat.path}
Target User: ${threat.user}
False Positive: ${threat.fp ? 'Yes' : 'No'}

Be specific. Do not use headers or bullet points.`;

  try {
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 300,
      messages: [{ role: 'user', content: prompt }],
    });
    res.json({ explanation: response.content?.[0]?.text || 'Unable to generate explanation.' });
  } catch (err) {
    res.status(500).json({ error: 'Explanation unavailable.' });
  }
});

// ── GET /api/geo/intelligence  (geo threat analysis) ──────────────────────
// Returns enriched geo data; admin gets full detail, client gets summary
app.get('/api/geo/intelligence', requireAuth, (req, res) => {
  // In production, call MaxMind / ipinfo.io / AbuseIPDB here
  const base = [
    { flag: '🇷🇺', name: 'Russia',        attacks: 247, ip: '185.220.x.x', risk: 'critical', knownTorExit: true  },
    { flag: '🇨🇳', name: 'China',         attacks: 189, ip: '45.33.x.x',   risk: 'critical', knownTorExit: false },
    { flag: '🇧🇷', name: 'Brazil',        attacks: 134, ip: '103.21.x.x',  risk: 'high',     knownTorExit: false },
    { flag: '🇳🇱', name: 'Netherlands',   attacks: 98,  ip: '89.248.x.x',  risk: 'high',     knownTorExit: true  },
    { flag: '🇺🇸', name: 'United States', attacks: 76,  ip: '198.51.x.x',  risk: 'medium',   knownTorExit: false },
    { flag: '🇩🇪', name: 'Germany',       attacks: 54,  ip: '91.108.x.x',  risk: 'medium',   knownTorExit: false },
    { flag: '🇮🇷', name: 'Iran',          attacks: 43,  ip: '45.142.x.x',  risk: 'critical', knownTorExit: false },
    { flag: '🇳🇬', name: 'Nigeria',       attacks: 38,  ip: '41.90.x.x',   risk: 'high',     knownTorExit: false },
  ];

  if (req.user.role === 'admin') {
    // Admin gets full enriched data
    res.json({ countries: base, generatedAt: new Date().toISOString() });
  } else {
    // Client gets summary without knownTorExit detail
    res.json({
      countries: base.map(({ knownTorExit, ...rest }) => rest),
      generatedAt: new Date().toISOString()
    });
  }
});

// ── POST /api/alerts/realtime  (simulate real-time alert webhook) ──────────
// In production, this endpoint receives alerts from your SIEM/WAF
app.post('/api/alerts/realtime', requireAuth, requireAdmin, (req, res) => {
  const { alert } = req.body;
  if (!alert) return res.status(400).json({ error: 'alert payload required' });
  // In production: broadcast to WebSocket clients, persist to DB, send email/SMS
  console.log('[ALERT]', JSON.stringify(alert));
  res.json({ received: true, alertId: `ALT-${Date.now()}` });
});

// ── GET /api/admin/users  (admin only) ────────────────────────────────────
app.get('/api/admin/users', requireAdmin, (req, res) => {
  res.json({
    users: USERS.map(({ password, ...u }) => u), // never return passwords
    total: USERS.length
  });
});

// ── GET /api/admin/sessions  (admin only) ─────────────────────────────────
app.get('/api/admin/sessions', requireAdmin, (req, res) => {
  res.json({ activeSessions: sessions.size });
});

// ── GET /api/health ───────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime(), timestamp: new Date().toISOString() });
});

// ── Serve frontend static files ───────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n🛡️  SentinelAI backend running on http://localhost:${PORT}`);
  console.log(`   API key loaded: ${process.env.ANTHROPIC_API_KEY ? '✅' : '❌ MISSING — set ANTHROPIC_API_KEY'}\n`);
});
