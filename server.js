const path = require('path');
const fs = require('fs');
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === 'production';
const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(process.env.DB_PATH || path.join(dataDir, 'gamehub.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT NOT NULL COLLATE NOCASE UNIQUE,
 email TEXT NOT NULL COLLATE NOCASE UNIQUE,
 password_hash TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS favorites (
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 game_id TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT (datetime('now')),
 PRIMARY KEY(user_id, game_id)
);
`);

app.disable('x-powered-by');
if (isProduction) app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
      imgSrc: ["'self'", 'https://cdn.cloudflare.steamstatic.com', 'https://images.unsplash.com', 'https://placehold.co', 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false,
}));
app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));
app.use(session({
  name: 'gamehub.sid',
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: dataDir, table: 'sessions' }),
  secret: process.env.SESSION_SECRET || (isProduction ? '' : 'local-development-secret-change-before-publishing-please'),
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: isProduction, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 24 * 7 },
  rolling: true,
}));
if (isProduction && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) {
  console.error('HATA: Yayında SESSION_SECRET en az 32 karakterlik rastgele bir değer olmalı.');
  process.exit(1);
}

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Çok fazla deneme yapıldı. Lütfen 15 dakika sonra tekrar dene.' } });
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const usernamePattern = /^[\p{L}\p{N}_-]{3,24}$/u;
function cleanText(value, max) { return typeof value === 'string' ? value.trim().slice(0, max) : ''; }
function publicUser(row) { return row ? { id: row.id, username: row.username, email: row.email, createdAt: row.created_at } : null; }
function requireUser(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Bu işlem için önce giriş yapmalısın.' });
  next();
}
function checkOrigin(req, res, next) {
  const origin = req.get('origin');
  if (origin) {
    try {
      if (new URL(origin).host !== req.get('host')) return res.status(403).json({ error: 'İstek kaynağı doğrulanamadı.' });
    } catch { return res.status(403).json({ error: 'İstek kaynağı doğrulanamadı.' }); }
  }
  next();
}
app.use('/api', checkOrigin);
app.use('/api/register', authLimiter);
app.use('/api/login', authLimiter);

app.get('/api/health', (_req, res) => res.json({ ok: true }));
app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  const user = db.prepare('SELECT id, username, email, created_at FROM users WHERE id = ?').get(req.session.userId);
  if (!user) { req.session.destroy(() => {}); return res.json({ user: null }); }
  res.json({ user: publicUser(user) });
});
app.post('/api/register', async (req, res, next) => {
  try {
    const username = cleanText(req.body.username, 24);
    const email = cleanText(req.body.email, 254).toLowerCase();
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    if (!usernamePattern.test(username)) return res.status(400).json({ error: 'Kullanıcı adı 3–24 karakter olmalı; harf, rakam, alt çizgi ve kısa çizgi kullanabilirsin.' });
    if (!emailPattern.test(email)) return res.status(400).json({ error: 'Geçerli bir e-posta adresi yaz.' });
    if (password.length < 10 || password.length > 128) return res.status(400).json({ error: 'Parola en az 10, en fazla 128 karakter olmalı.' });
    const hash = await bcrypt.hash(password, 12);
    let info;
    try { info = db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)').run(username, email, hash); }
    catch (e) { if (String(e.code).startsWith('SQLITE_CONSTRAINT')) return res.status(409).json({ error: 'Bu kullanıcı adı veya e-posta zaten kullanılıyor.' }); throw e; }
    req.session.regenerate(err => {
      if (err) return next(err);
      req.session.userId = Number(info.lastInsertRowid);
      req.session.save(err2 => { if (err2) return next(err2); res.status(201).json({ user: publicUser(db.prepare('SELECT id, username, email, created_at FROM users WHERE id = ?').get(req.session.userId)) }); });
    });
  } catch (e) { next(e); }
});
app.post('/api/login', async (req, res, next) => {
  try {
    const email = cleanText(req.body.email, 254).toLowerCase();
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    const row = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    const valid = row && await bcrypt.compare(password, row.password_hash);
    if (!valid) return res.status(401).json({ error: 'E-posta adresi veya parola hatalı.' });
    req.session.regenerate(err => {
      if (err) return next(err);
      req.session.userId = row.id;
      req.session.save(err2 => { if (err2) return next(err2); res.json({ user: publicUser(row) }); });
    });
  } catch (e) { next(e); }
});
app.post('/api/logout', (req, res, next) => {
  req.session.destroy(err => {
    if (err) return next(err);
    res.clearCookie('gamehub.sid', { httpOnly: true, secure: isProduction, sameSite: 'lax' });
    res.json({ ok: true });
  });
});
app.patch('/api/profile', requireUser, (req, res) => {
  const username = cleanText(req.body.username, 24);
  if (!usernamePattern.test(username)) return res.status(400).json({ error: 'Kullanıcı adı 3–24 karakter olmalı.' });
  try {
    db.prepare('UPDATE users SET username = ? WHERE id = ?').run(username, req.session.userId);
    res.json({ user: publicUser(db.prepare('SELECT id, username, email, created_at FROM users WHERE id = ?').get(req.session.userId)) });
  } catch (e) {
    if (String(e.code).startsWith('SQLITE_CONSTRAINT')) return res.status(409).json({ error: 'Bu kullanıcı adı zaten kullanılıyor.' });
    throw e;
  }
});
const gameIds = new Set(JSON.parse(fs.readFileSync(path.join(__dirname, 'games.json'), 'utf8')).map(g => g.id));
app.get('/api/favorites', requireUser, (req, res) => {
  const ids = db.prepare('SELECT game_id FROM favorites WHERE user_id = ? ORDER BY created_at DESC').all(req.session.userId).map(x => x.game_id);
  const games = JSON.parse(fs.readFileSync(path.join(__dirname, 'games.json'), 'utf8')).filter(g => ids.includes(g.id));
  res.json({ favorites: games });
});
app.post('/api/favorites/:id', requireUser, (req, res) => {
  const id = String(req.params.id || '');
  if (!gameIds.has(id)) return res.status(404).json({ error: 'Oyun bulunamadı.' });
  const exists = db.prepare('SELECT 1 FROM favorites WHERE user_id = ? AND game_id = ?').get(req.session.userId, id);
  if (exists) { db.prepare('DELETE FROM favorites WHERE user_id = ? AND game_id = ?').run(req.session.userId, id); return res.json({ saved: false }); }
  db.prepare('INSERT INTO favorites (user_id, game_id) VALUES (?, ?)').run(req.session.userId, id);
  res.json({ saved: true });
});

app.use(express.static(__dirname, { extensions: ['html'], index: 'index.html', maxAge: isProduction ? '1h' : 0 }));
app.use((req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'İstenen işlem bulunamadı.' });
  res.status(404).sendFile(path.join(__dirname, '404.html'));
});
app.use((err, _req, res, _next) => {
  console.error(err);
  if (res.headersSent) return;
  res.status(500).json({ error: 'Beklenmeyen bir hata oluştu. Lütfen daha sonra tekrar dene.' });
});
app.listen(PORT, () => console.log(`GAMEHUB çalışıyor: http://localhost:${PORT}`));
