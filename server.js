require('dotenv').config();

const path = require('node:path');
const crypto = require('node:crypto');
const fs = require('node:fs');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { DatabaseSync } = require('node:sqlite');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');

const TOKEN_LIFETIME = '7d';
const OAUTH_STATE_LIFETIME = 10 * 60 * 1000;
const OAUTH_TICKET_LIFETIME = 60 * 1000;
const allowedRoles = new Set(['student', 'client']);

function openDatabase(filename) {
  if (filename !== ':memory:')
    fs.mkdirSync(path.dirname(path.resolve(filename)), { recursive: true });

  const db = new DatabaseSync(filename);
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT,
      role TEXT NOT NULL CHECK(role IN ('student', 'client')),
      organization TEXT NOT NULL DEFAULT '',
      course TEXT NOT NULL DEFAULT '',
      year TEXT NOT NULL DEFAULT '',
      phone TEXT NOT NULL DEFAULT '',
      profile_photo TEXT NOT NULL DEFAULT '',
      teaches TEXT NOT NULL DEFAULT '[]',
      wants TEXT NOT NULL DEFAULT '[]',
      learning_mode TEXT NOT NULL DEFAULT 'Online',
      availability TEXT NOT NULL DEFAULT 'Evenings',
      bio TEXT NOT NULL DEFAULT '',
      google_sub TEXT UNIQUE,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);
  return db;
}

function serializeUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    organization: user.organization,
    course: user.course,
    year: user.year,
    phone: user.phone,
    profilePhoto: user.profile_photo,
    teaches: JSON.parse(user.teaches),
    wants: JSON.parse(user.wants),
    learningMode: user.learning_mode,
    availability: user.availability,
    bio: user.bio
  };
}

function createApp(options = {}) {
  const config = options.config || process.env;
  const db = options.db || openDatabase(config.DATABASE_PATH || path.join(__dirname, 'data', 'skillswap.sqlite'));
  const clientId = config.GOOGLE_CLIENT_ID || '';
  const clientSecret = config.GOOGLE_CLIENT_SECRET || '';
  const callbackUrl = config.GOOGLE_CALLBACK_URL || '';
  const oauthClient = options.oauthClient || (
    clientId && clientSecret && callbackUrl
      ? new OAuth2Client(clientId, clientSecret, callbackUrl)
      : null
  );
  const jwtSecret = options.jwtSecret || config.JWT_SECRET;
  const sessionSecret = config.SESSION_SECRET || jwtSecret;
  const app = express();
  const tickets = new Map();

  if (!jwtSecret)
    throw new Error('JWT_SECRET must be configured before starting the server.');

  app.disable('x-powered-by');
  app.use(express.json({ limit: '2mb' }));
  app.use(session({
    name: 'skillswap.sid',
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: config.NODE_ENV === 'production',
      maxAge: OAUTH_STATE_LIFETIME
    }
  }));
  const authRoutes = express.Router();

  function cleanupExpired(entries) {
    const now = Date.now();
    for (const [key, item] of entries)
      if (item.expiresAt <= now)
        entries.delete(key);
  }

  function issueToken(user) {
    return jwt.sign({ sub: String(user.id) }, jwtSecret, { expiresIn: TOKEN_LIFETIME });
  }

  function authRequired(req, res, next) {
    const match = /^Bearer\s+(.+)$/i.exec(req.get('authorization') || '');
    if (!match)
      return res.status(401).json({ error: 'Sign in to continue.' });
    let payload;
    try {
      payload = jwt.verify(match[1], jwtSecret);
    } catch {
      return res.status(401).json({ error: 'Your session has expired. Please sign in again.' });
    }
    req.user = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(payload.sub));
    if (!req.user)
      return res.status(401).json({ error: 'Your session is no longer valid. Please sign in again.' });
    next();
  }

  function frontendError(res, error) {
    res.redirect(`/#login?google_error=${encodeURIComponent(error)}`);
  }

  authRoutes.get('/google', (req, res) => {
    res.json({ configured: Boolean(oauthClient) });
  });

  app.get('/auth/google', (req, res) => {
    if (!oauthClient)
      return frontendError(res, 'config');
    const role = String(req.query.role || 'student');
    if (!allowedRoles.has(role))
      return res.status(400).json({ error: 'Choose a valid account type.' });

    const state = crypto.randomBytes(32).toString('hex');
    req.session.oauthFlow = { state, role, expiresAt: Date.now() + OAUTH_STATE_LIFETIME };
    const url = oauthClient.generateAuthUrl({
      access_type: 'online',
      prompt: 'select_account',
      scope: ['openid', 'email', 'profile'],
      state
    });
    res.redirect(url);
  });

  app.get('/auth/google/callback', async (req, res) => {
    if (!oauthClient)
      return frontendError(res, 'config');
    if (req.query.error === 'access_denied')
      return frontendError(res, 'cancelled');

    const state = typeof req.query.state === 'string' ? req.query.state : '';
    const flow = req.session.oauthFlow;
    delete req.session.oauthFlow;
    if (
      !flow ||
      flow.expiresAt <= Date.now() ||
      flow.state !== state ||
      typeof req.query.code !== 'string'
    )
      return frontendError(res, 'state');

    try {
      const { tokens } = await oauthClient.getToken(req.query.code);
      if (!tokens.id_token)
        return frontendError(res, 'failed');
      const ticketPayload = await oauthClient.verifyIdToken({
        idToken: tokens.id_token,
        audience: clientId
      });
      const profile = ticketPayload.getPayload();
      if (!profile?.sub || !profile.email || profile.email_verified !== true)
        return frontendError(res, 'account');

      let user = db.prepare('SELECT * FROM users WHERE google_sub = ?').get(profile.sub);
      if (!user) {
        const existing = db.prepare('SELECT * FROM users WHERE email = ?').get(profile.email);
        if (existing?.google_sub)
          return frontendError(res, 'account');
        if (existing) {
          db.prepare('UPDATE users SET google_sub = ?, profile_photo = CASE WHEN profile_photo = \'\' THEN ? ELSE profile_photo END WHERE id = ?')
            .run(profile.sub, profile.picture || '', existing.id);
          user = db.prepare('SELECT * FROM users WHERE id = ?').get(existing.id);
        } else {
          const result = db.prepare(`
            INSERT INTO users (name, email, role, profile_photo, google_sub)
            VALUES (?, ?, ?, ?, ?)
          `).run(profile.name || profile.email, profile.email, flow.role, profile.picture || '', profile.sub);
          user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
        }
      }

      cleanupExpired(tickets);
      const ticket = crypto.randomBytes(32).toString('hex');
      tickets.set(ticket, { userId: user.id, expiresAt: Date.now() + OAUTH_TICKET_LIFETIME });
      res.redirect(`/#login?google_ticket=${encodeURIComponent(ticket)}`);
    } catch (error) {
      console.error('Google OAuth callback failed:', error.code || error.name || 'unknown error');
      frontendError(res, 'failed');
    }
  });

  authRoutes.post('/google/exchange', (req, res) => {
    cleanupExpired(tickets);
    const ticket = typeof req.body.ticket === 'string' ? req.body.ticket : '';
    const payload = tickets.get(ticket);
    tickets.delete(ticket);
    if (!payload || !/^[a-f0-9]{64}$/.test(ticket))
      return res.status(401).json({ error: 'Google sign-in ticket expired or was already used. Please try again.' });
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(payload.userId);
    if (!user)
      return res.status(401).json({ error: 'The Google account could not be linked to a SkillSwap account.' });
    return res.json({ token: issueToken(user), user: serializeUser(user) });
  });

  authRoutes.post('/register', async (req, res) => {
    const body = req.body || {};
    const name = typeof body.name === 'string' ? body.name.trim() : '';
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    const role = body.role;
    if (!name || !/^\S+@\S+\.\S+$/.test(email) || password.length < 8 || !allowedRoles.has(role))
      return res.status(400).json({ error: 'Enter a name, valid email, password of at least 8 characters, and account type.' });
    if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email))
      return res.status(409).json({ error: 'An account with this email already exists. Please sign in.' });

    const initial = body.initialRequirement || {};
    try {
      const result = db.prepare(`
        INSERT INTO users (
          name, email, password_hash, role, organization, course, year, phone, profile_photo,
          teaches, wants, learning_mode, availability, bio
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        name, email, await bcrypt.hash(password, 12), role,
        body.organization || '', body.course || '', body.year || '', body.phone || '',
        typeof body.profilePhoto === 'string' ? body.profilePhoto : '',
        JSON.stringify(Array.isArray(body.teaches) ? body.teaches : []),
        JSON.stringify(Array.isArray(body.wants) ? body.wants : []),
        body.learningMode || 'Online', body.availability || 'Evenings', body.bio || ''
      );
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
      if (role === 'client' && initial.title && initial.skill) {
        db.prepare('CREATE TABLE IF NOT EXISTS requirements (id INTEGER PRIMARY KEY AUTOINCREMENT, client_id INTEGER NOT NULL, title TEXT NOT NULL, skill TEXT NOT NULL, description TEXT NOT NULL DEFAULT \'\', budget TEXT NOT NULL DEFAULT \'\', timeline TEXT NOT NULL DEFAULT \'\')');
        db.prepare('INSERT INTO requirements (client_id, title, skill, description, budget, timeline) VALUES (?, ?, ?, ?, ?, ?)')
          .run(user.id, initial.title, initial.skill, initial.description || '', initial.budget || '', initial.timeline || '');
      }
      return res.status(201).json({ user: serializeUser(user) });
    } catch (error) {
      if (error.code === 'SQLITE_CONSTRAINT_UNIQUE')
        return res.status(409).json({ error: 'An account with this email already exists. Please sign in.' });
      console.error('Account registration failed:', error.message);
      return res.status(500).json({ error: 'Could not create your account. Please try again.' });
    }
  });

  authRoutes.post('/login', async (req, res) => {
    const body = req.body || {};
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user || !user.password_hash || !(await bcrypt.compare(password, user.password_hash)))
      return res.status(401).json({ error: 'Email or password is incorrect.' });
    if (body.role && body.role !== user.role)
      return res.status(401).json({ error: 'Choose the account type you registered with.' });
    return res.json({ token: issueToken(user), user: serializeUser(user) });
  });

  authRoutes.get('/me', authRequired, (req, res) => {
    res.json({ user: serializeUser(req.user) });
  });

  authRoutes.post('/logout', authRequired, (req, res) => {
    res.json({ ok: true });
  });

  app.use('/api/auth', authRoutes);

  app.get('/api/users', authRequired, (req, res) => {
    const users = db.prepare('SELECT * FROM users WHERE id != ? ORDER BY id DESC').all(req.user.id);
    res.json({ users: users.map(serializeUser) });
  });

  app.use('/api', (req, res) => {
    res.status(404).json({ error: `No API route for ${req.method} ${req.path}.` });
  });

  app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
  app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

  app.locals.database = db;
  app.locals.oauthTickets = tickets;
  return app;
}

if (require.main === module) {
  const app = createApp();
  const port = Number(process.env.PORT || 3000);
  app.listen(port, () => {
    console.log(`SkillSwap is running at http://localhost:${port}`);
    if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET || !process.env.GOOGLE_CALLBACK_URL)
      console.warn('Google OAuth is not configured. Copy .env.example to .env and set the Google OAuth values.');
  });
}

module.exports = { createApp, openDatabase, serializeUser };
