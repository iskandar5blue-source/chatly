'use strict';
/*
  Chatly server — no external dependencies (Node.js 18+).
  Run:  node server.js        then open http://localhost:3000
  Realtime: Server-Sent Events (SSE). Actions: plain HTTP POST.
  Data is stored in data.json next to this file.
*/
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');
const PUBLIC_FILE = path.join(__dirname, 'public', 'index.html');
const USER_RE = /^[a-zA-Z0-9_]{3,20}$/;

/* ---------- storage ---------- */
function load() {
  try {
    const d = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    d.logins = d.logins || {}; d.accounts = d.accounts || {};
    d.messages = d.messages || []; d.tokens = d.tokens || {};
    return d;
  } catch (e) {
    return { logins: {}, accounts: {}, messages: [], tokens: {} };
  }
}
let db = load();
function save() {
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DATA_FILE);
}

/* ---------- helpers ---------- */
const subs = new Map(); // account -> Set<res>
function subscribe(account, res) {
  if (!subs.has(account)) subs.set(account, new Set());
  subs.get(account).add(res);
}
function emit(account, event, data) {
  const set = subs.get(account);
  if (!set) return;
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const r of set) r.write(payload);
}
function sendJSON(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(obj));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => {
      data += c;
      if (data.length > 2e6) { reject(new Error('Body too large')); req.destroy(); }
    });
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); }
      catch (e) { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}
function loginFor(req, urlToken) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : urlToken;
  if (!token || !db.tokens[token]) return null;
  return db.tokens[token].login;
}
function accountFor(login, name) {
  if (!name || !db.accounts[name] || db.accounts[name].login !== login) return null;
  return name;
}
function newToken(login) {
  const t = crypto.randomBytes(32).toString('hex');
  db.tokens[t] = { login, ts: Date.now() };
  return t;
}
function hashPassword(pw, salt) {
  return crypto.scryptSync(pw, salt, 64).toString('hex');
}
function conversation(a, b) {
  return db.messages.filter(m => (m.from === a && m.to === b) || (m.from === b && m.to === a));
}
function makeMessage(fields) {
  const msg = Object.assign({ id: crypto.randomUUID(), ts: Date.now(), read: false }, fields);
  db.messages.push(msg);
  save();
  return msg;
}

/* ---------- API ---------- */
async function handleApi(req, res, url) {
  const method = req.method;
  const p = url.pathname;

  // --- public routes ---
  if (method === 'POST' && p === '/api/register') {
    const body = await readBody(req);
    const login = String(body.login || '').trim();
    const password = String(body.password || '');
    if (!USER_RE.test(login)) return sendJSON(res, 400, { error: 'Login: 3–20 letters, numbers or underscore.' });
    if (password.length < 4) return sendJSON(res, 400, { error: 'Password must be at least 4 characters.' });
    if (db.logins[login] || db.accounts[login]) return sendJSON(res, 409, { error: 'This login is already taken.' });
    const salt = crypto.randomBytes(16).toString('hex');
    db.logins[login] = { salt, hash: hashPassword(password, salt), accounts: [login] };
    db.accounts[login] = { login, createdAt: Date.now() };
    const token = newToken(login);
    save();
    return sendJSON(res, 200, { token, login, accounts: [login] });
  }

  if (method === 'POST' && p === '/api/login') {
    const body = await readBody(req);
    const login = String(body.login || '').trim();
    const rec = db.logins[login];
    if (!rec) return sendJSON(res, 401, { error: 'No such login. Register first.' });
    const h = hashPassword(String(body.password || ''), rec.salt);
    if (!crypto.timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(rec.hash, 'hex')))
      return sendJSON(res, 401, { error: 'Wrong password.' });
    const token = newToken(login);
    save();
    return sendJSON(res, 200, { token, login, accounts: rec.accounts });
  }

  if (method === 'GET' && p === '/api/events') {
    // Server-Sent Events stream. Browsers can't set headers on EventSource, so the token is in the query.
    const login = loginFor(req, url.searchParams.get('token'));
    const account = login && accountFor(login, url.searchParams.get('account'));
    if (!account) return sendJSON(res, 401, { error: 'Not allowed' });
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
    res.write(': connected\n\n');
    subscribe(account, res);
    const ping = setInterval(() => res.write(': ping\n\n'), 25000);
    req.on('close', () => {
      clearInterval(ping);
      const set = subs.get(account);
      if (set) set.delete(res);
    });
    return;
  }

  // --- authenticated routes ---
  const login = loginFor(req, null);
  if (!login) return sendJSON(res, 401, { error: 'Please log in.' });

  if (method === 'POST' && p === '/api/logout') {
    const h = req.headers.authorization || '';
    if (h.startsWith('Bearer ')) delete db.tokens[h.slice(7)];
    save();
    return sendJSON(res, 200, { ok: true });
  }

  if (method === 'GET' && p === '/api/me') {
    return sendJSON(res, 200, { login, accounts: db.logins[login].accounts });
  }

  if (method === 'POST' && p === '/api/accounts') {
    const body = await readBody(req);
    const name = String(body.username || '').trim();
    if (!USER_RE.test(name)) return sendJSON(res, 400, { error: 'Username: 3–20 letters, numbers or underscore.' });
    if (db.accounts[name] || db.logins[name]) return sendJSON(res, 409, { error: 'That username is taken.' });
    db.accounts[name] = { login, createdAt: Date.now() };
    db.logins[login].accounts.push(name);
    save();
    return sendJSON(res, 200, { username: name });
  }

  // Everything below acts as one of this login's accounts (sent in X-Account).
  const me = accountFor(login, req.headers['x-account']);
  if (!me) return sendJSON(res, 400, { error: 'Select an account first.' });

  if (method === 'GET' && p === '/api/users/check') {
    const name = url.searchParams.get('name') || '';
    return sendJSON(res, 200, { exists: !!db.accounts[name], self: name === me });
  }

  if (method === 'GET' && p === '/api/chats') {
    const partners = new Map();
    for (const m of db.messages) {
      if (m.from !== me && m.to !== me) continue;
      const other = m.from === me ? m.to : m.from;
      const cur = partners.get(other) || { name: other, last: null, unread: 0 };
      cur.last = m; // messages are stored in time order
      if (m.to === me && !m.read) cur.unread++;
      partners.set(other, cur);
    }
    const list = [...partners.values()].sort((a, b) => b.last.ts - a.last.ts);
    return sendJSON(res, 200, list);
  }

  if (method === 'GET' && p === '/api/messages') {
    const withName = url.searchParams.get('with') || '';
    if (!db.accounts[withName]) return sendJSON(res, 404, { error: 'No such user.' });
    const msgs = conversation(me, withName);
    let changed = false;
    for (const m of msgs) if (m.to === me && !m.read) { m.read = true; changed = true; }
    if (changed) {
      save();
      emit(withName, 'read', { by: me });
    }
    return sendJSON(res, 200, msgs);
  }

  if (method === 'POST' && p === '/api/messages') {
    const body = await readBody(req);
    const to = String(body.to || '');
    const text = String(body.text || '').trim();
    if (!db.accounts[to] || to === me) return sendJSON(res, 400, { error: 'Invalid recipient.' });
    if (!text || text.length > 4000) return sendJSON(res, 400, { error: 'Message is empty or too long.' });
    const msg = makeMessage({ from: me, to, type: 'text', text });
    emit(to, 'chat', msg);
    emit(me, 'chat', msg); // other devices of the same account
    return sendJSON(res, 200, msg);
  }

  if (method === 'POST' && p === '/api/typing') {
    const body = await readBody(req);
    const to = String(body.to || '');
    if (!db.accounts[to] || to === me) return sendJSON(res, 400, { error: 'Invalid recipient.' });
    emit(to, 'typing', { from: me, on: !!body.on });
    return sendJSON(res, 200, { ok: true });
  }

  if (method === 'POST' && p === '/api/signal') {
    // WebRTC call signaling (offer / answer / ice / reject / end / cancel). Relayed only, not stored.
    const body = await readBody(req);
    const to = String(body.to || '');
    if (!db.accounts[to] || to === me) return sendJSON(res, 400, { error: 'Invalid recipient.' });
    emit(to, 'signal', { from: me, data: body.data });
    return sendJSON(res, 200, { ok: true });
  }

  if (method === 'POST' && p === '/api/call-log') {
    const body = await readBody(req);
    const withName = String(body.with || '');
    const kind = body.kind === 'video' ? 'video' : 'audio';
    const result = ['ok', 'missed', 'declined'].includes(body.result) ? body.result : 'missed';
    if (!db.accounts[withName] || withName === me) return sendJSON(res, 400, { error: 'Invalid recipient.' });
    const msg = makeMessage({
      from: me, to: withName, type: 'call', callKind: kind,
      callResult: result, callDur: Math.max(0, Number(body.duration) || 0),
    });
    emit(withName, 'chat', msg);
    emit(me, 'chat', msg);
    return sendJSON(res, 200, msg);
  }

  return sendJSON(res, 404, { error: 'Not found' });
}

/* ---------- HTTP server ---------- */
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  try {
    if (url.pathname.startsWith('/api/')) {
      await handleApi(req, res, url);
      return;
    }
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(fs.readFileSync(PUBLIC_FILE));
      return;
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found');
  } catch (e) {
    if (!res.headersSent) sendJSON(res, 400, { error: e.message || 'Bad request' });
    else res.end();
  }
});

server.listen(PORT, () => {
  console.log(`Chatly running at http://localhost:${PORT}`);
});
