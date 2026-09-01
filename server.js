require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const { spawn } = require('child_process');
const fs = require('fs');
const http = require('http');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);

const fetchFn = global.fetch ? global.fetch.bind(global) : null;
if (!fetchFn) {
  console.error('❌ Node.js 18+ required (fetch).');
  process.exit(1);
}

const PORT = Number(process.env.PORT || 3000);
const NODE_ROLE = (process.env.NODE_ROLE || 'hybrid').toLowerCase(); // master | agent | hybrid
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin';
const AGENT_KEY = process.env.AGENT_KEY || 'change-me-agent-key';

const XRAY_BASE_PORT = parseInt(process.env.XRAY_BASE_PORT || '10086', 10);
const DB_PATH = process.env.DB_PATH || './data/configs.db';
const COOKIE_NAME = 'panel_auth';
const COOKIE_VALUE = 'authenticated';

const XRAY_CONFIG_PATH = process.env.XRAY_CONFIG_PATH || '/tmp/xray-config.json';
const XRAY_BIN = process.env.XRAY_BIN || 'xray';

if (!fs.existsSync('./data')) fs.mkdirSync('./data', { recursive: true });

const db = new sqlite3.Database(DB_PATH);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(__dirname + '/public'));

// ========================= DB INIT =========================
db.serialize(() => {
  db.run('PRAGMA foreign_keys = ON');

  db.run(`
    CREATE TABLE IF NOT EXISTS panels (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      address TEXT NOT NULL,
      is_remote INTEGER DEFAULT 0,
      api_base TEXT DEFAULT '',
      api_key TEXT DEFAULT '',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS inbounds (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      panel_id INTEGER NOT NULL,
      remote_inbound_id TEXT DEFAULT '',
      tag TEXT DEFAULT '',
      port TEXT NOT NULL,
      protocol TEXT NOT NULL,
      host TEXT NOT NULL,
      path TEXT NOT NULL,
      tls TEXT DEFAULT 'tls',
      fp TEXT DEFAULT 'chrome',
      alpn TEXT DEFAULT 'http/1.1',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(panel_id) REFERENCES panels(id) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      uuid TEXT NOT NULL UNIQUE,
      sub_token TEXT UNIQUE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS user_inbound_access (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      inbound_id INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, inbound_id),
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(inbound_id) REFERENCES inbounds(id) ON DELETE CASCADE
    )
  `);

  // migration for old DB
  db.all(`PRAGMA table_info(users)`, [], (err, cols) => {
    if (err) return;
    const hasSubToken = cols.some(c => c.name === 'sub_token');
    if (!hasSubToken) {
      db.run(`ALTER TABLE users ADD COLUMN sub_token TEXT UNIQUE`);
    }
  });
});

// ========================= AUTH =========================
function requireAuth(req, res, next) {
  if (req.cookies[COOKIE_NAME] === COOKIE_VALUE) return next();
  return res.redirect('/dash');
}
function requireAgent(req, res, next) {
  const key = req.headers['x-panel-key'];
  if (!key || key !== AGENT_KEY) return res.status(401).json({ error: 'Unauthorized agent' });
  next();
}

// ========================= HELPERS =========================
function isMasterEnabled() {
  return NODE_ROLE === 'master' || NODE_ROLE === 'hybrid';
}
function isAgentEnabled() {
  return NODE_ROLE === 'agent' || NODE_ROLE === 'hybrid';
}
function normalizeHost(h) { return String(h || '').split(':')[0].toLowerCase().trim(); }
function normalizePath(p) { p = String(p || '/').trim(); return p.startsWith('/') ? p : '/' + p; }
function matchPath(reqPath, basePath) { return reqPath === basePath || reqPath.startsWith(basePath + '/'); }
function makeHostPathKey(host, path) { return `${normalizeHost(host)}|${normalizePath(path)}`; }
function randomPath(prefix = '/v') { return normalizePath(`${prefix}-${crypto.randomBytes(8).toString('hex')}`); }
function randomTag(prefix = 'ib') { return `${prefix}-${crypto.randomBytes(3).toString('hex')}`; }
function makeSubToken() { return crypto.randomBytes(18).toString('base64url'); }

function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => db.get(sql, params, (e, r) => e ? reject(e) : resolve(r)));
}
function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => db.all(sql, params, (e, r) => e ? reject(e) : resolve(r)));
}
function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (e) {
      if (e) return reject(e);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}
async function getPanelById(panelId) {
  return dbGet(`SELECT * FROM panels WHERE id = ?`, [panelId]);
}
function getPublicBaseUrl(req) {
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL.replace(/\/+$/, '');
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'http';
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  return `${proto}://${host}`;
}
async function ensureUserSubToken(userId) {
  const u = await dbGet(`SELECT id, sub_token FROM users WHERE id = ?`, [userId]);
  if (!u) return null;
  if (u.sub_token) return u.sub_token;
  let token = makeSubToken();
  for (let i = 0; i < 5; i++) {
    try {
      await dbRun(`UPDATE users SET sub_token = ? WHERE id = ?`, [token, userId]);
      return token;
    } catch {
      token = makeSubToken();
    }
  }
  throw new Error('failed to create unique sub_token');
}
async function ensureUserSubTokenByUuid(uuid) {
  const u = await dbGet(`SELECT id FROM users WHERE uuid = ?`, [uuid]);
  if (!u) return null;
  return ensureUserSubToken(u.id);
}

async function remoteCall(panel, method, path, body) {
  const base = String(panel.api_base || '').replace(/\/+$/, '');
  if (!base) throw new Error('Remote panel has empty api_base');
  const url = `${base}${path}`;

  const res = await fetchFn(url, {
    method,
    headers: { 'content-type': 'application/json', 'x-panel-key': panel.api_key || '' },
    body: body ? JSON.stringify(body) : undefined
  });

  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { data = { raw: text }; }
  if (!res.ok) throw new Error(data.error || data.message || `Remote ${res.status}`);
  return data;
}

function buildVlessLink(row) {
  const params = new URLSearchParams();
  params.set('encryption', 'none');
  params.set('security', row.tls || 'tls');
  params.set('sni', row.host);
  if (row.fp) params.set('fp', row.fp);
  if (row.alpn) params.set('alpn', row.alpn);
  params.set('type', row.protocol);
  params.set('host', row.host);
  params.set('path', row.path);
  params.set('allowInsecure', '0');
  if (row.protocol === 'grpc') {
    params.delete('path');
    params.set('serviceName', row.path.replace(/^\//, ''));
  }
  if (row.protocol === 'xhttp') params.set('mode', 'auto');

  const label = `${row.username}-${row.panel_name || 'panel'}-${row.tag || ('inb' + row.inbound_id)}`;
  return `vless://${row.uuid}@${row.address}:${row.external_port}?${params.toString()}#${encodeURIComponent(label)}`;
}

async function getUserLinksByUserId(userId) {
  const rows = await dbAll(`
    SELECT
      u.username, u.uuid,
      i.id AS inbound_id, i.tag, i.protocol, i.host, i.path, i.tls, i.fp, i.alpn,
      i.port AS external_port,
      p.name AS panel_name, p.address
    FROM user_inbound_access a
    JOIN users u ON u.id = a.user_id
    JOIN inbounds i ON i.id = a.inbound_id
    JOIN panels p ON p.id = i.panel_id
    WHERE u.id = ?
    ORDER BY i.id DESC
  `, [userId]);

  return rows.map(r => buildVlessLink(r));
}

// ========================= WEB =========================
app.get('/', (req, res) => res.sendFile(__dirname + '/public/index.html'));
app.get('/dash', (req, res) => res.sendFile(__dirname + '/public/dash.html'));
app.get('/dash/view', requireAuth, (req, res) => res.sendFile(__dirname + '/public/dash-view.html'));

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    res.cookie(COOKIE_NAME, COOKIE_VALUE, { httpOnly: true });
    return res.redirect('/dash/view');
  }
  return res.status(401).send('نام کاربری یا رمز عبور اشتباه است. <a href="/dash">بازگشت</a>');
});
app.get('/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.redirect('/dash');
});

// ========================= SUBSCRIPTION PUBLIC ENDPOINT =========================
app.get('/sub/:token', async (req, res) => {
  try {
    const token = String(req.params.token || '').trim();
    if (!token) return res.status(400).send('bad token');

    const user = await dbGet(`SELECT id, username FROM users WHERE sub_token = ?`, [token]);
    if (!user) return res.status(404).send('not found');

    const links = await getUserLinksByUserId(user.id);
    const text = links.join('\n');

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.send(text);
  } catch (e) {
    res.status(500).send('server error');
  }
});

// optional base64 sub
app.get('/sub64/:token', async (req, res) => {
  try {
    const token = String(req.params.token || '').trim();
    const user = await dbGet(`SELECT id FROM users WHERE sub_token = ?`, [token]);
    if (!user) return res.status(404).send('not found');

    const links = await getUserLinksByUserId(user.id);
    const text = links.join('\n');
    const b64 = Buffer.from(text, 'utf8').toString('base64');

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.send(b64);
  } catch {
    res.status(500).send('server error');
  }
});

// ========================= MASTER APIs =========================
if (isMasterEnabled()) {
  app.get('/api/panels', requireAuth, async (req, res) => {
    try { res.json(await dbAll(`SELECT * FROM panels ORDER BY id DESC`)); }
    catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.post('/api/panels', requireAuth, async (req, res) => {
    try {
      const { name, address, is_remote, api_base, api_key } = req.body;
      if (!name || !address) return res.status(400).json({ error: 'name and address are required' });

      const remote = Number(is_remote || 0) ? 1 : 0;
      const ins = await dbRun(
        `INSERT INTO panels (name, address, is_remote, api_base, api_key) VALUES (?, ?, ?, ?, ?)`,
        [String(name).trim(), String(address).trim(), remote, api_base || '', api_key || '']
      );
      res.json({ success: true, id: ins.lastID });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.get('/api/inbounds', requireAuth, async (req, res) => {
    try {
      const rows = await dbAll(`
        SELECT i.*, p.name AS panel_name, p.address AS panel_address, p.is_remote
        FROM inbounds i
        JOIN panels p ON p.id = i.panel_id
        ORDER BY i.id DESC
      `);
      res.json(rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.post('/api/panels/:panelId/inbounds', requireAuth, async (req, res) => {
    try {
      const panelId = Number(req.params.panelId);
      let { tag, port, protocol, host, path, tls, fp, alpn } = req.body;

      if (!port || !protocol || !host || !path) return res.status(400).json({ error: 'port, protocol, host, path are required' });
      if (!['ws', 'xhttp', 'grpc'].includes(protocol)) return res.status(400).json({ error: 'protocol must be ws|xhttp|grpc' });

      path = normalizePath(path);
      if (alpn === 'h2' || alpn === 'h3') alpn = 'http/1.1';

      const panel = await getPanelById(panelId);
      if (!panel) return res.status(404).json({ error: 'panel not found' });

      let remoteInboundId = '';
      if (Number(panel.is_remote) === 1) {
        const r = await remoteCall(panel, 'POST', '/agent/inbounds', {
          tag: tag || '', port: String(port), protocol, host: String(host).trim(), path,
          tls: tls || 'tls', fp: fp || 'chrome', alpn: alpn || 'http/1.1'
        });
        remoteInboundId = String(r.remote_inbound_id || r.id || '');
      }

      const ins = await dbRun(
        `INSERT INTO inbounds (panel_id, remote_inbound_id, tag, port, protocol, host, path, tls, fp, alpn)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [panelId, remoteInboundId, tag || '', String(port), protocol, String(host).trim(), path, tls || 'tls', fp || 'chrome', alpn || 'http/1.1']
      );

      if (Number(panel.is_remote) === 0) {
        await regenerateXrayConfigLocalOnly();
        restartXray();
      }

      res.json({ success: true, id: ins.lastID, remote_inbound_id: remoteInboundId || null });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.post('/api/panels/:panelId/inbounds/preset-anti-filter', requireAuth, async (req, res) => {
    try {
      const panelId = Number(req.params.panelId);
      const panel = await getPanelById(panelId);
      if (!panel) return res.status(404).json({ error: 'panel not found' });

      const { host, port = '443', tls = 'tls', fp = 'chrome', tagPrefix = 'af' } = req.body;
      if (!host) return res.status(400).json({ error: 'host is required' });

      const presets = [
        { protocol: 'ws', path: randomPath('/ws'), tag: randomTag(`${tagPrefix}-ws`), alpn: 'http/1.1' },
        { protocol: 'grpc', path: randomPath('/grpc'), tag: randomTag(`${tagPrefix}-grpc`), alpn: 'http/1.1' },
        { protocol: 'xhttp', path: randomPath('/xhttp'), tag: randomTag(`${tagPrefix}-xhttp`), alpn: 'http/1.1' },
      ];

      const created = [];
      for (const p of presets) {
        let remoteInboundId = '';

        if (Number(panel.is_remote) === 1) {
          const r = await remoteCall(panel, 'POST', '/agent/inbounds', {
            tag: p.tag, port: String(port), protocol: p.protocol, host: String(host).trim(),
            path: p.path, tls, fp, alpn: p.alpn
          });
          remoteInboundId = String(r.remote_inbound_id || r.id || '');
        }

        const ins = await dbRun(
          `INSERT INTO inbounds (panel_id, remote_inbound_id, tag, port, protocol, host, path, tls, fp, alpn)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [panelId, remoteInboundId, p.tag, String(port), p.protocol, String(host).trim(), p.path, tls, fp, p.alpn]
        );

        created.push({ id: ins.lastID, remote_inbound_id: remoteInboundId || null, ...p, host, port: String(port) });
      }

      if (Number(panel.is_remote) === 0) {
        await regenerateXrayConfigLocalOnly();
        restartXray();
      }

      res.json({ success: true, created });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.get('/api/users', requireAuth, async (req, res) => {
    try { res.json(await dbAll(`SELECT * FROM users ORDER BY id DESC`)); }
    catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.post('/api/users', requireAuth, async (req, res) => {
    try {
      const { username, uuid } = req.body;
      if (!username || !uuid) return res.status(400).json({ error: 'username and uuid are required' });

      const ins = await dbRun(`INSERT INTO users (username, uuid, sub_token) VALUES (?, ?, ?)`, [
        String(username).trim(),
        String(uuid).trim(),
        makeSubToken()
      ]);
      res.json({ success: true, id: ins.lastID });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.post('/api/panels/:panelId/users/quick-add', requireAuth, async (req, res) => {
    try {
      const panelId = Number(req.params.panelId);
      const { username, uuid, onlyTagPrefix = '' } = req.body;
      if (!username || !uuid) return res.status(400).json({ error: 'username and uuid are required' });

      let user = await dbGet(`SELECT * FROM users WHERE uuid = ?`, [String(uuid).trim()]);
      if (!user) {
        const insU = await dbRun(
          `INSERT INTO users (username, uuid, sub_token) VALUES (?, ?, ?)`,
          [String(username).trim(), String(uuid).trim(), makeSubToken()]
        );
        user = await dbGet(`SELECT * FROM users WHERE id = ?`, [insU.lastID]);
      } else if (!user.sub_token) {
        const t = await ensureUserSubToken(user.id);
        user.sub_token = t;
      }

      const inbs = await dbAll(
        `SELECT * FROM inbounds WHERE panel_id = ? ${onlyTagPrefix ? 'AND tag LIKE ?' : ''} ORDER BY id DESC`,
        onlyTagPrefix ? [panelId, `${onlyTagPrefix}%`] : [panelId]
      );

      for (const i of inbs) {
        await dbRun(`INSERT OR IGNORE INTO user_inbound_access (user_id, inbound_id) VALUES (?, ?)`, [user.id, i.id]);
      }

      await syncUserToRelatedRemotes(user.id);
      await regenerateXrayConfigLocalOnly();
      restartXray();

      res.json({ success: true, user_id: user.id, assigned_count: inbs.length });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.patch('/api/users/:userId/inbounds', requireAuth, async (req, res) => {
    try {
      const userId = Number(req.params.userId);
      const { inboundIds } = req.body;
      if (!Array.isArray(inboundIds)) return res.status(400).json({ error: 'inboundIds must be array' });

      await dbRun(`DELETE FROM user_inbound_access WHERE user_id = ?`, [userId]);
      for (const id of inboundIds.map(Number)) {
        await dbRun(`INSERT OR IGNORE INTO user_inbound_access (user_id, inbound_id) VALUES (?, ?)`, [userId, id]);
      }

      await ensureUserSubToken(userId);
      await syncUserToRelatedRemotes(userId);
      await regenerateXrayConfigLocalOnly();
      restartXray();

      res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.post('/api/users/:userId/reset-sub-token', requireAuth, async (req, res) => {
    try {
      const userId = Number(req.params.userId);
      const token = makeSubToken();
      await dbRun(`UPDATE users SET sub_token = ? WHERE id = ?`, [token, userId]);
      res.json({ success: true, sub_token: token });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.get('/api/users-with-access', requireAuth, async (req, res) => {
    try {
      const rows = await dbAll(`
        SELECT
          u.id AS user_id, u.username, u.uuid, u.sub_token,
          i.id AS inbound_id, i.tag, i.protocol, i.host, i.path, i.tls, i.fp, i.alpn,
          i.port AS external_port,
          p.name AS panel_name, p.address, p.is_remote
        FROM users u
        LEFT JOIN user_inbound_access a ON a.user_id = u.id
        LEFT JOIN inbounds i ON i.id = a.inbound_id
        LEFT JOIN panels p ON p.id = i.panel_id
        ORDER BY u.id DESC, i.id DESC
      `);

      const base = getPublicBaseUrl(req);
      const map = new Map();

      for (const r of rows) {
        if (!map.has(r.user_id)) {
          const token = r.sub_token || makeSubToken();
          map.set(r.user_id, {
            user_id: r.user_id,
            username: r.username,
            uuid: r.uuid,
            sub_token: token,
            sub_url: `${base}/sub/${token}`,
            sub64_url: `${base}/sub64/${token}`,
            inbounds: [],
            links: []
          });
        }
        if (r.inbound_id) {
          const m = map.get(r.user_id);
          m.inbounds.push({
            inbound_id: r.inbound_id,
            tag: r.tag,
            protocol: r.protocol,
            host: r.host,
            path: r.path,
            panel_name: r.panel_name,
            is_remote: Number(r.is_remote) === 1
          });
          m.links.push({
            inbound_id: r.inbound_id,
            protocol: r.protocol,
            host: r.host,
            path: r.path,
            link: buildVlessLink({ ...r, username: r.username, panel_name: r.panel_name })
          });
        }
      }

      // persist tokens if missing in DB
      for (const u of map.values()) {
        await ensureUserSubToken(u.user_id);
      }

      // reload with persisted real tokens for accuracy
      const users = await dbAll(`SELECT id, sub_token FROM users`);
      const tokenMap = new Map(users.map(x => [x.id, x.sub_token]));
      for (const u of map.values()) {
        const real = tokenMap.get(u.user_id);
        u.sub_token = real;
        u.sub_url = `${base}/sub/${real}`;
        u.sub64_url = `${base}/sub64/${real}`;
      }

      res.json(Array.from(map.values()));
    } catch (e) { res.status(500).json({ error: e.message }); }
  });
}

// sync user to remotes
async function syncUserToRelatedRemotes(userId) {
  const user = await dbGet(`SELECT * FROM users WHERE id = ?`, [userId]);
  if (!user) throw new Error('user not found');

  const rows = await dbAll(`
    SELECT i.id AS inbound_id, i.remote_inbound_id, i.panel_id, p.*
    FROM user_inbound_access a
    JOIN inbounds i ON i.id = a.inbound_id
    JOIN panels p ON p.id = i.panel_id
    WHERE a.user_id = ?
  `, [userId]);

  const grp = {};
  for (const r of rows) {
    if (Number(r.is_remote) !== 1) continue;
    if (!grp[r.panel_id]) grp[r.panel_id] = { panel: r, inboundRemoteIds: [] };
    if (r.remote_inbound_id) grp[r.panel_id].inboundRemoteIds.push(Number(r.remote_inbound_id));
  }

  for (const panelId of Object.keys(grp)) {
    const { panel, inboundRemoteIds } = grp[panelId];
    let remoteUserId = null;
    try {
      const create = await remoteCall(panel, 'POST', '/agent/users', { username: user.username, uuid: user.uuid });
      remoteUserId = Number(create.remote_user_id || create.id);
    } catch {
      const find = await remoteCall(panel, 'GET', `/agent/users/find?uuid=${encodeURIComponent(user.uuid)}`);
      remoteUserId = Number(find.remote_user_id || find.id);
    }
    await remoteCall(panel, 'PATCH', `/agent/users/${remoteUserId}/inbounds`, { inboundIds: inboundRemoteIds });
  }
}

// ========================= AGENT APIs =========================
if (isAgentEnabled()) {
  app.get('/agent/health', requireAgent, (req, res) => res.json({ ok: true, role: NODE_ROLE }));

  app.get('/agent/users/find', requireAgent, async (req, res) => {
    try {
      const uuid = String(req.query.uuid || '').trim();
      if (!uuid) return res.status(400).json({ error: 'uuid is required' });
      const row = await dbGet(`SELECT id, username, uuid FROM users WHERE uuid = ?`, [uuid]);
      if (!row) return res.status(404).json({ error: 'not found' });
      res.json({ success: true, remote_user_id: row.id, ...row });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.post('/agent/inbounds', requireAgent, async (req, res) => {
    try {
      let { tag, port, protocol, host, path, tls, fp, alpn } = req.body;
      if (!port || !protocol || !host || !path) return res.status(400).json({ error: 'port, protocol, host, path are required' });
      if (!['ws', 'xhttp', 'grpc'].includes(protocol)) return res.status(400).json({ error: 'protocol must be ws|xhttp|grpc' });

      path = normalizePath(path);
      if (alpn === 'h2' || alpn === 'h3') alpn = 'http/1.1';

      let localPanel = await dbGet(`SELECT * FROM panels WHERE is_remote = 0 ORDER BY id ASC LIMIT 1`);
      if (!localPanel) {
        const hostGuess = process.env.PUBLIC_HOST || 'localhost';
        const insP = await dbRun(
          `INSERT INTO panels (name, address, is_remote, api_base, api_key) VALUES (?, ?, 0, '', '')`,
          ['LocalAgentPanel', hostGuess]
        );
        localPanel = await dbGet(`SELECT * FROM panels WHERE id = ?`, [insP.lastID]);
      }

      const ins = await dbRun(
        `INSERT INTO inbounds (panel_id, tag, port, protocol, host, path, tls, fp, alpn)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [localPanel.id, tag || randomTag('ag'), String(port), protocol, String(host).trim(), path, tls || 'tls', fp || 'chrome', alpn || 'http/1.1']
      );

      await regenerateXrayConfigLocalOnly();
      restartXray();

      res.json({ success: true, remote_inbound_id: ins.lastID });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.post('/agent/users', requireAgent, async (req, res) => {
    try {
      const { username, uuid } = req.body;
      if (!username || !uuid) return res.status(400).json({ error: 'username and uuid are required' });

      const ex = await dbGet(`SELECT id FROM users WHERE uuid = ?`, [String(uuid).trim()]);
      if (ex) return res.json({ success: true, remote_user_id: ex.id, existed: true });

      const ins = await dbRun(`INSERT INTO users (username, uuid, sub_token) VALUES (?, ?, ?)`, [
        String(username).trim(),
        String(uuid).trim(),
        makeSubToken()
      ]);
      res.json({ success: true, remote_user_id: ins.lastID });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.patch('/agent/users/:userId/inbounds', requireAgent, async (req, res) => {
    try {
      const userId = Number(req.params.userId);
      const inboundIds = Array.isArray(req.body.inboundIds) ? req.body.inboundIds.map(Number) : null;
      if (!inboundIds) return res.status(400).json({ error: 'inboundIds must be array' });

      await dbRun(`DELETE FROM user_inbound_access WHERE user_id = ?`, [userId]);
      for (const id of inboundIds) {
        await dbRun(`INSERT OR IGNORE INTO user_inbound_access (user_id, inbound_id) VALUES (?, ?)`, [userId, id]);
      }

      await ensureUserSubToken(userId);
      await regenerateXrayConfigLocalOnly();
      restartXray();

      res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });
}

// ========================= XRAY LOCAL CONFIG =========================
let hostPathToPortMap = {};
let pathToPortFallback = {};
let xrayProcess = null;

function updateRouteMaps(routeRows) {
  hostPathToPortMap = {};
  pathToPortFallback = {};
  for (const r of routeRows) {
    const internalPort = XRAY_BASE_PORT + Number(r.inbound_id);
    const host = normalizeHost(r.host);
    const path = normalizePath(r.path);
    hostPathToPortMap[makeHostPathKey(host, path)] = internalPort;
    pathToPortFallback[path] = internalPort;
  }
}
function getTargetPort(reqLike) {
  const reqHost = normalizeHost(reqLike.headers?.host || '');
  const reqPath = normalizePath(reqLike.path || reqLike.url || '/');
  for (const [key, port] of Object.entries(hostPathToPortMap)) {
    const [h, p] = key.split('|');
    if (h === reqHost && matchPath(reqPath, p)) return port;
  }
  for (const [p, port] of Object.entries(pathToPortFallback)) {
    if (matchPath(reqPath, p)) return port;
  }
  return null;
}

async function regenerateXrayConfigLocalOnly() {
  const rows = await dbAll(`
    SELECT u.username, u.uuid, i.id AS inbound_id, i.protocol, i.host, i.path
    FROM user_inbound_access a
    JOIN users u ON u.id = a.user_id
    JOIN inbounds i ON i.id = a.inbound_id
    JOIN panels p ON p.id = i.panel_id
    WHERE p.is_remote = 0
    ORDER BY i.id, u.id
  `);

  const byInbound = new Map();
  for (const r of rows) {
    if (!byInbound.has(r.inbound_id)) {
      byInbound.set(r.inbound_id, {
        inbound_id: r.inbound_id,
        protocol: r.protocol,
        host: r.host,
        path: r.path,
        clients: []
      });
    }
    byInbound.get(r.inbound_id).clients.push({ id: r.uuid, email: r.username, flow: "" });
  }

  const inbounds = [];
  const routeRows = [];

  for (const inbound of byInbound.values()) {
    const internalPort = XRAY_BASE_PORT + Number(inbound.inbound_id);
    const ib = {
      listen: "127.0.0.1",
      port: internalPort,
      protocol: "vless",
      settings: { clients: inbound.clients, decryption: "none" },
      streamSettings: { network: inbound.protocol, security: "none" },
      sniffing: { enabled: true, destOverride: ["http", "tls"] }
    };

    if (inbound.protocol === 'ws') {
      ib.streamSettings.wsSettings = { path: inbound.path, headers: { Host: inbound.host } };
    } else if (inbound.protocol === 'xhttp') {
      ib.streamSettings.xhttpSettings = { path: inbound.path, host: inbound.host, mode: "auto" };
    } else if (inbound.protocol === 'grpc') {
      ib.streamSettings.grpcSettings = { serviceName: inbound.path.replace(/^\//, '') };
    }

    inbounds.push(ib);
    routeRows.push({ inbound_id: inbound.inbound_id, host: inbound.host, path: inbound.path });
  }

  if (inbounds.length === 0) {
    inbounds.push({
      listen: "127.0.0.1",
      port: XRAY_BASE_PORT,
      protocol: "vless",
      settings: { clients: [{ id: "00000000-0000-0000-0000-000000000000" }], decryption: "none" },
      streamSettings: { network: "ws", security: "none", wsSettings: { path: "/none" } }
    });
  }

  const config = {
    log: { loglevel: "warning" },
    inbounds,
    outbounds: [{ protocol: "freedom", tag: "direct" }, { protocol: "blackhole", tag: "block" }]
  };

  fs.writeFileSync(XRAY_CONFIG_PATH, JSON.stringify(config, null, 2));
  updateRouteMaps(routeRows);
}

function restartXray() {
  if (xrayProcess) { xrayProcess.kill(); xrayProcess = null; }
  if (!fs.existsSync(XRAY_CONFIG_PATH)) return;

  xrayProcess = spawn(XRAY_BIN, ['-c', XRAY_CONFIG_PATH]);
  xrayProcess.stdout.on('data', d => console.log('XRAY:', d.toString().trim()));
  xrayProcess.stderr.on('data', d => console.error('XRAY ERR:', d.toString().trim()));
  xrayProcess.on('exit', code => console.log('Xray exited with code', code));
}

// ========================= PROXY =========================
app.use((req, res) => {
  const targetPort = getTargetPort(req);
  if (!targetPort) return res.status(404).send('Not found');

  const proxyReq = http.request({
    hostname: '127.0.0.1',
    port: targetPort,
    path: req.url,
    method: req.method,
    headers: req.headers
  }, (proxyRes) => {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
  });

  proxyReq.on('error', (err) => {
    console.error('HTTP proxy error:', err.message);
    if (!res.headersSent) res.status(502).send('Proxy error');
  });

  req.pipe(proxyReq);
});

server.on('upgrade', (req, socket, head) => {
  const fakeReq = { headers: req.headers, path: (req.url || '/').split('?')[0] };
  const targetPort = getTargetPort(fakeReq);
  if (!targetPort) return socket.destroy();

  const proxyReq = http.request({
    hostname: '127.0.0.1',
    port: targetPort,
    path: req.url,
    method: req.method,
    headers: req.headers
  });

  proxyReq.on('upgrade', (proxyRes, proxySocket, proxyHead) => {
    socket.write(`HTTP/1.1 101 Switching Protocols\r\n`);
    Object.keys(proxyRes.headers).forEach(k => socket.write(`${k}: ${proxyRes.headers[k]}\r\n`));
    socket.write('\r\n');

    if (proxyHead?.length) proxySocket.unshift(proxyHead);
    if (head?.length) socket.unshift(head);

    proxySocket.pipe(socket);
    socket.pipe(proxySocket);

    proxySocket.on('error', () => socket.destroy());
    socket.on('error', () => proxySocket.destroy());
    proxySocket.on('close', () => socket.destroy());
    socket.on('close', () => proxySocket.destroy());
  });

  proxyReq.on('error', () => socket.destroy());
  req.pipe(proxyReq);
});

// ========================= BOOT =========================
(async () => {
  try {
    // ensure all users have sub_token
    const us = await dbAll(`SELECT id, uuid FROM users`);
    for (const u of us) await ensureUserSubTokenByUuid(u.uuid);

    await regenerateXrayConfigLocalOnly();
    restartXray();

    server.listen(PORT, () => {
      console.log(`✅ Panel running on :${PORT}`);
      console.log(`Role: ${NODE_ROLE}`);
      console.log(`Admin: ${ADMIN_USER}`);
    });
  } catch (e) {
    console.error('Boot error:', e);
    process.exit(1);
  }
})();
