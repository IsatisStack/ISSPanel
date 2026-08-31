require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const { spawn } = require('child_process');
const fs = require('fs');
const http = require('http');

const app = express();
const server = http.createServer(app);

// Node 18+ native fetch
const fetchFn = global.fetch ? global.fetch.bind(global) : null;
if (!fetchFn) {
  console.error('❌ This build requires Node.js 18+ (for fetch).');
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

if (!fs.existsSync('./data')) fs.mkdirSync('./data', { recursive: true });

const db = new sqlite3.Database(DB_PATH);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());

// =========================
// DB INIT
// =========================
db.serialize(() => {
  db.run('PRAGMA foreign_keys = ON');

  db.run(`
    CREATE TABLE IF NOT EXISTS panels (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      address TEXT NOT NULL,        -- domain/ip for links
      is_remote INTEGER DEFAULT 0,  -- 0 local / 1 remote-agent
      api_base TEXT DEFAULT '',     -- e.g. https://us.example.com
      api_key TEXT DEFAULT '',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS inbounds (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      panel_id INTEGER NOT NULL,
      remote_inbound_id TEXT DEFAULT '',  -- id on remote agent
      tag TEXT DEFAULT '',
      port TEXT NOT NULL,                 -- external port for links
      protocol TEXT NOT NULL,             -- ws|xhttp|grpc
      host TEXT NOT NULL,
      path TEXT NOT NULL,
      tls TEXT DEFAULT 'none',
      fp TEXT DEFAULT '',
      alpn TEXT DEFAULT 'http/1.1',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(panel_id) REFERENCES panels(id) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      remote_user_id TEXT DEFAULT '',     -- id on remote agent (optional)
      username TEXT NOT NULL UNIQUE,
      uuid TEXT NOT NULL UNIQUE,
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
});

// =========================
// AUTH
// =========================
function requireAuth(req, res, next) {
  if (req.cookies[COOKIE_NAME] === COOKIE_VALUE) return next();
  return res.redirect('/dash');
}

function requireAgent(req, res, next) {
  const key = req.headers['x-panel-key'];
  if (!key || key !== AGENT_KEY) return res.status(401).json({ error: 'Unauthorized agent' });
  next();
}

// =========================
// HELPERS
// =========================
function isMasterEnabled() {
  return NODE_ROLE === 'master' || NODE_ROLE === 'hybrid';
}
function isAgentEnabled() {
  return NODE_ROLE === 'agent' || NODE_ROLE === 'hybrid';
}

function normalizeHost(h) {
  if (!h) return '';
  return String(h).split(':')[0].toLowerCase().trim();
}
function normalizePath(p) {
  if (!p) return '/';
  p = String(p).trim();
  return p.startsWith('/') ? p : '/' + p;
}
function matchPath(reqPath, basePath) {
  return reqPath === basePath || reqPath.startsWith(basePath + '/');
}
function makeHostPathKey(host, path) {
  return `${normalizeHost(host)}|${normalizePath(path)}`;
}

function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
  });
}
function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
  });
}
function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

async function getPanelById(panelId) {
  return dbGet(`SELECT * FROM panels WHERE id = ?`, [panelId]);
}

async function remoteCall(panel, method, path, body) {
  const base = String(panel.api_base || '').replace(/\/+$/, '');
  if (!base) throw new Error('Remote panel has empty api_base');
  const url = `${base}${path}`;

  const res = await fetchFn(url, {
    method,
    headers: {
      'content-type': 'application/json',
      'x-panel-key': panel.api_key || ''
    },
    body: body ? JSON.stringify(body) : undefined
  });

  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }

  if (!res.ok) throw new Error(data.error || data.message || `Remote ${res.status}`);
  return data;
}

function buildVlessLink(row) {
  const params = new URLSearchParams();
  params.set('encryption', 'none');
  params.set('security', row.tls || 'none');
  params.set('sni', row.host);
  if (row.fp) params.set('fp', row.fp);
  if (row.alpn) params.set('alpn', row.alpn);
  params.set('insecure', '0');
  params.set('allowInsecure', '0');
  params.set('type', row.protocol);
  params.set('host', row.host);
  params.set('path', row.path);
  if (row.protocol === 'xhttp') params.set('mode', 'auto');

  const label = `${row.username}-${row.panel_name || 'panel'}-${row.tag || ('inb' + row.inbound_id)}`;
  return `vless://${row.uuid}@${row.address}:${row.external_port}?${params.toString()}#${encodeURIComponent(label)}`;
}

// =========================
// WEB / LOGIN
// =========================
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

app.get('/dash', (req, res) => {
  res.sendFile(__dirname + '/public/dash.html');
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    res.cookie(COOKIE_NAME, COOKIE_VALUE, { httpOnly: true });
    return res.redirect('/dash/view');
  }
  res.status(401).send('نام کاربری یا رمز عبور اشتباه است. <a href="/dash">بازگشت</a>');
});

app.get('/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.redirect('/dash');
});

app.get('/dash/view', requireAuth, (req, res) => {
  res.sendFile(__dirname + '/public/dash-view.html');
});

// =========================
// MASTER APIs
// =========================
if (isMasterEnabled()) {
  // Panels
  app.get('/api/panels', requireAuth, async (req, res) => {
    try {
      const rows = await dbAll(`SELECT * FROM panels ORDER BY id DESC`);
      res.json(rows);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.post('/api/panels', requireAuth, async (req, res) => {
    try {
      const { name, address, is_remote, api_base, api_key } = req.body;
      if (!name || !address) return res.status(400).json({ error: 'name and address are required' });

      const remote = Number(is_remote || 0) ? 1 : 0;
      const result = await dbRun(
        `INSERT INTO panels (name, address, is_remote, api_base, api_key) VALUES (?, ?, ?, ?, ?)`,
        [String(name).trim(), String(address).trim(), remote, api_base || '', api_key || '']
      );

      res.json({ success: true, id: result.lastID });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // Inbounds
  app.get('/api/inbounds', requireAuth, async (req, res) => {
    try {
      const rows = await dbAll(`
        SELECT i.*, p.name AS panel_name, p.address AS panel_address, p.is_remote
        FROM inbounds i
        JOIN panels p ON p.id = i.panel_id
        ORDER BY i.id DESC
      `);
      res.json(rows);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.get('/api/panels/:panelId/inbounds', requireAuth, async (req, res) => {
    try {
      const rows = await dbAll(`SELECT * FROM inbounds WHERE panel_id = ? ORDER BY id DESC`, [req.params.panelId]);
      res.json(rows);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.post('/api/panels/:panelId/inbounds', requireAuth, async (req, res) => {
    try {
      const panelId = Number(req.params.panelId);
      let { tag, port, protocol, host, path, tls, fp, alpn } = req.body;

      if (!port || !protocol || !host || !path) {
        return res.status(400).json({ error: 'port, protocol, host, path are required' });
      }
      if (!['ws', 'xhttp', 'grpc'].includes(protocol)) {
        return res.status(400).json({ error: 'protocol must be ws|xhttp|grpc' });
      }

      path = normalizePath(path);
      if (alpn === 'h2' || alpn === 'h3') alpn = 'http/1.1';

      const panel = await getPanelById(panelId);
      if (!panel) return res.status(404).json({ error: 'panel not found' });

      let remoteInboundId = '';

      // اگر پنل ریموت بود، اول روی Agent بساز
      if (Number(panel.is_remote) === 1) {
        const r = await remoteCall(panel, 'POST', '/agent/inbounds', {
          tag: tag || '',
          port: String(port),
          protocol,
          host: String(host).trim(),
          path,
          tls: tls || 'none',
          fp: fp || '',
          alpn: alpn || 'http/1.1'
        });
        remoteInboundId = String(r.remote_inbound_id || r.id || '');
      }

      // در DB master هم ثبت شود
      const ins = await dbRun(
        `INSERT INTO inbounds (panel_id, remote_inbound_id, tag, port, protocol, host, path, tls, fp, alpn)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          panelId,
          remoteInboundId,
          tag || '',
          String(port),
          protocol,
          String(host).trim(),
          path,
          tls || 'none',
          fp || '',
          alpn || 'http/1.1'
        ]
      );

      // برای local panel باید xray local regenerate شود
      if (Number(panel.is_remote) === 0) {
        await regenerateXrayConfigLocalOnly();
        restartXray();
      }

      res.json({ success: true, id: ins.lastID, remote_inbound_id: remoteInboundId || null });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // Users
  app.get('/api/users', requireAuth, async (req, res) => {
    try {
      const rows = await dbAll(`SELECT * FROM users ORDER BY id DESC`);
      res.json(rows);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.post('/api/users', requireAuth, async (req, res) => {
    try {
      const { username, uuid } = req.body;
      if (!username || !uuid) return res.status(400).json({ error: 'username and uuid are required' });

      const ins = await dbRun(
        `INSERT INTO users (username, uuid) VALUES (?, ?)`,
        [String(username).trim(), String(uuid).trim()]
      );

      res.json({ success: true, id: ins.lastID });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.patch('/api/users/:userId/inbounds', requireAuth, async (req, res) => {
    try {
      const userId = Number(req.params.userId);
      const { inboundIds } = req.body;
      if (!Array.isArray(inboundIds)) return res.status(400).json({ error: 'inboundIds must be array' });

      // 1) replace local mapping
      await dbRun(`DELETE FROM user_inbound_access WHERE user_id = ?`, [userId]);
      for (const inbId of inboundIds) {
        await dbRun(
          `INSERT OR IGNORE INTO user_inbound_access (user_id, inbound_id) VALUES (?, ?)`,
          [userId, Number(inbId)]
        );
      }

      // 2) sync to remotes grouped by panel
      const rows = await dbAll(`
        SELECT i.id AS inbound_id, i.remote_inbound_id, i.panel_id, p.is_remote, p.api_base, p.api_key
        FROM inbounds i
        JOIN panels p ON p.id = i.panel_id
        WHERE i.id IN (${inboundIds.length ? inboundIds.map(() => '?').join(',') : 'NULL'})
      `, inboundIds.map(Number));

      const user = await dbGet(`SELECT * FROM users WHERE id = ?`, [userId]);
      if (!user) return res.status(404).json({ error: 'user not found' });

      // ساخت کاربر روی هر ریموت (idempotent ساده: تلاش به create و در صورت خطا ادامه)
      const remotePanels = {};
      for (const r of rows) {
        if (Number(r.is_remote) === 1) {
          if (!remotePanels[r.panel_id]) remotePanels[r.panel_id] = { panel: r, inboundRemoteIds: [] };
          if (r.remote_inbound_id) remotePanels[r.panel_id].inboundRemoteIds.push(Number(r.remote_inbound_id));
        }
      }

      for (const pid of Object.keys(remotePanels)) {
        const panel = remotePanels[pid].panel;
        const inboundRemoteIds = remotePanels[pid].inboundRemoteIds;

        // ensure remote user exists (simple create-first)
        let remoteUserId = null;
        try {
          const ru = await remoteCall(panel, 'POST', '/agent/users', {
            username: user.username,
            uuid: user.uuid
          });
          remoteUserId = Number(ru.remote_user_id || ru.id);
        } catch (e) {
          // اگر user duplicate بود، تلاش برای find
          const find = await remoteCall(panel, 'GET', `/agent/users/find?uuid=${encodeURIComponent(user.uuid)}`);
          remoteUserId = Number(find.remote_user_id || find.id);
        }

        await remoteCall(panel, 'PATCH', `/agent/users/${remoteUserId}/inbounds`, {
          inboundIds: inboundRemoteIds
        });
      }

      // 3) regenerate local xray فقط برای inboundهای local
      await regenerateXrayConfigLocalOnly();
      restartXray();

      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.get('/api/users-with-access', requireAuth, async (req, res) => {
    try {
      const rows = await dbAll(`
        SELECT
          u.id AS user_id, u.username, u.uuid,
          i.id AS inbound_id, i.tag, i.protocol, i.host, i.path, i.tls, i.fp, i.alpn,
          i.port AS external_port,
          p.name AS panel_name, p.address, p.is_remote
        FROM users u
        LEFT JOIN user_inbound_access a ON a.user_id = u.id
        LEFT JOIN inbounds i ON i.id = a.inbound_id
        LEFT JOIN panels p ON p.id = i.panel_id
        ORDER BY u.id DESC, i.id DESC
      `);

      const map = new Map();
      for (const r of rows) {
        if (!map.has(r.user_id)) {
          map.set(r.user_id, {
            user_id: r.user_id,
            username: r.username,
            uuid: r.uuid,
            inbounds: [],
            links: []
          });
        }
        if (r.inbound_id) {
          const item = map.get(r.user_id);
          item.inbounds.push({
            inbound_id: r.inbound_id,
            tag: r.tag,
            protocol: r.protocol,
            host: r.host,
            path: r.path,
            panel_name: r.panel_name,
            is_remote: Number(r.is_remote) === 1
          });
          item.links.push({
            inbound_id: r.inbound_id,
            protocol: r.protocol,
            host: r.host,
            path: r.path,
            link: buildVlessLink({
              ...r,
              username: r.username,
              panel_name: r.panel_name
            })
          });
        }
      }

      res.json(Array.from(map.values()));
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });
}

// =========================
// AGENT APIs (remote side)
// =========================
if (isAgentEnabled()) {
  // Health
  app.get('/agent/health', requireAgent, (req, res) => {
    res.json({ ok: true, role: NODE_ROLE });
  });

  // find user by uuid (for upsert from master)
  app.get('/agent/users/find', requireAgent, async (req, res) => {
    try {
      const uuid = String(req.query.uuid || '').trim();
      if (!uuid) return res.status(400).json({ error: 'uuid is required' });

      const row = await dbGet(`SELECT id, username, uuid FROM users WHERE uuid = ?`, [uuid]);
      if (!row) return res.status(404).json({ error: 'not found' });

      res.json({ success: true, remote_user_id: row.id, ...row });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // create inbound on this node
  app.post('/agent/inbounds', requireAgent, async (req, res) => {
    try {
      let { tag, port, protocol, host, path, tls, fp, alpn } = req.body;

      if (!port || !protocol || !host || !path) {
        return res.status(400).json({ error: 'port, protocol, host, path are required' });
      }
      if (!['ws', 'xhttp', 'grpc'].includes(protocol)) {
        return res.status(400).json({ error: 'protocol must be ws|xhttp|grpc' });
      }

      path = normalizePath(path);
      if (alpn === 'h2' || alpn === 'h3') alpn = 'http/1.1';

      // on agent, panel_id can be 1(local virtual panel). ensure exists.
      let localPanel = await dbGet(`SELECT * FROM panels WHERE is_remote = 0 ORDER BY id ASC LIMIT 1`);
      if (!localPanel) {
        const hostGuess = process.env.PUBLIC_HOST || 'localhost';
        const insPanel = await dbRun(
          `INSERT INTO panels (name, address, is_remote, api_base, api_key) VALUES (?, ?, 0, '', '')`,
          ['LocalAgentPanel', hostGuess]
        );
        localPanel = await dbGet(`SELECT * FROM panels WHERE id = ?`, [insPanel.lastID]);
      }

      const ins = await dbRun(
        `INSERT INTO inbounds (panel_id, tag, port, protocol, host, path, tls, fp, alpn)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          localPanel.id,
          tag || '',
          String(port),
          protocol,
          String(host).trim(),
          path,
          tls || 'none',
          fp || '',
          alpn || 'http/1.1'
        ]
      );

      await regenerateXrayConfigLocalOnly();
      restartXray();

      res.json({ success: true, remote_inbound_id: ins.lastID });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // create user on agent
  app.post('/agent/users', requireAgent, async (req, res) => {
    try {
      const { username, uuid } = req.body;
      if (!username || !uuid) return res.status(400).json({ error: 'username and uuid are required' });

      // if exists by uuid, return existing
      const exists = await dbGet(`SELECT id FROM users WHERE uuid = ?`, [String(uuid).trim()]);
      if (exists) return res.json({ success: true, remote_user_id: exists.id, existed: true });

      const ins = await dbRun(
        `INSERT INTO users (username, uuid) VALUES (?, ?)`,
        [String(username).trim(), String(uuid).trim()]
      );
      res.json({ success: true, remote_user_id: ins.lastID });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // set access on agent user
  app.patch('/agent/users/:userId/inbounds', requireAgent, async (req, res) => {
    try {
      const userId = Number(req.params.userId);
      const inboundIds = Array.isArray(req.body.inboundIds) ? req.body.inboundIds.map(Number) : null;
      if (!inboundIds) return res.status(400).json({ error: 'inboundIds must be array' });

      await dbRun(`DELETE FROM user_inbound_access WHERE user_id = ?`, [userId]);
      for (const id of inboundIds) {
        await dbRun(
          `INSERT OR IGNORE INTO user_inbound_access (user_id, inbound_id) VALUES (?, ?)`,
          [userId, id]
        );
      }

      await regenerateXrayConfigLocalOnly();
      restartXray();

      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });
}

// =========================
// XRAY GENERATION (LOCAL ONLY)
// =========================
let hostPathToPortMap = {}; // key host|path -> internalPort
let pathToPortFallback = {}; // path -> internalPort
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
  // فقط inbounds پنل‌های local (is_remote=0) که access دارند
  const rows = await dbAll(`
    SELECT
      u.username, u.uuid,
      i.id AS inbound_id, i.protocol, i.host, i.path
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
    byInbound.get(r.inbound_id).clients.push({
      id: r.uuid,
      email: r.username,
      flow: ""
    });
  }

  const inbounds = [];
  const routeRows = [];

  for (const inbound of byInbound.values()) {
    const internalPort = XRAY_BASE_PORT + Number(inbound.inbound_id);

    const ib = {
      listen: "127.0.0.1",
      port: internalPort,
      protocol: "vless",
      settings: {
        clients: inbound.clients,
        decryption: "none"
      },
      streamSettings: {
        network: inbound.protocol,
        security: "none"
      },
      sniffing: {
        enabled: true,
        destOverride: ["http", "tls"]
      }
    };

    if (inbound.protocol === 'ws') {
      ib.streamSettings.wsSettings = {
        path: inbound.path,
        headers: { Host: inbound.host }
      };
    } else if (inbound.protocol === 'xhttp') {
      ib.streamSettings.xhttpSettings = {
        path: inbound.path,
        host: inbound.host,
        mode: "auto"
      };
    } else if (inbound.protocol === 'grpc') {
      ib.streamSettings.grpcSettings = {
        serviceName: inbound.path.replace(/^\//, '')
      };
    }

    inbounds.push(ib);
    routeRows.push({ inbound_id: inbound.inbound_id, host: inbound.host, path: inbound.path });
  }

  if (inbounds.length === 0) {
    inbounds.push({
      listen: "127.0.0.1",
      port: XRAY_BASE_PORT,
      protocol: "vless",
      settings: {
        clients: [{ id: "00000000-0000-0000-0000-000000000000" }],
        decryption: "none"
      },
      streamSettings: {
        network: "ws",
        security: "none",
        wsSettings: { path: "/none" }
      }
    });
  }

  const config = {
    log: { loglevel: "warning" },
    inbounds,
    outbounds: [
      { protocol: "freedom", tag: "direct" },
      { protocol: "blackhole", tag: "block" }
    ]
  };

  fs.writeFileSync('/tmp/xray-config.json', JSON.stringify(config, null, 2));
  updateRouteMaps(routeRows);
}

function restartXray() {
  if (xrayProcess) {
    xrayProcess.kill();
    xrayProcess = null;
  }
  if (!fs.existsSync('/tmp/xray-config.json')) return;

  xrayProcess = spawn('xray', ['-c', '/tmp/xray-config.json']);
  xrayProcess.stdout.on('data', d => console.log('XRAY:', d.toString().trim()));
  xrayProcess.stderr.on('data', d => console.error('XRAY ERR:', d.toString().trim()));
  xrayProcess.on('exit', code => console.log('Xray exited with code', code));
}

// =========================
// PROXY (LAST)
// =========================
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

// =========================
// BOOT
// =========================
(async () => {
  try {
    await regenerateXrayConfigLocalOnly();
    restartXray();

    server.listen(PORT, () => {
      console.log(`✅ Panel running on :${PORT}`);
      console.log(`Role: ${NODE_ROLE}`);
      console.log(`Admin: ${ADMIN_USER}`);
      if (isAgentEnabled()) console.log(`Agent enabled. AGENT_KEY is set: ${AGENT_KEY !== 'change-me-agent-key'}`);
    });
  } catch (e) {
    console.error('Boot error:', e);
    process.exit(1);
  }
})();
