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

const PORT = process.env.PORT || 3000;
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin';
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
  // legacy table (برای سازگاری)
  db.run(`
    CREATE TABLE IF NOT EXISTS configs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      address TEXT,
      port TEXT,
      uuid TEXT,
      protocol TEXT,
      host TEXT,
      path TEXT,
      tls TEXT,
      fp TEXT,
      alpn TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS panels (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      address TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS inbounds (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      panel_id INTEGER NOT NULL,
      tag TEXT DEFAULT '',
      port TEXT NOT NULL,
      protocol TEXT NOT NULL, -- ws | xhttp | grpc
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
  res.redirect('/dash');
}

// =========================
// STATIC / PAGES
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
  res.send('نام کاربری یا رمز عبور اشتباه است. <a href="/dash">بازگشت</a>');
});

app.get('/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.redirect('/dash');
});

app.get('/dash/view', requireAuth, (req, res) => {
  res.sendFile(__dirname + '/public/dash-view.html');
});

// =========================
// HELPERS
// =========================
function normalizeHost(h) {
  if (!h) return '';
  return String(h).split(':')[0].toLowerCase();
}
function normalizePath(p) {
  if (!p) return '/';
  return p.startsWith('/') ? p : '/' + p;
}
function matchPath(reqPath, basePath) {
  return reqPath === basePath || reqPath.startsWith(basePath + '/');
}
function makeHostPathKey(host, path) {
  return `${normalizeHost(host)}|${normalizePath(path)}`;
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
// API: PANELS
// =========================
app.get('/api/panels', requireAuth, (req, res) => {
  db.all(`SELECT * FROM panels ORDER BY id DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/panels', requireAuth, (req, res) => {
  const { name, address } = req.body;
  if (!name || !address) {
    return res.status(400).json({ error: 'name and address are required' });
  }

  db.run(
    `INSERT INTO panels (name, address) VALUES (?, ?)`,
    [String(name).trim(), String(address).trim()],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, id: this.lastID });
    }
  );
});

// =========================
// API: INBOUNDS
// =========================
app.get('/api/inbounds', requireAuth, (req, res) => {
  const sql = `
    SELECT i.*, p.name as panel_name, p.address as panel_address
    FROM inbounds i
    JOIN panels p ON p.id = i.panel_id
    ORDER BY i.id DESC
  `;
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/api/panels/:panelId/inbounds', requireAuth, (req, res) => {
  const { panelId } = req.params;
  db.all(
    `SELECT * FROM inbounds WHERE panel_id = ? ORDER BY id DESC`,
    [panelId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

app.post('/api/panels/:panelId/inbounds', requireAuth, (req, res) => {
  const { panelId } = req.params;
  let { tag, port, protocol, host, path, tls, fp, alpn } = req.body;

  if (!port || !protocol || !host || !path) {
    return res.status(400).json({ error: 'port, protocol, host, path are required' });
  }
  if (!['ws', 'xhttp', 'grpc'].includes(protocol)) {
    return res.status(400).json({ error: 'protocol must be ws | xhttp | grpc' });
  }

  path = normalizePath(path);
  if (alpn === 'h2' || alpn === 'h3') alpn = 'http/1.1';

  db.run(
    `INSERT INTO inbounds (panel_id, tag, port, protocol, host, path, tls, fp, alpn)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      panelId,
      tag || '',
      String(port),
      protocol,
      String(host).trim(),
      path,
      tls || 'none',
      fp || '',
      alpn || 'http/1.1'
    ],
    async function (err) {
      if (err) return res.status(500).json({ error: err.message });

      try {
        await regenerateXrayConfigV2();
        restartXray();
        res.json({ success: true, id: this.lastID });
      } catch (e) {
        res.json({ success: true, id: this.lastID, warning: e.message });
      }
    }
  );
});

app.delete('/api/inbounds/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  db.run(`DELETE FROM inbounds WHERE id = ?`, [id], async function (err) {
    if (err) return res.status(500).json({ error: err.message });

    try {
      await regenerateXrayConfigV2();
      restartXray();
      res.json({ success: true, changes: this.changes });
    } catch (e) {
      res.json({ success: true, changes: this.changes, warning: e.message });
    }
  });
});

// =========================
// API: USERS
// =========================
app.get('/api/users', requireAuth, (req, res) => {
  db.all(`SELECT * FROM users ORDER BY id DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/users', requireAuth, (req, res) => {
  const { username, uuid } = req.body;
  if (!username || !uuid) {
    return res.status(400).json({ error: 'username and uuid are required' });
  }

  db.run(
    `INSERT INTO users (username, uuid) VALUES (?, ?)`,
    [String(username).trim(), String(uuid).trim()],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, id: this.lastID });
    }
  );
});

app.get('/api/users/:userId/inbounds', requireAuth, (req, res) => {
  const { userId } = req.params;
  const sql = `
    SELECT i.*, p.name as panel_name, p.address as panel_address
    FROM user_inbound_access a
    JOIN inbounds i ON i.id = a.inbound_id
    JOIN panels p ON p.id = i.panel_id
    WHERE a.user_id = ?
    ORDER BY i.id DESC
  `;
  db.all(sql, [userId], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.patch('/api/users/:userId/inbounds', requireAuth, (req, res) => {
  const { userId } = req.params;
  const { inboundIds } = req.body;

  if (!Array.isArray(inboundIds)) {
    return res.status(400).json({ error: 'inboundIds must be array' });
  }

  db.serialize(() => {
    db.run(`DELETE FROM user_inbound_access WHERE user_id = ?`, [userId], (err) => {
      if (err) return res.status(500).json({ error: err.message });

      if (inboundIds.length === 0) {
        regenerateXrayConfigV2()
          .then(() => {
            restartXray();
            res.json({ success: true });
          })
          .catch(e => res.json({ success: true, warning: e.message }));
        return;
      }

      const stmt = db.prepare(
        `INSERT OR IGNORE INTO user_inbound_access (user_id, inbound_id) VALUES (?, ?)`
      );
      inboundIds.forEach(inbId => stmt.run([userId, inbId]));
      stmt.finalize(async (err2) => {
        if (err2) return res.status(500).json({ error: err2.message });

        try {
          await regenerateXrayConfigV2();
          restartXray();
          res.json({ success: true });
        } catch (e) {
          res.json({ success: true, warning: e.message });
        }
      });
    });
  });
});

// برای داشبورد جدید
app.get('/api/users-with-access', requireAuth, (req, res) => {
  const sql = `
    SELECT
      u.id as user_id,
      u.username,
      u.uuid,
      i.id as inbound_id,
      i.tag,
      i.protocol,
      i.host,
      i.path,
      i.tls,
      i.fp,
      i.alpn,
      i.port as external_port,
      p.name as panel_name,
      p.address
    FROM users u
    LEFT JOIN user_inbound_access a ON a.user_id = u.id
    LEFT JOIN inbounds i ON i.id = a.inbound_id
    LEFT JOIN panels p ON p.id = i.panel_id
    ORDER BY u.id DESC, i.id DESC
  `;

  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });

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
          panel_name: r.panel_name
        });

        item.links.push({
          inbound_id: r.inbound_id,
          protocol: r.protocol,
          host: r.host,
          path: r.path,
          link: buildVlessLink({
            ...r,
            username: r.username,
            uuid: r.uuid
          })
        });
      }
    }

    res.json(Array.from(map.values()));
  });
});

// لینک‌های یک کاربر
app.get('/api/users/:userId/links', requireAuth, (req, res) => {
  const { userId } = req.params;

  const sql = `
    SELECT
      u.username, u.uuid,
      i.id as inbound_id, i.tag, i.protocol, i.host, i.path, i.tls, i.fp, i.alpn,
      i.port as external_port,
      p.name as panel_name, p.address
    FROM user_inbound_access a
    JOIN users u ON u.id = a.user_id
    JOIN inbounds i ON i.id = a.inbound_id
    JOIN panels p ON p.id = i.panel_id
    WHERE u.id = ?
    ORDER BY i.id DESC
  `;

  db.all(sql, [userId], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });

    const links = rows.map(r => ({
      inbound_id: r.inbound_id,
      panel_name: r.panel_name,
      protocol: r.protocol,
      host: r.host,
      path: r.path,
      link: buildVlessLink({
        ...r,
        username: r.username,
        uuid: r.uuid
      })
    }));

    res.json(links);
  });
});

// Legacy endpoint (اختیاری)
app.get('/api/configs', requireAuth, (req, res) => {
  db.all(`SELECT * FROM configs ORDER BY id DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// =========================
// XRAY CONFIG + ROUTING MAP
// =========================
let hostPathToPortMap = {}; // `${host}|${path}` -> internalPort
let pathToPortFallback = {}; // `path` -> internalPort

function updateRouteMaps(inboundsRows) {
  hostPathToPortMap = {};
  pathToPortFallback = {};

  for (const r of inboundsRows) {
    const internalPort = XRAY_BASE_PORT + r.inbound_id;
    const host = normalizeHost(r.host);
    const path = normalizePath(r.path);

    hostPathToPortMap[makeHostPathKey(host, path)] = internalPort;
    pathToPortFallback[path] = internalPort; // fallback
  }
}

function getTargetPort(reqLike) {
  const reqHost = normalizeHost(reqLike.headers?.host || '');
  const reqPath = normalizePath(reqLike.path || reqLike.url || '/');

  // اولویت: host + path
  for (const [key, port] of Object.entries(hostPathToPortMap)) {
    const [h, p] = key.split('|');
    if (h === reqHost && matchPath(reqPath, p)) return port;
  }

  // fallback فقط path
  for (const [p, port] of Object.entries(pathToPortFallback)) {
    if (matchPath(reqPath, p)) return port;
  }

  return null;
}

function regenerateXrayConfigV2() {
  return new Promise((resolve, reject) => {
    const sql = `
      SELECT
        u.id as user_id, u.username, u.uuid,
        i.id as inbound_id, i.protocol, i.host, i.path, i.tls, i.fp, i.alpn
      FROM user_inbound_access a
      JOIN users u ON u.id = a.user_id
      JOIN inbounds i ON i.id = a.inbound_id
      ORDER BY i.id, u.id
    `;

    db.all(sql, [], (err, rows) => {
      if (err) return reject(err);

      const byInbound = new Map();
      for (const r of rows) {
        if (!byInbound.has(r.inbound_id)) {
          byInbound.set(r.inbound_id, {
            inbound_id: r.inbound_id,
            protocol: r.protocol,
            host: r.host,
            path: r.path,
            tls: r.tls,
            fp: r.fp,
            alpn: r.alpn,
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
        const internalPort = XRAY_BASE_PORT + inbound.inbound_id;

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
        routeRows.push({
          inbound_id: inbound.inbound_id,
          host: inbound.host,
          path: inbound.path
        });
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
      resolve();
    });
  });
}

// =========================
// XRAY PROCESS
// =========================
let xrayProcess = null;

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
// PROXY (حتماً آخر route ها)
// =========================

// HTTP Proxy
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

// WebSocket Proxy
server.on('upgrade', (req, socket, head) => {
  const fakeReq = {
    headers: req.headers,
    path: (req.url || '/').split('?')[0]
  };

  const targetPort = getTargetPort(fakeReq);
  if (!targetPort) {
    socket.destroy();
    return;
  }

  const proxyReq = http.request({
    hostname: '127.0.0.1',
    port: targetPort,
    path: req.url,
    method: req.method,
    headers: req.headers
  });

  proxyReq.on('upgrade', (proxyRes, proxySocket, proxyHead) => {
    socket.write(`HTTP/1.1 101 Switching Protocols\r\n`);
    Object.keys(proxyRes.headers).forEach(key => {
      socket.write(`${key}: ${proxyRes.headers[key]}\r\n`);
    });
    socket.write('\r\n');

    if (proxyHead && proxyHead.length) proxySocket.unshift(proxyHead);
    if (head && head.length) socket.unshift(head);

    proxySocket.pipe(socket);
    socket.pipe(proxySocket);

    proxySocket.on('error', err => {
      console.error('proxySocket error:', err.message);
      socket.destroy();
    });
    socket.on('error', err => {
      console.error('clientSocket error:', err.message);
      proxySocket.destroy();
    });
    proxySocket.on('close', () => socket.destroy());
    socket.on('close', () => proxySocket.destroy());
  });

  proxyReq.on('error', err => {
    console.error('WS upgrade request error:', err.message);
    socket.destroy();
  });

  proxyReq.on('response', res => {
    if (!socket.destroyed) {
      socket.write(`HTTP/1.1 ${res.statusCode} ${res.statusMessage}\r\n`);
      Object.keys(res.headers).forEach(key => {
        socket.write(`${key}: ${res.headers[key]}\r\n`);
      });
      socket.write('\r\n');
      res.pipe(socket);
    }
  });

  req.pipe(proxyReq);
});

// =========================
// BOOT
// =========================
(async () => {
  try {
    await regenerateXrayConfigV2();
    restartXray();

    server.listen(PORT, () => {
      console.log(`Panel running on port ${PORT}`);
      console.log(`Admin user: ${ADMIN_USER}`);
    });
  } catch (e) {
    console.error('Boot error:', e);
    process.exit(1);
  }
})();
