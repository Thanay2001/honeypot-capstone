// src/honeypot.js
// Lightweight honeypot providing simple TCP and HTTP listeners
// Exports start() and stop(), and appends events to logs/events.log

const net = require('net');
const http = require('http');
const fs = require('fs');
const path = require('path');

const LOG_DIR = path.resolve(__dirname, '..', 'logs');
const LOG_FILE = path.join(LOG_DIR, 'events.log');
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });

function appendEvent(obj) {
  try {
    fs.appendFileSync(LOG_FILE, JSON.stringify(obj) + '\n');
  } catch (err) {
    // keep process alive, but log to stderr
    console.error('Failed to write log:', err);
  }
}

function isoTime() { return new Date().toISOString(); }

function fakeBanner(port) {
  switch (port) {
    case 22: return 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3\r\n';
    case 23: return 'Welcome to telnetd\r\n';
    case 80:
    case 8080:
      return null; // HTTP handled separately
    case 445: return 'SMB Service Ready\r\n';
    default: return '220 FakeService Ready\r\n';
  }
}

let _servers = [];

function startTcpListener(port) {
  const server = net.createServer((socket) => {
    const remote = socket.remoteAddress + ':' + socket.remotePort;
    const start = Date.now();
    const chunks = [];
    socket.setTimeout(3000);

    socket.on('data', (chunk) => {
      chunks.push(chunk);
      // defensive cap: if attacker sends a lot, cut off
      if (Buffer.concat(chunks).length > 256 * 1024) {
        try { socket.end(); } catch (e) {}
      }
    });

    socket.on('end', () => {
      const payload = Buffer.concat(chunks);
      appendEvent({
        timestamp: isoTime(),
        type: 'tcp',
        listener_port: port,
        remote,
        payload_b64: payload.toString('base64'),
        payload_len: payload.length,
        duration_ms: Date.now() - start
      });
    });

    socket.on('timeout', () => {
      const banner = fakeBanner(port);
      if (banner) {
        try { socket.write(banner); } catch (e) {}
      }
      try { socket.end(); } catch (e) {}
    });

    socket.on('error', (err) => {
      appendEvent({
        timestamp: isoTime(),
        type: 'tcp',
        listener_port: port,
        remote,
        error: String(err)
      });
    });
  });

  server.on('error', (err) => console.error(`Listener ${port} error:`, err));
  server.listen(port, () => console.log(`TCP honeypot listening on ${port}`));
  return server;
}

function startHttpListener(port) {
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      appendEvent({
        timestamp: isoTime(),
        type: 'http',
        listener_port: port,
        remote: req.socket.remoteAddress + ':' + req.socket.remotePort,
        method: req.method,
        url: req.url,
        headers: req.headers,
        body_b64: body.toString('base64'),
        body_len: body.length
      });

      const html = '<html><body><h1>It works</h1></body></html>';
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Length': Buffer.byteLength(html)
      });
      res.end(html);
    });
  });

  server.on('error', (err) => console.error('HTTP listener error:', err));
  server.listen(port, () => console.log(`HTTP honeypot listening on ${port}`));
  return server;
}

// Default configuration. Can be mutated before calling start() in tests.
const config = {
  tcpPorts: [23],      // match tests which connect to port 23
  httpPorts: [8080],   // match tests which connect to port 8080
};

function start() {
  // don't start twice
  if (_servers.length) return _servers;

  config.tcpPorts.forEach((p) => {
    try {
      _servers.push(startTcpListener(p));
    } catch (e) {
      console.error('Failed to start TCP listener on', p, e);
    }
  });
  config.httpPorts.forEach((p) => {
    try {
      _servers.push(startHttpListener(p));
    } catch (e) {
      console.error('Failed to start HTTP listener on', p, e);
    }
  });

  return _servers;
}

function stop() {
  for (const s of _servers) {
    try { s.close(); } catch (e) { /* ignore */ }
  }
  _servers = [];
}

module.exports = {
  start,
  stop,
  config,
  _appendEvent: appendEvent,
  _logFile: LOG_FILE
};

if (require.main === module) {
  start();
}
