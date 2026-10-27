'use strict';

/**
 * lab-server - server HTTP lokal dengan kerentanan SENGAJA untuk menguji scanner.
 * HANYA untuk pengujian internal di 127.0.0.1. JANGAN dijalankan di publik.
 *
 * Kerentanan yang ditanam:
 *  1. Header keamanan hilang (CSP, HSTS n/a http, XFO, XCTO, RP)
 *  2. Cookie tanpa Secure/HttpOnly/SameSite
 *  3. /.env terekspos
 *  4. /.git/HEAD terekspos
 *  5. Directory listing di /backup/
 *  6. CORS merefleksikan Origin arbitrer + credentials
 *  7. Open redirect /redirect?url=<eksternal>
 *  8. Reflected XSS tanpa encoding /search?q=
 *  9. SQL error disclosure /user?id=' (pola error MySQL)
 * 10. Server version disclosure (Server header)
 * 11. Secret bocor di /app.js (AWS key + Google API key PALSU)
 * 12. phpinfo-like page /phpinfo.php
 */

const http = require('http');

const PORT = parseInt(process.env.LAB_PORT || '7777', 10);

const APP_JS = `// demo app bundle
window.cfg = { apiKey: "AIzaSyA2xWqR9pLmN0vTzYcXk1JhGfD5sBqWqE", env: "prod" };
// staging aws credentials (FAKE - dummy test data)
const awsKey = "AKIAIOSFODNN7EXAMPLE";
const awsSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
`;

const routes = {
  '/': (req, res) => {
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Server': 'nginx/1.14.0 (Ubuntu)',
      'Set-Cookie': 'session=abc123; Path=/',
      'X-Powered-By': 'Express',
    });
    res.end(`<!DOCTYPE html><html><head><title>Lab Shop</title></head><body>
<h1>Lab Shop</h1>
<script src="/app.js"></script>
<a href="/user?id=1">User</a>
<a href="/search?q=test">Search</a>
<a href="/redirect?url=https://example.com">External</a>
<a href="/api/data">API</a>
<a href="/backup/">Backups</a>
<a href="/admin">Admin</a>
</body></html>`);
  },
  '/app.js': (req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/javascript' });
    res.end(APP_JS);
  },
  '/.env': (req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('DB_PASSWORD=supersecret123\nAPI_KEY=dummy-key-not-real\n');
  },
  '/.git/HEAD': (req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ref: refs/heads/main\n');
  },
  '/backup/': (req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end('<html><head><title>Index of /backup/</title></head><body><h1>Index of /backup/</h1><ul><li><a href="db-2024.sql">db-2024.sql</a></li></ul></body></html>');
  },
  '/phpinfo.php': (req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><head><title>phpinfo()</title></head><body><h1>PHP Version 7.4.3</h1>phpinfo() output...</body></html>');
  },
};

const server = http.createServer((req, res) => {
  const u = new URL(req.url, `http://127.0.0.1:${PORT}`);
  const path = u.pathname;

  if (routes[path]) return routes[path](req, res);

  // CORS reflection vulnerability
  if (path === '/api/data') {
    const origin = req.headers.origin || '*';
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Credentials': 'true',
    });
    res.end(JSON.stringify({ ok: true, secret: 'internal-data' }));
    return;
  }

  // Open redirect
  if (path === '/redirect') {
    const target = u.searchParams.get('url') || '/';
    res.writeHead(302, { Location: target });
    res.end();
    return;
  }

  // Reflected XSS (tanpa encoding)
  if (path === '/search') {
    const q = u.searchParams.get('q') || '';
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Server': 'nginx/1.14.0' });
    res.end(`<html><head><title>Search</title></head><body><h1>Hasil untuk: ${q}</h1><p>tidak ada hasil</p></body></html>`);
    return;
  }

  // SQL error disclosure
  if (path === '/user') {
    const id = u.searchParams.get('id') || '';
    if (id.includes("'")) {
      res.writeHead(500, { 'Content-Type': 'text/html' });
      res.end('<html><body><pre>Warning: mysqli_query(): You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near \'\'\' at line 1</pre></body></html>');
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<html><head><title>User</title></head><body><h1>User ${id}</h1></body></html>`);
    return;
  }

  if (path === '/admin') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Server': 'nginx/1.14.0' });
    res.end('<html><head><title>Admin Login</title></head><body><form><input name="password" type="password"><button>Sign in</button></form></body></html>');
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/html', 'Server': 'nginx/1.14.0' });
  res.end('<html><head><title>404</title></head><body><h1>404 Not Found</h1></body></html>');
});

if (require.main === module) {
  server.listen(PORT, '127.0.0.1', () => {
    process.stdout.write(`Lab server (rentan SENGAJA) berjalan di http://127.0.0.1:${PORT}\n`);
  });
}

module.exports = { server, PORT };
