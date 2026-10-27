'use strict';

/**
 * VulnScanInternalEngine - pemindai kerentanan INTERNAL (pengganti nuclei).
 * 100% Node murni, non-destruktif, GET/OPTIONS saja, tanpa payload merusak.
 *
 * Cakupan pemeriksaan (indikator, wajib verifikasi manual):
 *  1.  Security header lengkap + analisis kelemahan CSP
 *  2.  Cookie flags (Secure/HttpOnly/SameSite)
 *  3.  CORS misconfiguration (reflected origin, wildcard+credentials)
 *  4.  Open redirect (parameter umum, kanari domain khusus)
 *  5.  Reflected XSS (marker aman, deteksi refleksi tanpa encoding)
 *  6.  SQLi error-based signature (hanya pola error DB pada respons)
 *  7.  Path traversal signature (../../etc/passwd via param, read-only)
 *  8.  File/path sensitif terekspos (.env, .git, backup, debug, actuator, dll)
 *  9.  Directory listing
 *  10. HTTP methods berbahaya (TRACE/PUT/DELETE via OPTIONS/TRACE)
 *  11. Mixed content (HTTP resource di halaman HTTPS)
 *  12. TLS lemah / sertifikat kedaluwarsa
 *  13. Info disclosure (server version, phpinfo, stack trace, private IP, email)
 *  14. Indikasi subdomain takeover (CNAME ke layanan mati + fingerprint)
 *  15. Clickjacking (XFO/frame-ancestors tidak ada)
 *  16. robots.txt/sitemap/security.txt (informatif: endpoint menarik)
 */

const tls = require('tls');
const { requestPinned, requestFollow, RateLimiter, mapPool, sleep, extractTitle } = require('./internal/netClient');
const { detectTech } = require('./internal/techKit');

const REDIRECT_CANARY = 'cxl-rd-check.example.net';
const XSS_MARKER = 'cxlp0i';
const XSS_PAYLOAD = `${XSS_MARKER}"><svg/onload=${XSS_MARKER}>`;
const SQLI_PROBE = "'";

const SQL_ERROR_SIGNATURES = [
  { re: /You have an error in your SQL syntax/i, db: 'MySQL' },
  { re: /Warning: mysql_\w+\(\)|mysqli?::query/i, db: 'MySQL' },
  { re: /Unclosed quotation mark after the character string/i, db: 'MSSQL' },
  { re: /Microsoft OLE DB Provider for SQL Server/i, db: 'MSSQL' },
  { re: /unterminated quoted string at or near/i, db: 'PostgreSQL' },
  { re: /PG::SyntaxError|ERROR:\s+syntax error at or near/i, db: 'PostgreSQL' },
  { re: /ORA-\d{5}:|quoted string not properly terminated/i, db: 'Oracle' },
  { re: /SQLite3?::query|SQLITE_ERROR|unrecognized token/i, db: 'SQLite' },
];

// Signature isi /etc/passwd yang SANGAT spesifik (hindari false positive HTML).
const PATH_TRAVERSAL_SIGNATURE = /root:[x*!]:0:0:0?:(?:\/root)?(?:\/[^:\n]*)?:\s*$|^\s*root@|daemon:\s*\/usr\/sbin|\[boot loader\]\s*$/im;

const EXPOSED_PATHS = [
  { path: '/.env', severity: 'critical', sig: null, sigType: 'nonhtml200', owasp: 'A02', name: 'File .env terekspos' },
  { path: '/.env.local', severity: 'critical', sig: null, sigType: 'nonhtml200', owasp: 'A02', name: 'File .env.local terekspos' },
  { path: '/.git/HEAD', severity: 'high', sig: /^ref:\s+\w+/m, sigType: 'body', owasp: 'A02', name: 'Repository .git terekspos' },
  { path: '/.git/config', severity: 'high', sig: /\[core\]|repositoryformatversion/, sigType: 'body', owasp: 'A02', name: 'Konfigurasi .git terekspos' },
  { path: '/.svn/entries', severity: 'high', sig: /\d+\n?dir/, sigType: 'body', owasp: 'A02', name: 'Metadata SVN terekspos' },
  { path: '/.DS_Store', severity: 'low', sig: null, sigType: 'magic', owasp: 'A02', name: 'File .DS_Store terekspos' },
  { path: '/.htaccess', severity: 'medium', sig: /<Files|RewriteRule|Deny from|Require /i, sigType: 'body', owasp: 'A02', name: 'File .htaccess terekspos' },
  { path: '/web.config', severity: 'medium', sig: /<configuration|<system\.web/i, sigType: 'body', owasp: 'A02', name: 'web.config terekspos' },
  { path: '/backup.zip', severity: 'critical', sig: /^PK\x03\x04/, sigType: 'magic', owasp: 'A02', name: 'Arsip backup.zip terekspos' },
  { path: '/backup.tar.gz', severity: 'critical', sig: /^\x1f\x8b/, sigType: 'magic', owasp: 'A02', name: 'Arsip backup.tar.gz terekspos' },
  { path: '/db.sql', severity: 'critical', sig: /INSERT INTO|CREATE TABLE|-- MySQL dump/i, sigType: 'body', owasp: 'A02', name: 'Dump database terekspos' },
  { path: '/database.sql', severity: 'critical', sig: /INSERT INTO|CREATE TABLE|-- MySQL dump/i, sigType: 'body', owasp: 'A02', name: 'Dump database terekspos' },
  { path: '/dump.sql', severity: 'critical', sig: /INSERT INTO|CREATE TABLE|-- MySQL dump/i, sigType: 'body', owasp: 'A02', name: 'Dump database terekspos' },
  { path: '/composer.json', severity: 'medium', sig: /"require"\s*:/, sigType: 'body', owasp: 'A03', name: 'composer.json terekspos' },
  { path: '/package.json', severity: 'low', sig: /"name"\s*:/, sigType: 'body', owasp: 'A03', name: 'package.json terekspos' },
  { path: '/.aws/credentials', severity: 'critical', sig: /\[default\]|aws_access_key_id/i, sigType: 'body', owasp: 'A02', name: 'Kredensial AWS terekspos' },
  { path: '/wp-config.php.bak', severity: 'critical', sig: /DB_PASSWORD|DB_NAME/i, sigType: 'body', owasp: 'A02', name: 'Backup wp-config terekspos' },
  { path: '/config.php.bak', severity: 'critical', sig: /password|db_|define\(/i, sigType: 'body', owasp: 'A02', name: 'Backup config.php terekspos' },
  { path: '/phpinfo.php', severity: 'high', sig: /phpinfo\(\)|PHP Version/i, sigType: 'body', owasp: 'A02', name: 'phpinfo terekspos' },
  { path: '/info.php', severity: 'high', sig: /phpinfo\(\)|PHP Version/i, sigType: 'body', owasp: 'A02', name: 'phpinfo (info.php) terekspos' },
  { path: '/server-status', severity: 'medium', sig: /Apache Server Status/i, sigType: 'body', owasp: 'A02', name: 'Apache server-status terekspos' },
  { path: '/debug/vars', severity: 'medium', sig: /"cmdline"|"memstats"/, sigType: 'body', owasp: 'A02', name: 'pprof expvar terekspos' },
  { path: '/actuator/env', severity: 'high', sig: /"propertySources"|"activeProfiles"/, sigType: 'body', owasp: 'A02', name: 'Spring Actuator env terekspos' },
  { path: '/actuator/heapdump', severity: 'high', sig: null, sigType: 'magic', owasp: 'A02', name: 'Spring Actuator heapdump terekspos' },
  { path: '/swagger.json', severity: 'medium', sig: /"openapi"|"swagger"/i, sigType: 'body', owasp: 'A01', name: 'Spesifikasi API (swagger.json) publik' },
  { path: '/swagger/ui/index.html', severity: 'low', sig: /swagger/i, sigType: 'body', owasp: 'A01', name: 'Swagger UI publik' },
  { path: '/graphql', severity: 'low', sig: /"data"|GraphiQL|Must provide query/i, sigType: 'body', owasp: 'A01', name: 'Endpoint GraphQL terbuka' },
  { path: '/graphql/playground', severity: 'medium', sig: /GraphQL playground|GraphiQL/i, sigType: 'body', owasp: 'A01', name: 'GraphQL playground publik' },
  { path: '/admin', severity: 'info', sig: null, sigType: 'status200', owasp: 'A01', name: 'Halaman /admin terjangkau' },
  { path: '/admin/login', severity: 'info', sig: /login|password|sign in/i, sigType: 'body', owasp: 'A01', name: 'Panel login admin terjangkau' },
  { path: '/administrator', severity: 'info', sig: /login|joomla/i, sigType: 'body', owasp: 'A01', name: 'Panel administrator terjangkau' },
  { path: '/phpmyadmin', severity: 'medium', sig: /phpMyAdmin/i, sigType: 'body', owasp: 'A01', name: 'phpMyAdmin terjangkau' },
  { path: '/xmlrpc.php', severity: 'low', sig: /XML-RPC server accepts only POST/i, sigType: 'body', owasp: 'A03', name: 'XML-RPC aktif (WordPress)' },
  { path: '/wp-json/wp/v2/users', severity: 'medium', sig: /\[?\{"id":\d+|"slug":/, sigType: 'body', owasp: 'A01', name: 'Enumerasi user WordPress terbuka' },
  { path: '/crossdomain.xml', severity: 'medium', sig: /allow-access-from\s+domain="\*"/i, sigType: 'body', owasp: 'A02', name: 'crossdomain.xml mengizinkan semua domain' },
  { path: '/.well-known/security.txt', severity: 'info', sig: /Contact:/i, sigType: 'body', owasp: 'A02', name: 'security.txt ditemukan (informatif)' },
  { path: '/robots.txt', severity: 'info', sig: /user-agent|disallow/i, sigType: 'body', owasp: 'A02', name: 'robots.txt ditemukan (informatif)' },
];

const DIRLIST_DIRS = ['/backup/', '/uploads/', '/files/', '/static/', '/assets/', '/images/', '/js/', '/css/', '/media/', '/data/', '/temp/', '/tmp/'];

const TAKEOVER_FINGERPRINTS = [
  { service: 'AWS S3', cname: /s3\.amazonaws\.com|s3-website/i, re: /NoSuchBucket|The specified bucket does not exist/i, severity: 'critical' },
  { service: 'GitHub Pages', cname: /github\.io/i, re: /There isn't a GitHub Pages site here/i, severity: 'high' },
  { service: 'Heroku', cname: /herokuapp\.com/i, re: /No such app|There's nothing here/i, severity: 'high' },
  { service: 'Fastly', cname: /fastly/i, re: /Fastly error: unknown domain/i, severity: 'high' },
  { service: 'Shopify', cname: /myshopify\.com/i, re: /Sorry, this shop is currently unavailable/i, severity: 'high' },
  { service: 'Zendesk', cname: /zendesk\.com/i, re: /Help Center Closed/i, severity: 'medium' },
  { service: 'Surge.sh', cname: /surge\.sh/i, re: /project not found/i, severity: 'medium' },
  { service: 'Tumblr', cname: /tumblr\.com/i, re: /There's nothing here\.?/i, severity: 'medium' },
  { service: 'Azure', cname: /azurewebsites\.net|cloudapp\.azure\.com/i, re: /404 Web Site not found/i, severity: 'high' },
  { service: 'Squarespace', cname: /squarespace\.com/i, re: /website expiring|NOT FOUND/i, severity: 'medium' },
];

const COMMON_PARAMS = ['id', 'page', 'url', 'redirect', 'redirect_uri', 'return', 'returnUrl', 'next', 'goto', 'target', 'link', 'dest', 'destination', 'continue', 'rurl', 'file', 'path', 'lang', 'q', 'search', 's', 'user', 'email', 'name', 'cat', 'category', 'item', 'view', 'template', 'dir'];

const STACK_TRACE_PATTERNS = [
  { re: /Traceback \(most recent call last\)/, label: 'Python traceback' },
  { re: /System\.\w+Exception:/, label: '.NET exception' },
  { re: /Fatal error: Uncaught \w+Exception/, label: 'PHP fatal error' },
  { re: /Warning: (?:mysql|mysqli|pg_)\w*\(\)/, label: 'PHP DB warning' },
  { re: /java\.lang\.NullPointerException|at [\w$.]+\.[\w$]+\([\w./-]+\.java:\d+\)/, label: 'Java stack trace' },
];

/**
 * Signature malware/defacement/spam pada isi halaman (pasif, read-only).
 * Semua pattern dibuat SANGAT spesifik agar minim false positive;
 * hasilnya INDICATOR - wajib verifikasi manual.
 */
const MALWARE_SIGNATURES = [
  // Crypto miner (coinhive dan turunannya)
  { id: 'miner:coinhive', re: /coinhive\.com\/lib\/minero?|coin-hive|minero\.mining|deepMiner|cryptallos|crypto-looter/i, sev: 'high', label: 'Skrip crypto miner terdeteksi (CoinHive/turunan)' },
  { id: 'miner:generic', re: /(?:minero|miner)\.(?:start|startWithThread|Anonymous)\s*\(|stratum\+tcp:\/\/|miningPoolURL/i, sev: 'high', label: 'Pola mining pool / skrip miner generik' },
  // Obfuscation berbahaya khas malware JS
  { id: 'js:eval-atob-chain', re: /eval\s*\(\s*(?:atob|unescape|String\.fromCharCode|Function)\s*\(/i, sev: 'medium', label: 'Kode JS terobfuscasi (eval+decode chain)' },
  { id: 'js:packed', re: /eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)/, sev: 'medium', label: 'Dean Edwards packer (JS terobfuscasi)' },
  // Hidden/malicious iframe injection (deface/malware redirect)
  { id: 'web:hidden-iframe', re: /<iframe[^>]{0,400}(?:width\s*=\s*["']?0|height\s*=\s*["']?0|display\s*:\s*none|visibility\s*:\s*hidden|left\s*:\s*-{1,4}\d{3,})/i, sev: 'high', label: 'Hidden iframe (teknik injeksi malware/redirect)' },
  // Drive-by / exploit kit style
  { id: 'web:fake-update', re: /(?:chrome|firefox|flash-player?)[^<]{0,40}\.(?:update|setup|installer)\.(?:exe|dmg|msi)|(?:update|install)[-_]?(?:your[-_])?(?:browser|flash)[^<]{0,20}\.exe/i, sev: 'high', label: 'Umpan fake browser/plugin update (soceng malware)' },
  { id: 'web:fake-av', re: /(?:your|the)\s+(?:computer|system|device)\s+(?:has been|is)\s+(?:infected|blocked)|virus(?:es)?\s+(?:detected|found)\s*\(!\)/i, sev: 'medium', label: 'Teks scareware/fake antivirus' },
  // Spam/pharma/defacement keywords
  { id: 'spam:pharma', re: /(?:cheap|buy|best)\s+(?:cialis|viagra|xanax|tramadol)\b|casino\s+(?:online|slots)\b|porn(?:hub)?\s*(?:free|hd)\b.{0,40}(?:video|watch)/i, sev: 'medium', label: 'Konten spam (pharma/casino/porn) tertanam' },
  { id: 'deface:marker', re: /hacked\s+by\s+|owntz\b|\bdefaced\b(?:\s+by)|#op(?:eration)?[a-z0-9]{3,}\s*was\s*here/i, sev: 'high', label: 'Penanda defacement pada halaman' },
  // Shell/webshell landing markers
  { id: 'webshell:marker', re: /(?:c99|r57|b374k|wso)\s*(?:shell|-\s*(?:shell|ext))\b|FilesMan|WSO\s*\d+\.\d+/i, sev: 'critical', label: 'Penanda webshell (c99/r57/WSO)' },
  // Redirect ke TLD berisiko tinggi dari script kecil
  { id: 'web:susp-redirect', re: /(?:window\.)?location(?:\.href|\.replace)?\s*=\s*["']https?:\/\/[^"']*\.(?:tk|ml|ga|cf|gq|top|xyz)\//i, sev: 'medium', label: 'Auto-redirect JS ke domain TLD berisiko tinggi' },
];

const PRIVATE_IP_RE = /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/;
const EMAIL_RE = /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,}\b/g;

function mkFinding(engineName, targetUrl, { checkId, owasp, severity, name, detail, evidence }) {
  return {
    engine: engineName,
    externalId: checkId,
    name,
    severity,
    target: targetUrl,
    evidence: JSON.stringify({ detail, evidence: String(evidence || '').slice(0, 500) }).slice(0, 2000),
    reference: '',
    tags: checkId,
    owaspId: owasp,
    classification: 'INDICATOR',
  };
}

function lcaseHeaders(headers) {
  const l = {};
  for (const k of Object.keys(headers || {})) l[k.toLowerCase()] = headers[k];
  return l;
}

/**
 * Peta checkId -> kategori pemeriksaan. Dipakai filter mode terfokus
 * (XSS Scan hanya kategori xss, Malware Scan hanya malware, dst).
 */
function checkCategory(checkId) {
  const id = String(checkId || '');
  if (id.startsWith('xss:')) return 'xss';
  if (id.startsWith('sqli:')) return 'sqli';
  if (id.startsWith('traversal:')) return 'traversal';
  if (id.startsWith('redirect:')) return 'redirect';
  if (id.startsWith('malware:')) return 'malware';
  if (id.startsWith('takeover:')) return 'takeover';
  if (id.startsWith('cors:')) return 'cors';
  if (id.startsWith('tls:')) return 'tls';
  if (id.startsWith('cookie:')) return 'cookie';
  if (id.startsWith('exposed:')) return 'exposed';
  if (id.startsWith('dirlisting:') || id === 'page:dirlisting') return 'dirlist';
  if (id === 'http:dangerous-methods') return 'methods';
  if (id.startsWith('info:')) return 'info';
  if (id.startsWith('tech:')) return 'tech';
  if (id.startsWith('recon:')) return 'recon';
  if (id.startsWith('sec:')) return 'header';
  if (id === 'page:mixed-content') return 'mixed';
  return 'other';
}

/** ---- Evaluasi respons statis (dapat dites tanpa jaringan) ----
 * ctx.only: array kategori opsional (header|cookie|mixed|info|tls|malware|dirlist).
 * Dipakai mode terfokus (mis. Malware Scan hanya butuh kategori malware+info).
 */
function evaluateSecurityPosture(ctx) {
  const f = [];
  const h = lcaseHeaders(ctx.headers);
  const url = ctx.url;
  const body = String(ctx.body || '');
  const httpsOn = url.startsWith('https://');
  const only = Array.isArray(ctx.only) && ctx.only.length ? ctx.only : null;
  const want = (c) => !only || only.includes(c);

  // --- Header keamanan ---
  if (want('header')) {
  const csp = String(h['content-security-policy'] || '');
  const hsts = String(h['strict-transport-security'] || '');
  if (httpsOn && !hsts) f.push({ checkId: 'sec:hsts-missing', owasp: 'A02', severity: 'low', name: 'HSTS tidak diatur', detail: `Strict-Transport-Security tidak ada pada ${url}`, evidence: 'header strict-transport-security absen' });
  if (hsts && /max-age=(\d+)/i.test(hsts) && parseInt(RegExp.$1, 10) < 15768000) {
    f.push({ checkId: 'sec:hsts-weak', owasp: 'A02', severity: 'info', name: 'HSTS max-age rendah', detail: `max-age ${RegExp.$1} < 6 bulan`, evidence: hsts.slice(0, 120) });
  }
  if (!csp) {
    f.push({ checkId: 'sec:csp-missing', owasp: 'A02', severity: 'low', name: 'CSP tidak diatur', detail: `Content-Security-Policy tidak ada pada ${url}`, evidence: 'header content-security-policy absen' });
  } else {
    if (/unsafe-inline/i.test(csp) && !/nonce-/.test(csp)) {
      f.push({ checkId: 'sec:csp-unsafe-inline', owasp: 'A02', severity: 'info', name: "CSP memakai 'unsafe-inline'", detail: "CSP mengizinkan inline script tanpa nonce, mengurangi proteksi XSS", evidence: csp.slice(0, 200) });
    }
    if (/script-src[^;]*\*/i.test(csp)) {
      f.push({ checkId: 'sec:csp-wildcard', owasp: 'A02', severity: 'info', name: 'CSP script-src wildcard *', detail: 'script-src mengizinkan semua sumber', evidence: csp.slice(0, 200) });
    }
  }
  if (!h['x-content-type-options']) {
    f.push({ checkId: 'sec:xcto-missing', owasp: 'A02', severity: 'info', name: 'X-Content-Type-Options tidak diatur', detail: `nosniff tidak diatur pada ${url}`, evidence: 'header x-content-type-options absen' });
  }
  const xfo = String(h['x-frame-options'] || '');
  if (!xfo && !/frame-ancestors/i.test(csp)) {
    f.push({ checkId: 'sec:clickjacking', owasp: 'A02', severity: 'low', name: 'Proteksi clickjacking tidak diatur', detail: `X-Frame-Options dan CSP frame-ancestors absen pada ${url}`, evidence: 'tidak ada proteksi framing' });
  }
  if (!h['referrer-policy']) {
    f.push({ checkId: 'sec:referrer-missing', owasp: 'A02', severity: 'info', name: 'Referrer-Policy tidak diatur', detail: `Referrer-Policy tidak ada pada ${url}`, evidence: 'header referrer-policy absen' });
  }
  if (httpsOn && !h['permissions-policy']) {
    f.push({ checkId: 'sec:permissions-missing', owasp: 'A02', severity: 'info', name: 'Permissions-Policy tidak diatur', detail: 'Permissions-Policy tidak ada (opsional namun disarankan)', evidence: 'header permissions-policy absen' });
  }
  }

  // --- Cookie flags ---
  if (want('cookie')) {
  const setCookies = [].concat(h['set-cookie'] || []);
  for (const c of setCookies) {
    const cname = String(c).split('=')[0].slice(0, 60);
    const issues = [];
    if (!/secure/i.test(String(c))) issues.push('tanpa Secure');
    if (!/httponly/i.test(String(c))) issues.push('tanpa HttpOnly');
    if (!/samesite/i.test(String(c))) issues.push('tanpa SameSite');
    if (issues.length) {
      f.push({ checkId: 'cookie:flags', owasp: 'A07', severity: 'medium', name: `Cookie tanpa proteksi: ${cname}`, detail: `Cookie ${cname} ${issues.join(', ')} pada ${url}`, evidence: `set-cookie: ${String(c).slice(0, 200)}` });
    }
  }
  }

  // --- Mixed content ---
  if (want('mixed') && httpsOn) {
    const httpRes = body.match(/(?:src|href)\s*=\s*["']http:\/\/[^"']{1,200}["']/gi) || [];
    const filtered = httpRes.filter((s) => !/http:\/\/(www\.)?(w3\.org|schema\.org|purl\.org|ogp\.me|gmpg\.org|adobe\.com|dublincore\.org)/i.test(s)).slice(0, 5);
    if (filtered.length) {
      f.push({ checkId: 'page:mixed-content', owasp: 'A02', severity: 'medium', name: 'Mixed content (resource HTTP di halaman HTTPS)', detail: `${filtered.length} resource http:// ditemukan di halaman HTTPS`, evidence: filtered.join(' | ').slice(0, 300) });
    }
  }

  // --- Info disclosure ---
  if (want('info')) {
  const server = String(h['server'] || '');
  if (/\d+\.\d+/.test(server)) {
    f.push({ checkId: 'info:server-version', owasp: 'A03', severity: 'info', name: 'Versi server terungkap', detail: `Header Server: ${server}`, evidence: `server: ${server.slice(0, 120)}` });
  }
  const poweredBy = String(h['x-powered-by'] || '');
  if (poweredBy && /\d+\.\d+/.test(poweredBy)) {
    f.push({ checkId: 'info:poweredby', owasp: 'A03', severity: 'info', name: 'X-Powered-By mengungkap teknologi', detail: `X-Powered-By: ${poweredBy}`, evidence: `x-powered-by: ${poweredBy.slice(0, 120)}` });
  }
  for (const p of STACK_TRACE_PATTERNS) {
    if (p.re.test(body)) {
      f.push({ checkId: `info:stacktrace:${p.label}`, owasp: 'A05', severity: 'low', name: `Kebocoran detail error: ${p.label}`, detail: `Respons ${url} mengandung pola "${p.label}"`, evidence: body.slice(0, 300) });
      break;
    }
  }
  const privIp = PRIVATE_IP_RE.exec(body);
  if (privIp) {
    f.push({ checkId: 'info:private-ip', owasp: 'A10', severity: 'info', name: 'IP privat bocor di respons', detail: `Ditemukan IP privat ${privIp[1]} pada ${url}`, evidence: body.slice(Math.max(0, (privIp.index || 0) - 60), (privIp.index || 0) + 100) });
  }
  if (/Directory listing for \/|<title>Index of \//i.test(body)) {
    f.push({ checkId: 'page:dirlisting', owasp: 'A02', severity: 'medium', name: 'Directory listing aktif', detail: `Halaman ${url} menampilkan daftar direktori`, evidence: body.slice(0, 200) });
  }
  }

  // --- TLS ---
  if (want('tls')) {
  if (ctx.tlsProto && /^TLSv1(\.[01])?$/.test(ctx.tlsProto)) {
    f.push({ checkId: 'tls:weak-version', owasp: 'A02', severity: 'medium', name: `Versi TLS lemah (${ctx.tlsProto})`, detail: `Server menegosiasikan ${ctx.tlsProto}; disarankan TLS 1.2+/1.3`, evidence: `protocol: ${ctx.tlsProto}` });
  }
  if (ctx.certExpiryDays != null) {
    if (ctx.certExpiryDays <= 0) {
      f.push({ checkId: 'tls:cert-expired', owasp: 'A02', severity: 'high', name: 'Sertifikat TLS kedaluwarsa', detail: `Sertifikat ${url} kedaluwarsa ${Math.abs(ctx.certExpiryDays)} hari lalu`, evidence: `daysLeft=${ctx.certExpiryDays}` });
    } else if (ctx.certExpiryDays <= 14) {
      f.push({ checkId: 'tls:cert-expiring', owasp: 'A02', severity: 'info', name: 'Sertifikat TLS segera kedaluwarsa', detail: `Sertifikat ${url} kedaluwarsa dalam ${ctx.certExpiryDays} hari`, evidence: `daysLeft=${ctx.certExpiryDays}` });
    }
  }
  }

  // --- Email di halaman (info) ---
  if (want('info')) {
    const emails = [...new Set((body.match(EMAIL_RE) || []).map((e) => e.toLowerCase()))].filter((e) => !/(example|sentry|wixpress)\./.test(e)).slice(0, 5);
    if (emails.length >= 3) {
      f.push({ checkId: 'info:emails', owasp: 'A10', severity: 'info', name: 'Alamat email terekspos di halaman', detail: `${emails.length} email unik pada ${url}: ${emails.slice(0, 3).join(', ')} (potensi enumerasi/phishing)`, evidence: emails.join(', ') });
    }
  }

  // --- Malware / defacement / spam / webshell signature (pasif) ---
  if (want('malware')) {
    for (const m of MALWARE_SIGNATURES) {
      const mt = m.re.exec(body);
      if (mt) {
        f.push({
          checkId: `malware:${m.id}`,
          owasp: 'A02',
          severity: m.sev,
          name: m.label,
          detail: `Pola "${m.label}" terdeteksi pada ${url}. Ini INDICATOR - verifikasi manual wajib sebelum dilaporkan.`,
          evidence: String(body).slice(Math.max(0, (mt.index || 0) - 60), (mt.index || 0) + 160),
        });
      }
    }
  }

  return f;
}

/** ---- TLS sertifikat info ---- */
function getCertInfo(hostname, port = 443, timeoutMs = 8000) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host: hostname, port, servername: hostname, rejectUnauthorized: false, timeout: timeoutMs }, () => {
      try {
        const cert = socket.getPeerCertificate();
        const proto = socket.getProtocol();
        if (!cert || !cert.valid_to) {
          resolve({ ok: false });
          return;
        }
        const expiry = new Date(cert.valid_to);
        const days = Math.floor((expiry.getTime() - Date.now()) / 86400000);
        resolve({ ok: true, proto, daysLeft: days, issuer: (cert.issuer && cert.issuer.O) || null, subject: cert.subject && cert.subject.CN });
      } catch (e) {
        resolve({ ok: false, error: e.message });
      } finally {
        socket.end();
      }
    });
    socket.on('error', () => resolve({ ok: false }));
    socket.on('timeout', () => {
      socket.destroy();
      resolve({ ok: false });
    });
  });
}

/** ---- Engine utama ---- */
class VulnScanInternalEngine {
  constructor(config, logger) {
    this.name = 'vulnscan-internal';
    this.builtIn = true;
    this.config = config;
    this.logger = logger && logger.child ? logger.child('vulnscan-internal') : logger;
  }

  async checkInstalled() {
    return { status: 'AVAILABLE', version: `node-${process.version} (internal)`, binaryPath: 'internal', reason: 'OK', error: null };
  }

  _readUrls(opts) {
    let urls = [];
    if (opts.listFile) {
      const fs = require('fs');
      urls = fs.readFileSync(opts.listFile, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean);
    } else if (Array.isArray(opts.urls)) {
      urls = opts.urls.map(String);
    }
    return [...new Set(urls)];
  }

  async run(jobCtx, opts) {
    const o = opts || {};
    this._seenKeys = new Map(); // dedup per-origin+checkId per run
    const urls = this._readUrls(o).slice(0, Math.max(this.config.maxLiveHosts, 20));
    const items = [];
    const stats = { urlsChecked: 0, probesSent: 0, exposedChecked: 0, paramProbed: 0 };
    const limiter = new RateLimiter({ minDelayMs: this.config.internalMinDelayMs || 120, concurrency: this.config.internalConcurrency || 4 });
    const ua = this.config.userAgent;
    const deep = o.mode === 'deep' || (o.mode == null && true);
    const ipMap = o.ipMap instanceof Map ? o.ipMap : new Map();
    // Filter kategori mode terfokus (null = jalankan semua)
    const catOnly = Array.isArray(o.categories) && o.categories.length ? o.categories : null;
    const wantCat = (c) => !catOnly || catOnly.includes(c);

    const send = async (url, extraOpts = {}) => {
      stats.probesSent++;
      return limiter.run(() =>
        requestFollow({
          url,
          ip: ipMap.get(new URL(url).hostname) || null,
          method: 'GET',
          timeoutMs: 10000,
          maxBodyBytes: 300 * 1024,
          maxRedirects: 3,
          userAgent: ua,
          interRequestDelayMs: 60,
          ...extraOpts,
        })
      );
    };

    const add = (targetUrl, finding) => {
      // Dedup per-origin + checkId: cek host-wide (exposed files, dirlisting,
      // header absen) cukup dilaporkan SEKALI per origin, bukan per URL.
      let origin = targetUrl;
      try {
        origin = new URL(targetUrl).origin;
      } catch (_) {
        /* pakai url apa adanya */
      }
      const key = `${origin}|${finding.checkId}`;
      if (this._seenKeys.has(key)) return;
      this._seenKeys.set(key, true);
      items.push(mkFinding(this.name, targetUrl, finding));
    };

    for (const url of urls) {
      if (jobCtx.signal && jobCtx.signal.aborted) {
        const e = new Error('Dibatalkan pengguna');
        e.name = 'AbortError';
        throw e;
      }
      let u;
      try {
        u = new URL(url);
      } catch (_) {
        // eslint-disable-next-line no-continue
        continue;
      }
      stats.urlsChecked++;

      // 1) Respons utama + evaluasi postur keamanan
      // eslint-disable-next-line no-await-in-loop
      const main = await send(url);
      if (main.ok && main.status) {
        const certInfo = u.protocol === 'https:' ? null : null; // sertifikat dicek terpisah di bawah
        let certDays = null;
        if (u.protocol === 'https:') {
          // eslint-disable-next-line no-await-in-loop
          const ci = await getCertInfo(u.hostname, parseInt(u.port || '443', 10));
          if (ci.ok) {
            certDays = ci.daysLeft;
            if (ci.proto && /^TLSv1(\.[01])?$/.test(ci.proto)) {
              add(url, { checkId: 'tls:weak-version', owasp: 'A02', severity: 'medium', name: `Versi TLS lemah (${ci.proto})`, detail: `Server menegosiasikan ${ci.proto}`, evidence: `protocol=${ci.proto}` });
            }
            if (ci.daysLeft <= 0) {
              add(url, { checkId: 'tls:cert-expired', owasp: 'A02', severity: 'high', name: 'Sertifikat TLS kedaluwarsa', detail: `Kedaluwarsa ${Math.abs(ci.daysLeft)} hari lalu (issuer: ${ci.issuer || 'unknown'})`, evidence: `daysLeft=${ci.daysLeft}` });
            } else if (ci.daysLeft <= 14) {
              add(url, { checkId: 'tls:cert-expiring', owasp: 'A02', severity: 'info', name: 'Sertifikat TLS segera kedaluwarsa', detail: `Sertifikat kedaluwarsa dalam ${ci.daysLeft} hari`, evidence: `daysLeft=${ci.daysLeft}` });
            }
          }
        }
        const findings = evaluateSecurityPosture({ url: main.finalUrl || url, status: main.status, headers: main.headers, body: main.body, tlsProto: main.tlsProto, certExpiryDays: certDays, only: catOnly });
        for (const fd of findings) add(url, fd);

        // teknologi dengan versi terdeteksi (A03 indikatif)
        const tech = detectTech({ headers: main.headers, body: main.body });
        for (const t of tech) {
          if (t.version && t.category === 'language') {
            add(url, { checkId: 'tech:version-disclosure', owasp: 'A03', severity: 'info', name: `Versi bahasa/server terungkap: ${t.name} ${t.version}`, detail: `${t.name} versi ${t.version} terdeteksi (${t.source}); cocokkan dengan advisori`, evidence: `${t.name}/${t.version}` });
          }
        }

        // robots.txt intel (informatif: jalur menarik)
        if (deep && wantCat('recon')) {
          // eslint-disable-next-line no-await-in-loop
          const rob = await send(new URL('/robots.txt', url).toString());
          if (rob.ok && rob.status === 200 && /disallow/i.test(rob.body || '')) {
            const interesting = (rob.body.match(/disallow:\s*(\/[^\s\r\n]{1,120})/gi) || [])
              .map((s) => s.split(/:\s*/).slice(1).join(':').trim())
              .filter((p) => p && !/^\*(?:$|\/?$)/.test(p) && !/\.(css|js|ico|png|jpe?g|svg|gif)$/i.test(p))
              .slice(0, 10);
            if (interesting.length) {
              add(url, { checkId: 'recon:robots-paths', owasp: 'A02', severity: 'info', name: `robots.txt mengungkap ${interesting.length} jalur menarik`, detail: `Jalur: ${interesting.join(', ')}`, evidence: interesting.join(', ') });
            }
          }
        }
      }

      // 2) CORS misconfiguration
      if (wantCat('cors')) {
      // eslint-disable-next-line no-await-in-loop
      const cors = await send(url, { headers: { Origin: 'https://cxl-cors-probe.example.net' } });
      if (cors.ok && cors.headers) {
        const h = lcaseHeaders(cors.headers);
        const acao = String(h['access-control-allow-origin'] || '');
        const acac = String(h['access-control-allow-credentials'] || '');
        if (acao === 'https://cxl-cors-probe.example.net') {
          add(url, { checkId: 'cors:reflected-origin', owasp: 'A05', severity: 'high', name: 'CORS merefleksikan origin arbitrer', detail: `Origin acak direfleksikan pada Access-Control-Allow-Origin${acac.toLowerCase() === 'true' ? ' DENGAN credentials=true' : ''}`, evidence: `acao=${acao} acac=${acac || 'absen'}` });
        } else if (acao === '*' && acac.toLowerCase() === 'true') {
          add(url, { checkId: 'cors:wildcard-credentials', owasp: 'A05', severity: 'medium', name: 'CORS wildcard dengan credentials', detail: 'Access-Control-Allow-Origin: * bersama Allow-Credentials: true (konfigurasi tidak valid)', evidence: `acao=* acac=${acac}` });
        } else if (acao === '*' && /authorization|cookie/i.test(String(h['access-control-allow-headers'] || ''))) {
          add(url, { checkId: 'cors:wildcard-auth-headers', owasp: 'A05', severity: 'info', name: 'CORS wildcard mengizinkan header auth', detail: 'Wildcard origin dengan Access-Control-Allow-Headers berisi kredensial header', evidence: `acao=* allow-headers=${String(h['access-control-allow-headers']).slice(0, 120)}` });
        }
      }
      }

      // 3) HTTP methods (OPTIONS)
      if (wantCat('methods')) {
      // eslint-disable-next-line no-await-in-loop
      const opt = await limiter.run(() =>
        requestPinned({ url, ip: ipMap.get(u.hostname) || null, method: 'OPTIONS', timeoutMs: 8000, maxBodyBytes: 4096, userAgent: ua })
      );
      stats.probesSent++;
      if (opt.ok && opt.headers) {
        const allow = String(opt.headers.allow || opt.headers['access-control-allow-methods'] || '');
        const dangerous = ['TRACE', 'PUT', 'DELETE', 'PATCH', 'CONNECT'].filter((m) => new RegExp(`(^|,\\s*)${m}(,|$)`, 'i').test(allow));
        if (dangerous.length) {
          add(url, { checkId: 'http:dangerous-methods', owasp: 'A02', severity: dangerous.includes('TRACE') ? 'medium' : 'info', name: `Metode HTTP berisiko diizinkan: ${dangerous.join(', ')}`, detail: `Header Allow: ${allow}`, evidence: `allow=${allow.slice(0, 200)}` });
        }
      }
      }

      // 4) File sensitif terekspos
      if (wantCat('exposed')) {
      for (const ex of EXPOSED_PATHS) {
        if (jobCtx.signal && jobCtx.signal.aborted) break;
        // eslint-disable-next-line no-await-in-loop
        const r = await send(new URL(ex.path, url).toString(), { maxRedirects: 0 });
        stats.exposedChecked++;
        if (!r.ok || !r.status) continue;
        const ctype = String((r.headers && r.headers['content-type']) || '');
        let hit = false;
        if (ex.sigType === 'body' && ex.sig && ex.sig.test(String(r.body || ''))) hit = true;
        else if (ex.sigType === 'nonhtml200' && r.status === 200 && !/text\/html/i.test(ctype)) hit = true;
        else if (ex.sigType === 'status200' && r.status === 200) hit = true;
        else if (ex.sigType === 'magic' && r.status === 200) {
          const b = String(r.body || '').slice(0, 8);
          if (ex.path === '/.DS_Store') hit = b.charCodeAt(0) === 0 && b.includes('Bud1');
          else if (/backup\.zip|\.war$/.test(ex.path)) hit = b.startsWith('PK');
          else if (/tar\.gz/.test(ex.path)) hit = r.body.charCodeAt(0) === 0x1f;
          else if (/heapdump/.test(ex.path)) hit = r.body.charCodeAt(0) === 0xac || /java-heap/i.test(ctype);
          else hit = r.status === 200 && !/text\/html/i.test(ctype);
        }
        if (hit) {
          add(url, { checkId: `exposed:${ex.path}`, owasp: ex.owasp, severity: ex.severity, name: ex.name, detail: `${new URL(ex.path, url).toString()} merespons ${r.status}. Isi TIDAK diunduh/disimpan.`, evidence: `status=${r.status} content-type=${ctype.slice(0, 80)}` });
        }
        // eslint-disable-next-line no-await-in-loop
        await sleep(30);
      }
      }

      // 5) Directory listing umum
      if (wantCat('dirlist')) {
      for (const d of DIRLIST_DIRS.slice(0, deep ? 12 : 5)) {
        // eslint-disable-next-line no-await-in-loop
        const r = await send(new URL(d, url).toString());
        if (r.ok && r.status === 200 && /Directory listing for \/|<title>Index of \//i.test(r.body || '')) {
          add(url, { checkId: `dirlisting:${d}`, owasp: 'A02', severity: 'medium', name: `Directory listing aktif di ${d}`, detail: `${new URL(d, url).toString()} menampilkan daftar direktori`, evidence: String(r.body).slice(0, 200) });
        }
      }
      }

      // 6) Uji parameter (XSS reflect / SQLi error / open redirect / traversal)
      if (deep && (wantCat('xss') || wantCat('sqli') || wantCat('traversal') || wantCat('redirect'))) {
        // eslint-disable-next-line no-await-in-loop
        await this._probeParams(url, u, send, add, stats, wantCat);
      }
    }

    // 7) Indikasi subdomain takeover (level host via validator scope)
    if (deep && wantCat('takeover') && jobCtx && jobCtx.validator) {
      // eslint-disable-next-line no-await-in-loop
      await this._checkTakeover(jobCtx, add, stats, ipMap, ua);
    }

    // filter severity (dipakai bila mode nuclei memilih batas severity)
    let finalItems = items;
    if (o.severity && Array.isArray(o.severity) && o.severity.length) {
      const allow = new Set(o.severity.map((s) => String(s).toLowerCase()));
      finalItems = finalItems.filter((it) => allow.has(String(it.severity).toLowerCase()));
    }
    // filter kategori (mode terfokus xss/sqli/malware/dll)
    if (catOnly) {
      finalItems = finalItems.filter((it) => catOnly.includes(checkCategory(it.externalId)));
    }

    return {
      status: 'COMPLETED',
      items: finalItems,
      stats,
      exitCode: 0,
      timedOut: false,
      truncated: false,
      stderrHead: '',
      error: null,
      droppedFlags: [],
      usedArgs: [`urls=${urls.length}`, `mode=${deep ? 'deep' : 'standard'}`],
    };
  }

  /** Uji parameter aman: hanya GET, nilai kanari, deteksi refleksi/signature. */
  async _probeParams(url, u, send, add, stats, wantCat) {
    const wc = typeof wantCat === 'function' ? wantCat : () => true;
    // URL punya param? gunakan itu; jika tidak, probe param umum pada URL root (terbatas)
    const existingParams = [...u.searchParams.keys()].slice(0, 6);
    const paramsToProbe = existingParams.length ? existingParams : COMMON_PARAMS.slice(0, 8);

    for (const p of paramsToProbe) {
      if (stats.paramProbed >= 30) break;
      const tUrl = new URL(url);
      tUrl.searchParams.set(p, 'cxlp0i-base');
      // eslint-disable-next-line no-await-in-loop
      const base = await send(tUrl.toString(), { maxRedirects: 0 });
      stats.paramProbed++;
      if (!base.ok || !base.status || base.status >= 400) continue;

      const baseLen = String(base.body || '').length;

      // XSS reflection
      if (wc('xss')) {
      const xUrl = new URL(url);
      xUrl.searchParams.set(p, XSS_PAYLOAD);
      // eslint-disable-next-line no-await-in-loop
      const xr = await send(xUrl.toString(), { maxRedirects: 0 });
      if (xr.ok && xr.body && xr.body.includes(XSS_MARKER)) {
        const raw = /<svg\/onload=/i.test(xr.body) || xr.body.includes(XSS_PAYLOAD);
        if (raw) {
          add(url, { checkId: `xss:reflected:${p}`, owasp: 'A03', severity: 'high', name: `Refleksi input tanpa encoding pada parameter '${p}' (indikasi XSS)`, detail: `Payload marker direfleksikan mentah (raw) di respons; uji eksekusi manual di browser.`, evidence: `param=${p} reflected=${XSS_PAYLOAD}` });
        } else {
          add(url, { checkId: `xss:reflected-encoded:${p}`, owasp: 'A03', severity: 'info', name: `Parameter '${p}' merefleksikan input (ter-encode)`, detail: 'Input direfleksikan tetapi ter-encode; risiko rendah, cek konteks.', evidence: `param=${p}` });
        }
      }
      }

      // SQLi error signature
      if (wc('sqli')) {
      const sUrl = new URL(url);
      sUrl.searchParams.set(p, SQLI_PROBE);
      // eslint-disable-next-line no-await-in-loop
      const sr = await send(sUrl.toString(), { maxRedirects: 0 });
      if (sr.ok && sr.body) {
        for (const sig of SQL_ERROR_SIGNATURES) {
          if (sig.re.test(sr.body)) {
            add(url, { checkId: `sqli:error-signature:${p}`, owasp: 'A03', severity: 'high', name: `Pesan error ${sig.db} terungkap pada parameter '${p}' (indikasi SQLi)`, detail: `Kutipan tunggal memicu pola error ${sig.db}; verifikasi manual wajib.`, evidence: `db=${sig.db} param=${p}` });
            break;
          }
        }
      }
      }

      // Path traversal signature (read-only)
      if (wc('traversal')) {
      const tUrl2 = new URL(url);
      tUrl2.searchParams.set(p, '../../etc/passwd');
      // eslint-disable-next-line no-await-in-loop
      const tr = await send(tUrl2.toString(), { maxRedirects: 0 });
      if (tr.ok && tr.body && PATH_TRAVERSAL_SIGNATURE.test(tr.body)) {
        add(url, { checkId: `traversal:param:${p}`, owasp: 'A01', severity: 'critical', name: `Signature /etc/passwd pada respons parameter '${p}' (indikasi path traversal)`, detail: 'Pola isi /etc/passwd terdeteksi; konfirmasi manual segera.', evidence: `param=${p}` });
      }
      }

      // Open redirect (3xx Location mengandung kanari)
      if (wc('redirect')) {
      const oUrl = new URL(url);
      oUrl.searchParams.set(p, `https://${REDIRECT_CANARY}/rd`);
      // eslint-disable-next-line no-await-in-loop
      const orr = await send(oUrl.toString(), { maxRedirects: 0 });
      if (orr.ok && orr.status >= 300 && orr.status < 400 && orr.headers && orr.headers.location) {
        const loc = String(orr.headers.location);
        if (loc.includes(REDIRECT_CANARY) || decodeURIComponent(loc).includes(REDIRECT_CANARY)) {
          add(url, { checkId: `redirect:open:${p}`, owasp: 'A01', severity: 'medium', name: `Open redirect pada parameter '${p}'`, detail: `Redirect 3xx menuju domain eksternal kanari via param ${p}`, evidence: `location=${loc.slice(0, 300)}` });
        }
      }
      }
      // eslint-disable-next-line no-await-in-loop
      await sleep(40);
    }
  }

  /** Cek indikasi takeover untuk subdomain hasil enumerasi (CNAME + fingerprint). */
  async _checkTakeover(jobCtx, add, stats, ipMap, ua) {
    const dns = require('dns').promises;
    const store = jobCtx.store;
    let hosts = [];
    try {
      hosts = store.listSubdomains ? store.listSubdomains(jobCtx.scanId) : [];
    } catch (_) {
      hosts = [];
    }
    if (!hosts.length || !hosts.length) return;
    const limited = hosts.slice(0, 60);
    for (const hostRow of limited) {
      const host = typeof hostRow === 'string' ? hostRow : hostRow.host;
      if (!host || host === jobCtx.target) continue;
      try {
        // eslint-disable-next-line no-await-in-loop
        const cnames = await dns.resolveCname(host);
        const cn = (cnames || []).join(' ');
        if (!cn) continue;
        for (const fp of TAKEOVER_FINGERPRINTS) {
          if (!fp.cname.test(cn)) continue;
          // eslint-disable-next-line no-await-in-loop
          const r = await requestPinned({ url: `http://${host}/`, timeoutMs: 8000, maxBodyBytes: 20 * 1024, userAgent: ua });
          const bodyMatch = r.ok && fp.re.test(String(r.body || ''));
          let nx = false;
          try {
            await dns.resolve4(host);
          } catch (e) {
            nx = /ENOTFOUND|NXDOMAIN/i.test(String(e.code || e.message || ''));
          }
          if (bodyMatch || nx) {
            add(`http://${host}/`, { checkId: `takeover:${fp.service}`, owasp: 'A02', severity: nx ? fp.severity : fp.severity, name: `Indikasi kuat subdomain takeover (${fp.service})`, detail: `CNAME ${host} -> ${cn} menunjuk layanan ${fp.service}${nx ? ' (NXDOMAIN)' : ` dengan fingerprint "${fp.service}" pada respons`}. Klaim CNAME untuk konfirmasi.`, evidence: `cname=${cn.slice(0, 200)} nxdomain=${nx}` });
          }
          break;
        }
      } catch (_) {
        /* tanpa CNAME - lanjut */
      }
      // eslint-disable-next-line no-await-in-loop
      await sleep(50);
    }
  }
}

module.exports = {
  VulnScanInternalEngine,
  evaluateSecurityPosture,
  EXPOSED_PATHS,
  TAKEOVER_FINGERPRINTS,
  SQL_ERROR_SIGNATURES,
  MALWARE_SIGNATURES,
  COMMON_PARAMS,
  checkCategory,
};
