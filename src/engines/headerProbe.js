'use strict';

/**
 * headerProbe - engine INTERNAL (Node murni, tanpa binary eksternal).
 * Pemeriksaan pasif non-destruktif: GET/HEAD terbatas, rate rendah, timeout ketat.
 * Cakupan: header keamanan, cookie flags, TLS versi/sertifikat, redirect turun ke HTTP
 * atau keluar scope, directory listing, stack trace pada body, file konfigurasi terekspos.
 *
 * PENTING (privasi): isi file sensitif (.env dll) TIDAK PERNAH disimpan - hanya indikator
 * keberadaan. DNS di-pin ke IP hasil guard (lookup kustom) sehingga request internal bebas
 * dari DNS rebinding.
 */

const https = require('https');
const http = require('http');
const tls = require('tls');
const { isIP } = require('net');
const { sanitizeText } = require('../utils/validation');

const STACK_TRACE_PATTERNS = [
  { re: /Traceback \(most recent call last\)/, label: 'Python traceback' },
  { re: /at (?:[\w$.]+\.)?[\w$]+\((?:[\w./-]+\.java:\d+)\)/, label: 'Java stack trace' },
  { re: /System\.\w+Exception:/, label: '.NET exception' },
  { re: /Fatal error: Uncaught \w+Exception/, label: 'PHP fatal error' },
  { re: /ORA-\d{5}/, label: 'Oracle error code' },
  { re: /You have an error in your SQL syntax|MySQLSyntaxErrorException/, label: 'SQL syntax error disclosure' },
  { re: /Warning: (?:mysql|mysqli|pg_)\w*\(\)/, label: 'PHP DB warning' },
];

const EXPOSED_FILES = [
  { path: '/.env', severity: 'high', sig: null, sigType: 'none', owasp: 'A02', name: 'File .env terekspos' },
  { path: '/.git/HEAD', severity: 'high', sig: /^ref:\s+\w+/, sigType: 'body', owasp: 'A02', name: 'Repository .git terekspos' },
  { path: '/debug/vars', severity: 'medium', sig: /"cmdline"|"memstats"/, sigType: 'body', owasp: 'A10', name: 'pprof expvar debug endpoint terekspos' },
  { path: '/actuator/env', severity: 'high', sig: /"propertySources"|"activeProfiles"/, sigType: 'body', owasp: 'A02', name: 'Spring Boot Actuator env terekspos' },
  { path: '/server-status', severity: 'medium', sig: /Apache Server Status/i, sigType: 'body', owasp: 'A02', name: 'Apache server-status terekspos' },
  { path: '/phpinfo.php', severity: 'medium', sig: /phpinfo\(\)|PHP Version/i, sigType: 'body', owasp: 'A02', name: 'phpinfo terekspos' },
];

/** Header yang wajib ada (nilai tidak dinilai, hanya keberadaan). */
const REQUIRED_HEADERS = [
  { header: 'strict-transport-security', owasp: 'A04', sev: 'low', name: 'HSTS tidak diatur', httpsOnly: true },
  { header: 'content-security-policy', owasp: 'A02', sev: 'low', name: 'CSP tidak diatur' },
  { header: 'x-content-type-options', owasp: 'A02', sev: 'info', name: 'X-Content-Type-Options tidak diatur' },
  { header: 'x-frame-options', owasp: 'A02', sev: 'low', name: 'X-Frame-Options tidak diatur (indikasi clickjacking)', alt: 'content-security-policy' },
  { header: 'referrer-policy', owasp: 'A02', sev: 'info', name: 'Referrer-Policy tidak diatur' },
];

/**
 * Fungsi murni evaluasi respons (dapat dites tanpa jaringan).
 * ctx: { url, status, headers, body (string kecil), tlsProtocol, tlsError, redirectChain: [{url,location}] }
 * Hasil: array descriptor temuan { checkId, owasp, severity, name, detail, evidence }
 */
function evaluateResponse(ctx) {
  const findings = [];
  const headers = ctx.headers || {};
  const lkey = {};
  for (const k of Object.keys(headers)) lkey[k.toLowerCase()] = headers[k];
  const serverHeader = sanitizeText(String(lkey['server'] || ''), 200);
  const poweredBy = sanitizeText(String(lkey['x-powered-by'] || ''), 200);

  for (const h of REQUIRED_HEADERS) {
    if (h.httpsOnly && !ctx.url.startsWith('https://')) continue;
    if (h.alt && lkey[h.alt]) continue; // sudah tercakup alternatif (CSP frame-ancestors)
    if (!lkey[h.header]) {
      findings.push({
        checkId: `header:${h.header}`,
        owasp: h.owasp,
        severity: h.sev,
        name: h.name,
        detail: `Header ${h.header} tidak ditemukan pada respons ${ctx.url}`,
        evidence: sanitizeText(JSON.stringify({ url: ctx.url, status: ctx.status }), 400),
      });
    }
  }

  // Cookie flags (A07)
  const setCookies = [].concat(lkey['set-cookie'] || []);
  for (const c of setCookies) {
    const name = String(c).split('=')[0].slice(0, 60);
    const issues = [];
    if (!/secure/i.test(String(c))) issues.push('tanpa Secure');
    if (!/httponly/i.test(String(c))) issues.push('tanpa HttpOnly');
    if (!/samesite/i.test(String(c))) issues.push('tanpa SameSite');
    if (issues.length) {
      findings.push({
        checkId: 'cookie:flags',
        owasp: 'A07',
        severity: 'medium',
        name: `Cookie tanpa proteksi: ${name}`,
        detail: `Cookie ${name} ${issues.join(', ')} pada ${ctx.url}`,
        evidence: sanitizeText(`set-cookie: ${String(c).slice(0, 200)}`, 300),
      });
    }
  }

  // Pengungkapan versi server (A03)
  if (/\d+\.\d+/.test(serverHeader)) {
    findings.push({
      checkId: 'server:version',
      owasp: 'A03',
      severity: 'info',
      name: 'Versi server terungkap',
      detail: `Header Server mengandung nomor versi: ${serverHeader}`,
      evidence: `server: ${serverHeader}`,
    });
  }
  if (poweredBy && /\d+\.\d+/.test(poweredBy)) {
    findings.push({
      checkId: 'server:poweredby',
      owasp: 'A03',
      severity: 'info',
      name: 'X-Powered-By mengungkap teknologi/versi',
      detail: `X-Powered-By: ${poweredBy}`,
      evidence: `x-powered-by: ${poweredBy}`,
    });
  }

  // TLS (A04)
  if (ctx.tlsError) {
    findings.push({
      checkId: 'tls:cert',
      owasp: 'A04',
      severity: 'medium',
      name: 'Masalah sertifikat TLS',
      detail: `TLS gagal/diverifikasi ketat: ${sanitizeText(ctx.tlsError, 200)}`,
      evidence: sanitizeText(ctx.tlsError, 300),
    });
  } else if (ctx.tlsProtocol && /^TLSv1(\.[01])?$/.test(ctx.tlsProtocol)) {
    findings.push({
      checkId: 'tls:version',
      owasp: 'A04',
      severity: 'medium',
      name: `Versi TLS lemah (${ctx.tlsProtocol})`,
      detail: `Server menegosiasikan ${ctx.tlsProtocol}; disarankan TLS 1.2+ / 1.3.`,
      evidence: `protocol: ${ctx.tlsProtocol}`,
    });
  }

  // Redirect (A04 / A01 indikatif)
  for (const r of ctx.redirectChain || []) {
    if (r.location && r.fromHttps && r.location.startsWith('http://')) {
      findings.push({
        checkId: 'redirect:downgrade',
        owasp: 'A04',
        severity: 'medium',
        name: 'Redirect turun ke HTTP',
        detail: `Redirect dari HTTPS ke HTTP: ${sanitizeText(r.location, 200)}`,
        evidence: sanitizeText(`${r.url} -> ${r.location}`, 400),
      });
    }
    if (r.outOfScope) {
      findings.push({
        checkId: 'redirect:scope',
        owasp: 'A01',
        severity: 'info',
        name: 'Redirect menuju host di luar scope (indikatif, bukan bukti open redirect)',
        detail: `${sanitizeText(r.url, 200)} -> ${sanitizeText(r.location, 200)}. Dinilai manual apakah terkontrol penyerang.`,
        evidence: sanitizeText(`${r.url} -> ${r.location}`, 400),
      });
    }
  }

  // Directory listing (A02)
  const body = String(ctx.body || '');
  if (/<title>Index of \//i.test(body) || /Directory listing for \//i.test(body)) {
    findings.push({
      checkId: 'page:dirlisting',
      owasp: 'A02',
      severity: 'medium',
      name: 'Directory listing aktif',
      detail: `Halaman ${ctx.url} tampak menampilkan daftar direktori.`,
      evidence: sanitizeText(body.slice(0, 200), 250),
    });
  }

  // Stack trace / error disclosure (A10, dan SQL error -> A05 indikatif)
  if (ctx.status && ctx.status >= 500) {
    findings.push({
      checkId: 'page:5xx',
      owasp: 'A10',
      severity: 'info',
      name: `Respons error server (${ctx.status})`,
      detail: `${ctx.url} mengembalikan status ${ctx.status}.`,
      evidence: sanitizeText(body.slice(0, 200), 250),
    });
  }
  for (const p of STACK_TRACE_PATTERNS) {
    if (p.re.test(body)) {
      const isSql = /SQL|ORA-|mysql/i.test(p.label);
      findings.push({
        checkId: `page:stacktrace:${p.label}`,
        owasp: isSql ? 'A05' : 'A10',
        severity: isSql ? 'medium' : 'low',
        name: `Kebocoran detail error: ${p.label}`,
        detail: `Respons ${ctx.url} mengandung pola "${p.label}".`,
        evidence: sanitizeText(body.slice(0, 300), 350),
      });
      break; // satu pola cukup per respons
    }
  }

  return findings;
}

/** Ambil URL dengan DNS ter-pin ke IP yang telah divalidasi guard. */
function fetchWithPinnedDns(targetUrl, { ip, userAgent, timeoutMs, maxBodyBytes, method }) {
  return new Promise((resolve) => {
    let u;
    try {
      u = new URL(targetUrl);
    } catch (e) {
      resolve({ error: 'URL tidak valid' });
      return;
    }
    const isHttps = u.protocol === 'https:';
    const mod = isHttps ? https : http;
    const family = ip && isIP(ip) === 6 ? 6 : 4;
    const options = {
      hostname: u.hostname,
      port: u.port || (isHttps ? 443 : 80),
      path: u.pathname + u.search,
      method: method || 'GET',
      servername: isHttps ? u.hostname : undefined,
      timeout: timeoutMs || 10000,
      headers: {
        'User-Agent': userAgent,
        Accept: '*/*',
        Connection: 'close',
      },
      // Pin DNS: abaikan resolver sistem, pakai IP yang sudah divalidasi guard
      lookup: (hostname, opts, cb) => {
        if (typeof opts === 'function') {
          cb = opts;
        }
        if (!ip) {
          cb(new Error('IP ter-pin tidak tersedia'));
          return;
        }
        cb(null, ip, family);
      },
    };
    const req = mod.request(options, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size <= maxBodyBytes) chunks.push(c);
        else res.destroy(); // cukup; hentikan unduhan
      });
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks).toString('utf8', 0, maxBodyBytes),
          socket: res.socket && res.socket.getProtocol ? res.socket.getProtocol() : null,
        });
      });
      res.on('error', () => {
        resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8', 0, maxBodyBytes), socket: null });
      });
    });
    req.on('socket', (socket) => {
      socket.on('secureConnect', () => {
        if (socket.getProtocol) {
          req._tlsProto = socket.getProtocol();
        }
      });
    });
    req.on('timeout', () => {
      req.destroy(new Error('timeout'));
    });
    req.on('error', (err) => {
      resolve({ error: sanitizeText(err.message, 200), tlsProto: req._tlsProto || null });
    });
    req.end();
  });
}

function findingToItem(f, targetUrl) {
  return {
    engine: 'headerProbe',
    externalId: f.checkId,
    name: f.name,
    severity: f.severity,
    target: targetUrl,
    evidence: JSON.stringify({ detail: f.detail, evidence: f.evidence }).slice(0, 2000),
    reference: '',
    tags: f.checkId,
    owaspId: f.owasp,
    classification: 'INDICATOR',
  };
}

class HeaderProbeEngine {
  constructor(config, logger) {
    this.name = 'headerProbe';
    this.builtIn = true;
    this.config = config;
    this.logger = logger && logger.child ? logger.child('headerProbe') : logger;
  }

  async checkInstalled() {
    return { status: 'AVAILABLE', version: `node-${process.version} (internal)`, binaryPath: 'internal', reason: 'OK', error: null };
  }

  /**
   * opts: { targets: [{url, host, ip}] }  (ip = pin hasil guard)
   * Semua request: GET, timeout 10s, sequential dengan jeda, maksimal maxLiveHosts.
   */
  async run(jobCtx, opts) {
    const o = opts || {};
    const targets = (o.targets || []).slice(0, this.config.maxLiveHosts);
    const items = [];
    const stats = { probed: 0, errors: 0, exposedChecked: 0 };
    const exposed = this.config.exposedFilesCheck ? EXPOSED_FILES : [];

    for (const t of targets) {
      if (jobCtx.signal && jobCtx.signal.aborted) {
        const e = new Error('Dibatalkan pengguna');
        e.name = 'AbortError';
        throw e;
      }
      const first = await fetchWithPinnedDns(t.url, {
        ip: t.ip,
        userAgent: this.config.userAgent,
        timeoutMs: 10000,
        maxBodyBytes: 64 * 1024,
      });
      stats.probed++;
      if (first.error) {
        stats.errors++;
        // TLS error khusus HTTPS => temuan A04
        if (t.url.startsWith('https://') && /certificate|tls|ssl|handshake/i.test(first.error)) {
          items.push(
            findingToItem(
              {
                checkId: 'tls:cert',
                owasp: 'A04',
                severity: 'medium',
                name: 'Masalah sertifikat/TLS',
                detail: `Koneksi TLS gagal ke ${t.url}: ${first.error}`,
                evidence: first.error,
              },
              t.url
            )
          );
        }
        continue;
      }

      // redirect chain (maks 3, manual, tervalidasi scope)
      const redirectChain = [];
      let current = first;
      let currentUrl = t.url;
      let hops = 0;
      while (
        current.status &&
        current.status >= 300 &&
        current.status < 400 &&
        current.headers &&
        current.headers.location &&
        hops < 3
      ) {
        const loc = String(current.headers.location);
        let abs = null;
        try {
          abs = new URL(loc, currentUrl).toString();
        } catch (_) {
          break;
        }
        const outOfScope = !/^https?:\/\//i.test(abs);
        redirectChain.push({
          url: currentUrl,
          location: abs,
          fromHttps: currentUrl.startsWith('https://'),
          outOfScope,
        });
        if (outOfScope) break; // jangan ikuti keluar scope
        // eslint-disable-next-line no-await-in-loop
        const nextRes = await fetchWithPinnedDns(abs, {
          ip: t.ip,
          userAgent: this.config.userAgent,
          timeoutMs: 10000,
          maxBodyBytes: 64 * 1024,
        });
        if (nextRes.error) break;
        currentUrl = abs;
        current = nextRes;
        hops++;
        stats.probed++;
      }

      const findings = evaluateResponse({
        url: t.url,
        status: current.status,
        headers: current.headers || {},
        body: current.body || '',
        tlsProtocol: first.socket || first.tlsProto || null,
        tlsError: null,
        redirectChain,
      });
      for (const f of findings) items.push(findingToItem(f, t.url));

      // File konfigurasi terekspos - GET terbatas; ISI TIDAK DISIMPAN
      for (const ex of exposed) {
        if (jobCtx.signal && jobCtx.signal.aborted) break;
        const probeUrl = new URL(ex.path, t.url.startsWith('http') ? t.url : `https://${t.url}`).toString();
        // eslint-disable-next-line no-await-in-loop
        const r = await fetchWithPinnedDns(probeUrl, {
          ip: t.ip,
          userAgent: this.config.userAgent,
          timeoutMs: 8000,
          maxBodyBytes: 4 * 1024,
        });
        stats.exposedChecked++;
        if (r.error || !r.status) continue;
        const contentType = String((r.headers && r.headers['content-type']) || '');
        let hit = false;
        if (ex.sigType === 'body' && ex.sig && ex.sig.test(String(r.body || ''))) hit = true;
        if (ex.sigType === 'none' && r.status === 200 && !/text\/html/i.test(contentType)) hit = true;
        if (hit) {
          items.push(
            findingToItem(
              {
                checkId: `exposed:${ex.path}`,
                owasp: ex.owasp,
                severity: ex.severity,
                name: ex.name,
                detail: `${probeUrl} merespons ${r.status}. ISI TIDAK diunduh/disimpan (kebijakan privasi).`,
                evidence: `status=${r.status} content-type=${contentType.slice(0, 80)}`,
              },
              probeUrl
            )
          );
        }
        // eslint-disable-next-line no-await-in-loop
        await new Promise((res) => setTimeout(res, 150));
      }

      // eslint-disable-next-line no-await-in-loop
      await new Promise((res) => setTimeout(res, 200));
    }

    return {
      status: 'COMPLETED',
      items,
      stats,
      exitCode: 0,
      timedOut: false,
      truncated: false,
      stderrHead: '',
      error: null,
      droppedFlags: [],
      usedArgs: [`targets=${targets.length}`],
    };
  }
}

module.exports = {
  HeaderProbeEngine,
  evaluateResponse,
  EXPOSED_FILES,
  STACK_TRACE_PATTERNS,
  REQUIRED_HEADERS,
  tls: { _unused: tls },
};
