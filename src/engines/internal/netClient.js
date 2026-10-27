'use strict';

/**
 * netClient - klien HTTP internal (Node murni, tanpa binary eksternal).
 * Dipakai SEMUA engine internal agar konsisten:
 * - DNS ter-pin ke IP hasil NetworkGuard (anti DNS rebinding).
 * - Batas ukuran body, timeout ketat, jeda antar-request (rate limiting),
 *   batas percobaan redirect, dan dukungan abort signal.
 * - Non-destruktif: default GET/HEAD, tidak ada payload berbahaya.
 */

const https = require('https');
const http = require('http');
const dns = require('dns');
const { isIP } = require('net');

const DEFAULT_UA = 'CxLScanner/1.4 (internal; authorized security assessment)';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms || 0));

/**
 * requestPinned - satu request HTTP(S) dengan DNS ter-pin.
 * opts: { url, ip, method, timeoutMs, maxBodyBytes, headers, userAgent, validateTls }
 * return: { ok, status, headers, body, tlsProto, error, elapsedMs, finalUrl }
 */
function requestPinned(opts) {
  const o = opts || {};
  return new Promise((resolve) => {
    let u;
    try {
      u = new URL(String(o.url || ''));
    } catch (e) {
      resolve({ ok: false, error: 'URL tidak valid', status: 0, headers: {}, body: '' });
      return;
    }
    if (u.protocol !== 'https:' && u.protocol !== 'http:') {
      resolve({ ok: false, error: 'Protokol tidak didukung', status: 0, headers: {}, body: '' });
      return;
    }
    const isHttps = u.protocol === 'https:';
    const mod = isHttps ? https : http;
    const started = Date.now();
    const family = o.ip && isIP(o.ip) === 6 ? 6 : 4;
    const headers = { 'User-Agent': o.userAgent || DEFAULT_UA, Accept: '*/*', Connection: 'close', ...(o.headers || {}) };
    const req = mod.request(
      {
        hostname: u.hostname,
        port: u.port || (isHttps ? 443 : 80),
        path: u.pathname + u.search,
        method: o.method || 'GET',
        servername: isHttps ? u.hostname : undefined,
        timeout: o.timeoutMs || 10000,
        headers,
        rejectUnauthorized: o.validateTls !== false,
        // Pin DNS: pakai IP yang sudah divalidasi NetworkGuard
        lookup: (hostname, lOpts, cb) => {
          if (typeof lOpts === 'function') cb = lOpts;
          if (!o.ip) {
            dns.lookup(hostname, { family: 0 }, (err, addr, fam) => {
              if (err) cb(err);
              else cb(null, addr, fam);
            });
            return;
          }
          cb(null, o.ip, family);
        },
      },
      (res) => {
        const chunks = [];
        let size = 0;
        res.on('data', (c) => {
          size += c.length;
          if (size <= (o.maxBodyBytes || 256 * 1024)) chunks.push(c);
          else res.destroy();
        });
        res.on('end', () => {
          resolve({
            ok: true,
            status: res.statusCode || 0,
            headers: res.headers || {},
            body: Buffer.concat(chunks).toString('utf8'),
            tlsProto: res.socket && res.socket.getProtocol ? res.socket.getProtocol() : null,
            elapsedMs: Date.now() - started,
            finalUrl: u.toString(),
          });
        });
        res.on('error', () => {
          resolve({
            ok: true,
            status: res.statusCode || 0,
            headers: res.headers || {},
            body: Buffer.concat(chunks).toString('utf8'),
            tlsProto: null,
            elapsedMs: Date.now() - started,
            finalUrl: u.toString(),
          });
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', (err) => {
      resolve({ ok: false, error: String(err.message || err), status: 0, headers: {}, body: '', elapsedMs: Date.now() - started });
    });
    req.end();
  });
}

/**
 * requestFollow - request dengan mengikuti redirect (maks hop).
 * Setiap hop diikat ke IP yang sama (pin) agar tidak rebinding.
 * return: { ok, status, headers, body, redirectChain: [{url, location, status}], tlsProto, error, elapsedMs }
 */
async function requestFollow(opts) {
  const o = opts || {};
  const maxHops = o.maxRedirects == null ? 5 : o.maxRedirects;
  const chain = [];
  let currentUrl = String(o.url || '');
  let last = { ok: false, error: 'no request', status: 0, headers: {}, body: '' };
  for (let i = 0; i <= maxHops; i++) {
    // eslint-disable-next-line no-await-in-loop
    const r = await requestPinned({ ...o, url: currentUrl });
    last = r;
    if (!r.ok) return { ...r, redirectChain: chain };
    if (r.status >= 300 && r.status < 400 && r.headers.location) {
      let abs;
      try {
        abs = new URL(String(r.headers.location), currentUrl).toString();
      } catch (e) {
        return { ...r, redirectChain: chain };
      }
      chain.push({ url: currentUrl, location: abs, status: r.status });
      if (/^https?:/i.test(abs)) {
        currentUrl = abs;
        // eslint-disable-next-line no-await-in-loop
        await sleep(o.interRequestDelayMs || 0);
        // eslint-disable-next-line no-continue
        continue;
      }
      return { ...r, redirectChain: chain };
    }
    return { ...r, redirectChain: chain };
  }
  return { ...last, redirectChain: chain, tooManyRedirects: true };
}

/**
 * Rate limiter sederhana berbasis antrean global per instance.
 * Menjaga minimal `minDelayMs` antar request dan maksimal `concurrency` koneksi.
 */
class RateLimiter {
  constructor({ minDelayMs = 120, concurrency = 8 } = {}) {
    this.minDelayMs = Math.max(0, minDelayMs);
    this.concurrency = Math.max(1, concurrency);
    this.active = 0;
    this.queue = [];
    this.lastStart = 0;
  }

  _next() {
    if (this.active >= this.concurrency || !this.queue.length) return;
    const wait = Math.max(0, this.lastStart + this.minDelayMs - Date.now());
    this.active++;
    this.lastStart = Date.now() + wait;
    setTimeout(() => {
      const job = this.queue.shift();
      if (!job) {
        this.active--;
        this._next();
        return;
      }
      job().finally(() => {
        this.active--;
        this._next();
      });
    }, wait);
  }

  /** Jalankan fn async di bawah batas rate. */
  run(fn) {
    return new Promise((resolve, reject) => {
      this.queue.push(() =>
        fn()
          .then(resolve, reject)
          // eslint-disable-next-line no-useless-return
          .then(() => undefined)
      );
      setImmediate(() => this._next());
    });
  }
}

/** Pool utilitas: jalankan async worker untuk array item dengan batas konkurensi. */
async function mapPool(items, limit, fn) {
  const results = [];
  let idx = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    while (idx < items.length) {
      const i = idx++;
      // eslint-disable-next-line no-await-in-loop
      results[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return results;
}

/** Ekstrak <title> dari HTML. */
function extractTitle(html) {
  const m = /<title[^>]*>([\s\S]{0,300}?)<\/title>/i.exec(String(html || ''));
  if (!m) return '';
  return m[1].replace(/\s+/g, ' ').trim().slice(0, 200);
}

/** Ambil URL final dari chain redirect. */
function finalUrlOf(chain, original) {
  if (chain && chain.length) return chain[chain.length - 1].location;
  return original;
}

module.exports = {
  requestPinned,
  requestFollow,
  RateLimiter,
  mapPool,
  sleep,
  extractTitle,
  finalUrlOf,
  DEFAULT_UA,
};
