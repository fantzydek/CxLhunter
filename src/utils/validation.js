'use strict';

const crypto = require('crypto');
const { isIP } = require('net');

const DOMAIN_LABEL_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const CONTROL_CHARS_RE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g;
const TOKEN_RE = /\b\d{8,10}:[A-Za-z0-9_-]{30,}\b/g;
const SECRET_KV_RE = /(token|secret|password|passwd|authorization|api[_-]?key)(\s*[:=]\s*)("[^"\s]*"|'[^'\s]*'|[^\s'",]+)/gi;

/** Normalisasi input menjadi hostname domain (lowercase, tanpa skema/path/port/userinfo). */
function normalizeDomain(input) {
  if (typeof input !== 'string') return null;
  let s = input.trim().toLowerCase();
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, ''); // buang skema
  s = s.split(/[/?#]/)[0];
  if (s.includes('@')) return null; // userinfo ditolak
  s = s.split(':')[0]; // buang port
  if (s.endsWith('.')) s = s.slice(0, -1);
  if (!s || s.length > 253) return null;
  if (isIP(s)) return null; // IP ditangani jalur lain
  const labels = s.split('.');
  if (labels.length < 2) return null;
  for (const label of labels) {
    if (!DOMAIN_LABEL_RE.test(label)) return null;
  }
  return s;
}

function isValidDomain(input) {
  return normalizeDomain(input) !== null;
}

/** true bila host === root atau host adalah subdomain dari root. */
function isSubdomainOf(host, root) {
  if (!host || !root) return false;
  if (host === root) return true;
  return host.endsWith('.' + root);
}

/** Cocokkan host terhadap daftar root; kembalikan root yang cocok atau null. */
function matchScopeRoot(host, roots) {
  for (const root of roots || []) {
    if (isSubdomainOf(host, root)) return root;
  }
  return null;
}

/**
 * Validasi URL untuk dipakai/diteruskan ke engine.
 * Menolak: skema non-HTTP(S), userinfo, port di luar allowlist, hostname aneh.
 * Hasil: { ok, url (URL object), host, isIp, reason }
 */
function parseUrlSafe(input, opts) {
  const options = opts || {};
  const allowedProtocols = options.allowedProtocols || ['https', 'http'];
  const allowedPorts = options.allowedPorts || ['80', '443', '8080', '8443'];
  const allowIpLiteral = !!options.allowIpLiteral;

  if (typeof input !== 'string' || input.length > 2048) {
    return { ok: false, reason: 'URL kosong atau terlalu panjang' };
  }
  let u;
  try {
    u = new URL(input);
  } catch (_) {
    return { ok: false, reason: 'URL tidak valid' };
  }
  if (!allowedProtocols.includes(u.protocol.replace(':', '').toLowerCase())) {
    return { ok: false, reason: `Protokol tidak diizinkan: ${u.protocol}` };
  }
  if (u.username || u.password) {
    return { ok: false, reason: 'URL mengandung kredensial (userinfo) - ditolak' };
  }
  const port = u.port || (u.protocol === 'https:' ? '443' : '80');
  if (!allowedPorts.includes(port)) {
    return { ok: false, reason: `Port tidak diizinkan: ${port}` };
  }
  const host = u.hostname.toLowerCase();
  let isIp = false;
  if (isIP(host.replace(/^\[|\]$/g, ''))) {
    isIp = true;
    if (!allowIpLiteral) return { ok: false, reason: 'Alamat IP literal tidak diizinkan (gunakan domain)' };
  } else if (!isValidDomain(host)) {
    return { ok: false, reason: `Hostname tidak valid: ${host.slice(0, 60)}` };
  }
  return { ok: true, url: u, host, isIp, port };
}

/** Hash pendek stabil untuk deduplikasi temuan. */
function sha16(str) {
  return crypto.createHash('sha256').update(String(str)).digest('hex').slice(0, 16);
}

function clampInt(v, min, max, dflt) {
  const n = parseInt(v, 10);
  if (!Number.isFinite(n)) return dflt;
  return Math.min(max, Math.max(min, n));
}

function toBool(v, dflt) {
  if (v === undefined || v === null || v === '') return !!dflt;
  return ['1', 'true', 'yes', 'on'].includes(String(v).toLowerCase());
}

/** Nama file aman: hanya [A-Za-z0-9._-], dibatasi panjang. */
function sanitizeFilename(s, maxLen) {
  const out = String(s || '')
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, maxLen || 80);
  return out || 'file';
}

/** Bersihkan teks dari karakter kontrol dan batasi panjang (untuk log/DB). */
function sanitizeText(s, maxLen) {
  if (s === null || s === undefined) return '';
  let out = String(s).replace(CONTROL_CHARS_RE, ' ');
  if (maxLen && out.length > maxLen) out = out.slice(0, maxLen);
  return out;
}

/** Sembunyikan token/secret dalam teks log. */
function maskSecrets(s) {
  let out = String(s == null ? '' : s);
  out = out.replace(TOKEN_RE, '[REDACTED_TOKEN]');
  out = out.replace(SECRET_KV_RE, (_m, k, sep) => `${k}${sep}[REDACTED]`);
  return out;
}

function escapeRegExp(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function randomId(prefix) {
  const rand = crypto.randomBytes(5).toString('hex');
  return `${prefix || 'id'}-${Date.now().toString(36)}${rand}`;
}

module.exports = {
  normalizeDomain,
  isValidDomain,
  isSubdomainOf,
  matchScopeRoot,
  parseUrlSafe,
  sha16,
  clampInt,
  toBool,
  sanitizeFilename,
  sanitizeText,
  maskSecrets,
  escapeRegExp,
  randomId,
};
