'use strict';

/**
 * Scope validator: gerbang pertama sebelum segala aktivitas jaringan.
 * - Allowlist eksplisit root domain (config.allowedTargets)
 * - Port & protokol dari allowlist
 * - Menolak IP literal (kecuali lab mode), URL ber-kredensial, skema aneh
 * - Validasi redirect: host tujuan HARUS tetap dalam scope
 */

const { isIP } = require('net');
const { normalizeDomain, isValidDomain, isSubdomainOf, parseUrlSafe } = require('../utils/validation');

class ScopeValidator {
  constructor(config) {
    this.config = config;
    this.roots = (config.allowedTargets || []).filter((r) => isValidDomain(r));
    this.ports = config.allowedPorts || ['80', '443', '8080', '8443'];
    this.protocols = config.allowedProtocols || ['https', 'http'];
  }

  get configured() {
    return this.roots.length > 0;
  }

  /**
   * Mode terbuka: ALLOWED_TARGETS kosong. Scanner menerima domain publik apa pun
   * (pelindung IP internal/privat di networkGuard TETAP aktif). Isi ALLOWED_TARGETS
   * untuk mengunci scanner hanya ke domain yang Anda izinkan.
   */
  get openMode() {
    return this.roots.length === 0;
  }

  /** Validasi input target pengguna (domain atau URL). Hasil: {ok, host, root, reason} */
  validateTargetInput(input) {
    if (typeof input !== 'string' || !input.trim()) {
      return { ok: false, reason: 'Target kosong. Contoh: /scan example.com' };
    }
    if (input.length > 253) return { ok: false, reason: 'Input terlalu panjang untuk sebuah domain' };
    if (isIP(input.trim())) {
      return {
        ok: false,
        reason:
          'Alamat IP literal tidak diizinkan di mode normal. Untuk lab lokal gunakan LAB_MODE + LAB_ALLOWED_TARGETS.',
      };
    }
    const host = normalizeDomain(input);
    if (!host) {
      return { ok: false, reason: 'Input bukan hostname yang valid. Gunakan format domain, mis: example.com' };
    }
    if (this.openMode) {
      // Mode terbuka: domain valid apa pun diterima; root diikat ke host target
      return { ok: true, host, root: host, openMode: true };
    }
    const root = matchRoot(host, this.roots);
    if (!root) {
      return {
        ok: false,
        reason: `Target di luar scope. Root yang diizinkan: ${this.roots.join(', ')}`,
      };
    }
    return { ok: true, host, root };
  }

  /** Host termasuk scope? Kembalikan root atau null. */
  hostInScope(host) {
    if (!host) return null;
    const h = String(host).toLowerCase().replace(/\.$/, '');
    if (isIP(h)) return null; // IP tidak otomatis dalam scope
    if (!isValidDomain(h)) return null;
    if (this.openMode) return h; // mode terbuka: domain valid apa pun dalam scope
    return matchRoot(h, this.roots);
  }

  /** Validasi URL untuk feed engine. Hasil: {ok, url, host, reason} */
  validateUrl(input, { allowIpLiteral = false } = {}) {
    const r = parseUrlSafe(input, {
      allowedProtocols: this.protocols,
      allowedPorts: this.ports,
      // IP literal diizinkan hanya pada LAB MODE (konsisten dengan kebijakan lab di bawah)
      allowIpLiteral: allowIpLiteral || this.config.labMode,
    });
    if (!r.ok) return r;
    if (!r.isIp) {
      const root = this.hostInScope(r.host);
      if (!root) return { ok: false, reason: `Host di luar scope: ${r.host}` };
      return { ok: true, url: r.url, host: r.host, root };
    }
    // IP literal hanya bila lab mode mengizinkan
    if (!this.config.labMode) return { ok: false, reason: 'IP literal ditolak di mode normal' };
    const ip = r.host.replace(/^\[|\]$/g, '');
    if (!isLabIpAllowed(this.config, ip)) return { ok: false, reason: 'IP di luar lab allowlist' };
    return { ok: true, url: r.url, host: r.host, root: 'LAB' };
  }

  /** Validasi target redirect: harus tetap dalam scope. Hasil: {ok, reason} */
  validateRedirect(fromUrl, locationHeader) {
    if (!locationHeader) return { ok: false, reason: 'Redirect tanpa Location' };
    let abs;
    try {
      abs = new URL(locationHeader, fromUrl);
    } catch (_) {
      return { ok: false, reason: 'Header Location tidak valid' };
    }
    const v = this.validateUrl(abs.toString());
    return v.ok ? { ok: true, url: abs.toString(), host: v.host } : { ok: false, reason: v.reason };
  }

  /** URL target dasar untuk sebuah host (https dahulu). */
  targetUrls(host) {
    const urls = [`https://${host}`];
    if (this.protocols.includes('http')) urls.push(`http://${host}`);
    return urls;
  }
}

function matchRoot(host, roots) {
  for (const root of roots) {
    if (isSubdomainOf(host, root)) return root;
  }
  return null;
}

/** Kebijakan IP lab: hanya bila lab mode aktif dan IP termasuk lab allowlist (CIDR/host). */
function isLabIpAllowed(config, ip) {
  if (!config.labMode) return false;
  const targets = config.labTargets || [];
  if (!targets.length) return false;
  for (const t of targets) {
    if (t.includes('/')) {
      if (ipInCidr(ip, t)) return true;
    } else if (t === ip) {
      return true;
    } else if (isIP(t)) {
      continue;
    } else if (t.includes('*')) {
      // wildcard sederhana 192.168.*.*
      const re = new RegExp('^' + t.split('.').map((p) => (p === '*' ? '\\d+' : p)).join('\\.') + '$');
      if (re.test(ip)) return true;
    }
  }
  return false;
}

function ip4ToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const v = parseInt(p, 10);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = n * 256 + v;
  }
  return n;
}

function ipInCidr(ip, cidr) {
  const [base, bitsRaw] = cidr.split('/');
  const bits = parseInt(bitsRaw, 10);
  if (isIP(base) === 4 && isIP(ip) === 4) {
    const a = ip4ToInt(ip);
    const b = ip4ToInt(base);
    if (a == null || b == null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return ((a >>> 0) & mask) === ((b >>> 0) & mask);
  }
  if (isIP(base) === 6 && isIP(ip) === 6) {
    // pembanding IPv6 sederhana via BigInt
    const a6 = ip6ToBigInt(ip);
    const b6 = ip6ToBigInt(base);
    if (a6 == null || b6 == null || !Number.isInteger(bits) || bits < 0 || bits > 128) return false;
    const mask = bits === 0 ? 0n : ((1n << BigInt(bits)) - 1n) << BigInt(128 - bits);
    return (a6 & mask) === (b6 & mask);
  }
  return false;
}

function ip6ToBigInt(ip) {
  if (!ip.includes(':')) return null;
  let padded = ip.replace(/^\[|\]$/g, '');
  // Notasi IPv4-dotted di ujung (mis. ::ffff:10.0.0.1) -> dua segmen hex
  const dottedIdx = padded.lastIndexOf('.');
  if (dottedIdx !== -1) {
    const lastColon = padded.lastIndexOf(':');
    const v4part = padded.slice(lastColon + 1);
    const v4 = v4part.split('.');
    if (v4.length !== 4) return null;
    const hexParts = [];
    for (const seg of v4) {
      const n = parseInt(seg, 10);
      if (!/^\d+$/.test(seg) || !Number.isInteger(n) || n > 255) return null;
      hexParts.push(n.toString(16).padStart(2, '0'));
    }
    padded = padded.slice(0, lastColon + 1) + hexParts[0] + hexParts[1] + ':' + hexParts[2] + hexParts[3];
  }
  const sections = padded.split('::');
  if (sections.length > 2) return null;
  const head = sections[0] ? sections[0].split(':').filter(Boolean) : [];
  const tail = sections.length === 2 && sections[1] ? sections[1].split(':').filter(Boolean) : [];
  const missing = 8 - head.length - tail.length;
  if (sections.length === 2 && missing < 0) return null;
  if (sections.length === 1 && head.length !== 8) return null;
  const all = sections.length === 2 ? [...head, ...Array(missing).fill('0'), ...tail] : head;
  if (all.length !== 8) return null;
  let out = 0n;
  for (const sec of all) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(sec)) return null;
    out = (out << 16n) | BigInt(parseInt(sec, 16));
  }
  return out;
}

module.exports = { ScopeValidator, isLabIpAllowed, ipInCidr, ip6ToBigInt, matchRoot };
