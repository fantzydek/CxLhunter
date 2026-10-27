'use strict';

/**
 * Network Guard: gerbang kedua, dipanggil sebelum setiap tahap dan setiap request internal.
 * - Menolak localhost, private IP, link-local, multicast, reserved, CGNAT, dokumentasi
 * - Resolusi DNS fail-closed: gagal resolve => DENY
 * - Mencatat SEMUA keputusan (ALLOW/DENY) ke tabel scope_decisions
 * - Re-check DNS antar tahap (mitigasi DNS rebinding; lihat README untuk batasan TOCTOU
 *   terkait engine eksternal yang melakukan resolusi sendiri)
 * - resolveFn dapat diinjeksi untuk pengujian
 */

const dns = require('dns').promises;
const { isIP } = require('net');
const { isLabIpAllowed, ip6ToBigInt } = require('./validator');

// ---- Klasifikasi IPv4 ----
const V4_RANGES = [
  ['0.0.0.0', 8, 'this-network'],
  ['10.0.0.0', 8, 'private'],
  ['100.64.0.0', 10, 'cgnat'],
  ['127.0.0.0', 8, 'loopback'],
  ['169.254.0.0', 16, 'link-local'],
  ['172.16.0.0', 12, 'private'],
  ['192.0.0.0', 24, 'ietf-protocol'],
  ['192.0.2.0', 24, 'documentation'],
  ['192.88.99.0', 24, 'anycast'],
  ['192.168.0.0', 16, 'private'],
  ['198.18.0.0', 15, 'benchmark'],
  ['198.51.100.0', 24, 'documentation'],
  ['203.0.113.0', 24, 'documentation'],
  ['224.0.0.0', 4, 'multicast'],
  ['240.0.0.0', 4, 'reserved'],
];

function v4ToInt(ip) {
  const parts = String(ip).split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const v = parseInt(p, 10);
    if (!/^\d+$/.test(p) || !Number.isInteger(v) || v > 255) return null;
    n = n * 256 + v;
  }
  return n >>> 0;
}

function v4Matches(ip, base, bits) {
  const a = v4ToInt(ip);
  const b = v4ToInt(base);
  if (a == null || b == null) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (a & mask) === (b & mask);
}

// ---- Klasifikasi IPv6 (BigInt) ----
const V6_RANGES = [
  ['::', 128, 'unspecified'],
  ['::1', 128, 'loopback'],
  ['fc00::', 7, 'ula'],
  ['fe80::', 10, 'link-local'],
  ['ff00::', 8, 'multicast'],
  ['2001:db8::', 32, 'documentation'],
  ['100::', 64, 'discard'],
  ['2002::', 16, '6to4'],
  ['64:ff9b::', 96, 'nat64'],
  ['::ffff:0:0', 96, 'v4-mapped'],
];

function v6Matches(ip, base, bits) {
  const a = ip6ToBigInt(ip);
  const b = ip6ToBigInt(base);
  if (a == null || b == null) return false;
  const mask = bits === 0 ? 0n : ((1n << BigInt(bits)) - 1n) << BigInt(128 - bits);
  return (a & mask) === (b & mask);
}

/**
 * Periksa apakah IP termasuk kategori yang ditolak.
 * Hasil: null (public/boleh) atau { category }
 */
function classifyReservedIp(ip) {
  if (isIP(ip) === 4) {
    for (const [base, bits, cat] of V4_RANGES) {
      if (v4Matches(ip, base, bits)) return { category: cat };
    }
    return null;
  }
  if (isIP(ip) === 6) {
    // v4-mapped: evaluasi IPv4 di dalamnya (::ffff:a.b.c.d == a.b.c.d)
    const v6 = ip6ToBigInt(ip);
    if (v6 != null && v6Matches(ip, '::ffff:0:0', 96)) {
      const lo = v6 & 0xffffffffn;
      const v4 = [(lo >> 24n) & 0xffn, (lo >> 16n) & 0xffn, (lo >> 8n) & 0xffn, lo & 0xffn]
        .map((x) => x.toString())
        .join('.');
      const cls = classifyReservedIp(v4);
      if (cls) return cls;
      return null; // mapped ke IPv4 publik == publik
    }
    // NAT64 (64:ff9b::/96) & 6to4 (2002::/16) selalu dianggap reserved secara konservatif:
    // akses melewati gateway penerjemah/relay, bukan koneksi langsung ke tujuan.
    for (const [base, bits, cat] of V6_RANGES) {
      if (v6Matches(ip, base, bits)) return { category: cat };
    }
    return null;
  }
  return { category: 'invalid' };
}

function isPrivateIp(ip) {
  return classifyReservedIp(ip) != null;
}

class NetworkGuard {
  constructor({ config, store, logger, resolveFn } = {}) {
    this.config = config;
    this.store = store || null;
    this.logger = logger || { debug: () => {}, warn: () => {}, info: () => {} };
    this.resolveFn = resolveFn || this._defaultResolve.bind(this);
    this._cache = new Map(); // host -> { ips, ts }
  }

  async _defaultResolve(host) {
    const out = { ips: [], errors: [] };
    const fams = [dns.resolve4, dns.resolve6];
    for (const fn of fams) {
      try {
        const rows = await fn(host);
        for (const r of rows) {
          const ip = typeof r === 'string' ? r : r.address;
          if (ip && !out.ips.includes(ip)) out.ips.push(ip);
        }
      } catch (err) {
        out.errors.push(err.code || err.message);
      }
    }
    return out;
  }

  _record(scanId, decision, { host, ip, reason, stage }) {
    if (this.store) {
      try {
        this.store.saveDecision(scanId, { decision, host, ip, reason, stage });
      } catch (e) {
        this.logger.warn('Gagal menyimpan keputusan scope:', e.message);
      }
    }
    this.logger.debug(`GUARD ${decision} host=${host || '-'} ip=${ip || '-'} alasan=${reason} tahap=${stage || '-'}`);
  }

  /** Periksa satu IP literal. Hasil: {allowed, reason, ip} */
  checkIp(ip, { scanId, stage, host } = {}) {
    if (isIP(ip) == null) {
      this._record(scanId, 'DENY', { host, ip, reason: 'IP tidak valid', stage });
      return { allowed: false, reason: 'IP tidak valid', ip };
    }
    const cls = classifyReservedIp(ip);
    if (cls && !this.config.labMode) {
      this._record(scanId, 'DENY', {
        host,
        ip,
        reason: `Alamat internal/dilindungi (${cls.category}) ditolak secara default`,
        stage,
      });
      return { allowed: false, reason: `Alamat internal (${cls.category})`, ip };
    }
    if (cls && this.config.labMode) {
      if (!isLabIpAllowed(this.config, ip)) {
        this._record(scanId, 'DENY', {
          host,
          ip,
          reason: `Alamat internal (${cls.category}) di luar LAB_ALLOWED_TARGETS`,
          stage,
        });
        return { allowed: false, reason: `Alamat internal (${cls.category}) di luar lab allowlist`, ip };
      }
      this._record(scanId, 'ALLOW', { host, ip, reason: 'LAB MODE: diizinkan eksplisit', stage });
      return { allowed: true, reason: 'lab-mode', ip };
    }
    this._record(scanId, 'ALLOW', { host, ip, reason: 'IP publik', stage });
    return { allowed: true, reason: 'public', ip };
  }

  /**
   * Periksa host (domain atau IP) sebelum digunakan.
   * Domain: resolve A+AAAA, SEMUA hasil harus publik (fail-closed).
   * Hasil: { allowed, reason, ips }
   */
  async checkHost(host, { scanId, stage, useCache = true } = {}) {
    if (!host || typeof host !== 'string') {
      this._record(scanId, 'DENY', { host, reason: 'Host kosong/tidak valid', stage });
      return { allowed: false, reason: 'Host tidak valid', ips: [] };
    }
    const h = host.replace(/^\[|\]$/g, '');
    if (isIP(h)) {
      const r = this.checkIp(h, { scanId, stage, host: h });
      return { allowed: r.allowed, reason: r.reason, ips: r.allowed ? [h] : [] };
    }
    if (useCache) {
      const c = this._cache.get(h);
      if (c && Date.now() - c.ts < 60000) {
        return { allowed: true, reason: 'cache', ips: c.ips };
      }
    }

    let res;
    try {
      res = await this.resolveFn(h);
    } catch (err) {
      this._record(scanId, 'DENY', { host: h, reason: `Resolver error: ${err.message}`, stage });
      return { allowed: false, reason: 'Gagal resolusi DNS (fail-closed)', ips: [] };
    }
    if (!res || !res.ips || !res.ips.length) {
      const detail = res && res.errors && res.errors.length ? res.errors.join(',') : 'ENODATA';
      this._record(scanId, 'DENY', { host: h, reason: `DNS tanpa alamat (${detail})`, stage });
      return { allowed: false, reason: 'Host tidak dapat diresolusi (fail-closed)', ips: [] };
    }
    for (const ip of res.ips) {
      const r = this.checkIp(ip, { scanId, stage, host: h });
      if (!r.allowed) return { allowed: false, reason: r.reason, ips: res.ips };
    }
    this._cache.set(h, { ips: res.ips, ts: Date.now() });
    return { allowed: true, reason: 'dns-ok', ips: res.ips };
  }

  /**
   * Re-check antar tahap: resolve ulang dan pastikan tidak berubah menjadi alamat internal.
   * Mengembalikan { allowed, ips, changed }
   */
  async recheckHost(host, { scanId, stage } = {}) {
    const prev = this._cache.get(host);
    const r = await this.checkHost(host, { scanId, stage, useCache: false });
    const changed = prev ? JSON.stringify(prev.ips.slice().sort()) !== JSON.stringify(r.ips.slice().sort()) : true;
    if (r.allowed && changed) {
      this.logger.debug(`DNS re-check ${host}: ${prev ? prev.ips.join(',') : 'baru'} -> ${r.ips.join(',')}`);
    }
    return { ...r, changed };
  }

  /** Validasi host hasil enumerasi (subfinder/dnsx) sebelum dipakai ke tahap berikutnya. */
  async filterHosts(hosts, { scanId, stage, limit } = {}) {
    const out = [];
    for (const host of hosts) {
      if (limit && out.length >= limit) break;
      // eslint-disable-next-line no-await-in-loop
      const r = await this.checkHost(host, { scanId, stage });
      if (r.allowed) out.push({ host, ips: r.ips });
    }
    return out;
  }

  clearCache() {
    this._cache.clear();
  }
}

const AbortErrorName = 'AbortError';
function abortError(message) {
  const e = new Error(message || 'Operasi dibatalkan');
  e.name = AbortErrorName;
  return e;
}
function isAbortError(err) {
  return err && (err.name === AbortErrorName || err.code === 'ABORT_ERR');
}

module.exports = { NetworkGuard, isPrivateIp, classifyReservedIp, abortError, isAbortError };
