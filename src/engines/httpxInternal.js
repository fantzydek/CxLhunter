'use strict';

/**
 * HttpxInternalEngine - deteksi layanan HTTP internal (pengganti httpx).
 * Input: daftar host (file list atau array). Output: item host hidup dengan
 * meta (status, title, webserver, tech, content-length, redirect final).
 * Protokol diuji: https dulu lalu http (mengikuti preferensi scope).
 * Semua request GET ringan, DNS ter-pin, timeout ketat.
 */

const fs = require('fs');
const { requestPinned, requestFollow, mapPool, extractTitle, finalUrlOf, sleep } = require('./internal/netClient');
const { detectTech } = require('./internal/techKit');

class HttpxInternalEngine {
  constructor(config, logger) {
    this.name = 'httpx-internal';
    this.builtIn = true;
    this.config = config;
    this.logger = logger && logger.child ? logger.child('httpx-internal') : logger;
  }

  async checkInstalled() {
    return { status: 'AVAILABLE', version: `node-${process.version} (internal)`, binaryPath: 'internal', reason: 'OK', error: null };
  }

  _readHosts(opts) {
    let hosts = [];
    if (opts.listFile) {
      const raw = fs.readFileSync(opts.listFile, 'utf8');
      hosts = raw.split('\n').map((s) => s.trim()).filter(Boolean);
    } else if (Array.isArray(opts.hosts)) {
      hosts = opts.hosts.map(String);
    }
    return [...new Set(hosts)];
  }

  _candidateUrls(host) {
    // bila host sudah berisi skema, pakai apa adanya
    if (/^https?:\/\//i.test(host)) return [host];
    const ports = (this.config.allowedPorts && this.config.allowedPorts.length ? this.config.allowedPorts : ['443', '80']).map(String);
    const protos = (this.config.allowedProtocols && this.config.allowedProtocols.length ? this.config.allowedProtocols : ['https', 'http']).map(String);
    const urls = [];
    for (const proto of protos) {
      for (const p of ports.slice(0, 4)) {
        const isDefault = (proto === 'https' && p === '443') || (proto === 'http' && p === '80');
        const withPort = isDefault ? '' : `:${p}`;
        urls.push(`${proto}://${host}${withPort}`);
      }
    }
    return [...new Set(urls)].slice(0, 8);
  }

  async run(jobCtx, opts) {
    const o = opts || {};
    const hosts = this._readHosts(o).slice(0, this.config.maxResolveTargets);
    const items = [];
    const stats = { probed: 0, live: 0, errors: 0 };
    const maxBody = 256 * 1024;
    const limiter = new (require('./internal/netClient').RateLimiter)({ minDelayMs: 100, concurrency: 6 });
    const timeoutMs = (this.config.engineTimeouts && this.config.engineTimeouts.httpx) || 180000;

    const deadline = Date.now() + timeoutMs;

    async function probeOne(url, ip) {
      const r = await requestFollow({
        url,
        ip,
        method: 'GET',
        timeoutMs: 12000,
        maxBodyBytes: maxBody,
        maxRedirects: 4,
        userAgent: this.config.userAgent,
        interRequestDelayMs: 100,
      });
      return r;
    }

    const probeOneBound = probeOne.bind(this);

    for (const host of hosts) {
      if (jobCtx.signal && jobCtx.signal.aborted) {
        const e = new Error('Dibatalkan pengguna');
        e.name = 'AbortError';
        throw e;
      }
      if (Date.now() > deadline) break;
      // eslint-disable-next-line no-await-in-loop
      const found = await this._probeHost(host, o.ipMap || null, probeOneBound, items, stats, limiter, maxBody);
      if (!found) stats.errors++;
      // eslint-disable-next-line no-await-in-loop
      await sleep(50);
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
      usedArgs: [`hosts=${hosts.length}`],
    };
  }

  async _probeHost(host, ipMap, probeOne, items, stats, limiter, maxBody) {
    const candidates = this._candidateUrls(host).slice(0, 8);
    for (const url of candidates) {
      const ip = ipMap && ipMap.get ? ipMap.get(host) : ipMap || null;
      // eslint-disable-next-line no-await-in-loop
      const r = await limiter.run(() => probeOne(url, ip));
      stats.probed++;
      if (!r.ok || !r.status) continue;
      stats.live++;
      const finalUrl = finalUrlOf(r.redirectChain, url);
      const tech = detectTech({ headers: r.headers, body: r.body });
      const server = String((r.headers && r.headers.server) || '').slice(0, 100);
      const cl = (r.headers && (r.headers['content-length'] || (r.body ? String(r.body.length) : '0'))) || '0';
      items.push({
        url: finalUrl || url,
        requestedUrl: url,
        host,
        statusCode: r.status,
        title: extractTitle(r.body),
        webserver: server,
        tech: tech.map((t) => (t.version ? `${t.name}/${t.version}` : t.name)).join(',').slice(0, 200),
        techList: tech,
        contentLength: parseInt(cl, 10) || 0,
        tlsProto: r.tlsProto || null,
        redirects: (r.redirectChain || []).map((c) => `${c.status}->${c.location}`.slice(0, 200)),
      });
      return true; // satu URL hidup cukup per host
    }
    return false;
  }
}

module.exports = { HttpxInternalEngine };
