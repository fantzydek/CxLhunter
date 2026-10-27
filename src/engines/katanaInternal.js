'use strict';

/**
 * KatanaInternalEngine - crawler internal ringan (pengganti katana).
 * BFS terbatas: ambil tautan (a href), script JS, form action, iframe src.
 * Filter scope ketat via validator (hostInScope / validateUrl), depth & jumlah
 * endpoint dibatasi konfigurasi. Hanya GET, tanpa eksekusi JS.
 */

const { requestFollow, mapPool, sleep } = require('./internal/netClient');

const LINK_RE = /(?:href|src|action|data-url|data-href)\s*=\s*["']([^"'\s]{1,500})["']/gi;

function extractLinks(html, baseUrl) {
  const out = new Set();
  const body = String(html || '');
  let m;
  // regex loop sederhana (LINK_RE global direset tiap panggilan)
  const re = new RegExp(LINK_RE.source, 'gi');
  while ((m = re.exec(body)) !== null) {
    const raw = m[1];
    if (!raw || raw.startsWith('#') || /^(javascript|mailto|tel|data|blob):/i.test(raw)) continue;
    try {
      const abs = new URL(raw, baseUrl).toString();
      if (/^https?:\/\//i.test(abs)) out.add(abs.split('#')[0]);
    } catch (_) {
      /* URL rusak - abaikan */
    }
  }
  // endpoint-ish paths di JS inline (fetch/axios/api path)
  const apiRe = /["'](\/(?:api|v[0-9]|rest|graphql|admin|user|upload|ajax)[a-zA-Z0-9_\-/.]{0,120})["']/g;
  while ((m = apiRe.exec(body)) !== null) {
    try {
      const abs = new URL(m[1], baseUrl).toString();
      out.add(abs.split('#')[0]);
    } catch (_) { /* abaikan */ }
  }
  return [...out];
}

function extractForms(html, baseUrl) {
  const forms = [];
  const re = /<form[^>]*>[\s\S]{0,4000}?<\/form>/gi;
  let m;
  while ((m = re.exec(String(html || ''))) !== null) {
    const tag = m[0];
    const action = /action\s*=\s*["']([^"']*)["']/i.exec(tag);
    const method = /method\s*=\s*["']([^"']*)["']/i.exec(tag);
    const inputs = [];
    const inputRe = /<input[^>]*>/gi;
    let im;
    while ((im = inputRe.exec(tag)) !== null) {
      const t = im[0];
      const name = /name\s*=\s*["']([^"']*)["']/i.exec(t);
      const type = /type\s*=\s*["']([^"']*)["']/i.exec(t);
      if (name) inputs.push({ name: name[1].slice(0, 80), type: type ? type[1] : 'text' });
    }
    let absAction = '';
    try {
      absAction = new URL(action && action[1] ? action[1] : '', baseUrl).toString();
    } catch (_) {
      absAction = baseUrl;
    }
    forms.push({ action: absAction, method: (method ? method[1] : 'get').toUpperCase(), inputs: inputs.slice(0, 30) });
  }
  return forms;
}

class KatanaInternalEngine {
  constructor(config, logger) {
    this.name = 'katana-internal';
    this.builtIn = true;
    this.config = config;
    this.logger = logger && logger.child ? logger.child('katana-internal') : logger;
  }

  async checkInstalled() {
    return { status: 'AVAILABLE', version: `node-${process.version} (internal)`, binaryPath: 'internal', reason: 'OK', error: null };
  }

  async run(jobCtx, opts) {
    const o = opts || {};
    const seeds = (o.seeds || []).slice(0, 10);
    if (o.listFile) {
      const fs = require('fs');
      const raw = fs.readFileSync(o.listFile, 'utf8');
      for (const s of raw.split('\n').map((x) => x.trim()).filter(Boolean)) {
        if (seeds.length < 10) seeds.push(s);
      }
    }
    if (!seeds.length) {
      return { status: 'COMPLETED', items: [], stats: { crawled: 0, found: 0 }, exitCode: 0, timedOut: false, truncated: false, stderrHead: '', error: null, droppedFlags: [], usedArgs: ['seeds=0'] };
    }

    const maxDepth = Math.max(1, Math.min(this.config.katanaDepth || 2, 4));
    const maxEndpoints = this.config.maxEndpoints || 300;
    const maxBody = 256 * 1024;
    const items = [];
    const stats = { crawled: 0, found: 0, errors: 0 };
    const visited = new Set();
    let queue = seeds.map((u) => ({ url: u, depth: 1 }));
    const validator = (jobCtx && jobCtx.validator) || null;

    const inScope = (url) => {
      if (!validator) return true;
      try {
        // validateUrl menangani domain scope + IP literal lab mode secara konsisten
        const v = validator.validateUrl(url);
        return !!v.ok;
      } catch (_) {
        return false;
      }
    };

    for (let depth = 1; depth <= maxDepth; depth++) {
      if (items.length >= maxEndpoints) break;
      const level = queue.filter((q) => q.depth === depth && !visited.has(q.url) && inScope(q.url));
      if (!level.length) break;
      // eslint-disable-next-line no-await-in-loop
      await mapPool(level, 5, async (q) => {
        if (items.length >= maxEndpoints || visited.has(q.url)) return;
        if (jobCtx.signal && jobCtx.signal.aborted) return;
        visited.add(q.url);
        // endpoint DICATAT dulu (discovery dari tautan), konten hanya untuk crawl lebih dalam
        items.push({ url: q.url, method: 'GET', source: 'crawl' });
        stats.found++;
        // JANGAN ikuti redirect saat crawl (hindari keluar scope); cukup catat endpoint
        // eslint-disable-next-line no-await-in-loop
        const r = await requestFollow({
          url: q.url,
          ip: o.ipMap && o.ipMap.get ? o.ipMap.get(new URL(q.url).hostname) : null,
          method: 'GET',
          timeoutMs: 12000,
          maxBodyBytes: maxBody,
          maxRedirects: 0,
          userAgent: this.config.userAgent,
        });
        stats.crawled++;
        if (!r.ok || !r.status || r.status >= 400) {
          if (!r.ok) stats.errors++;
          return;
        }
        const ctype = String((r.headers && r.headers['content-type']) || '');
        if (/text\/html/i.test(ctype) && q.depth < maxDepth) {
          const links = extractLinks(r.body, q.url).filter(inScope);
          for (const l of links.slice(0, 60)) {
            if (items.length >= maxEndpoints) break;
            if (!visited.has(l)) queue.push({ url: l, depth: q.depth + 1 });
          }
        }
      });
      // eslint-disable-next-line no-await-in-loop
      await sleep(80);
    }

    // dedup
    const seen = new Set();
    const dedup = [];
    for (const it of items) {
      if (seen.has(it.url)) continue;
      seen.add(it.url);
      dedup.push(it);
    }

    return {
      status: 'COMPLETED',
      items: dedup.slice(0, maxEndpoints),
      stats: { ...stats, found: dedup.length },
      exitCode: 0,
      timedOut: false,
      truncated: false,
      stderrHead: '',
      error: null,
      droppedFlags: [],
      usedArgs: [`seeds=${seeds.length}`, `depth=${maxDepth}`],
    };
  }
}

module.exports = { KatanaInternalEngine, extractLinks, extractForms };
