'use strict';

/**
 * Orchestrator: merangkai pipeline scan per mode, membukukan engine_runs,
 * menyaring hasil melalui scope validator + network guard di SETIAP transisi tahap,
 * menggabungkan & mendeduplikasi temuan, memetakan OWASP, dan menyiapkan laporan.
 *
 * Prinsip:
 * - Progress berasal dari status proses yang NYATA (per tahap), bukan persentase palsu.
 * - Kegagalan satu engine tidak mengubah tahap independen menjadi "berhasil kosong";
 *   hasil akhir ditandai PARTIAL secara jujur.
 * - Abort diturunkan ke semua child process dan di antara tahap.
 */

const fs = require('fs');
const path = require('path');
const { abortError, isAbortError } = require('../scope/networkGuard');
const { sha16, sanitizeText } = require('../utils/validation');
const { computeCoverage } = require('../owasp/coverage');
const { buildReportFiles } = require('../reports/json');
const { ENRICH } = require('../engines/internal/vulnKB');

class ScopeDeniedError extends Error {
  constructor(reason) {
    super(`Target ditolak oleh kebijakan scope: ${reason}`);
    this.name = 'ScopeDeniedError';
    this.reason = reason;
  }
}

/**
 * Peta fallback: bila binary eksternal tidak tersedia, engine INTERNAL Node murni
 * dipakai otomatis agar scan TETAP BERJALAN tanpa instalasi tambahan.
 */
const ENGINE_FALLBACK = {
  subfinder: 'subfinder-internal',
  dnsx: 'dnsx-internal',
  httpx: 'httpx-internal',
  katana: 'katana-internal',
  nuclei: 'vulnscan-internal',
  xray: 'vulnscan-internal',
};

function safeUnlinkDir(dir) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (_) {
    /* diamkan */
  }
}

function writeListFile(workDir, name, lines) {
  const p = path.join(workDir, name);
  fs.writeFileSync(p, lines.join('\n') + (lines.length ? '\n' : ''), 'utf8');
  return p;
}

class Orchestrator {
  constructor({ config, store, guard, validator, engines, logger, registry }) {
    this.config = config;
    this.store = store;
    this.guard = guard;
    this.validator = validator;
    this.engines = engines;
    this.logger = logger || console;
    this.registry = registry || null;
    this._active = new Map(); // jobId -> {cancel: bool}
  }

  _fallbackFor(engineName) {
    if (!ENGINE_FALLBACK[engineName]) return null;
    if (this.config.internalFallback === false) return null;
    const fb = this.engines.get(ENGINE_FALLBACK[engineName]);
    // kembalikan NAMA engine fallback (bukan objek)
    return fb ? ENGINE_FALLBACK[engineName] : null;
  }

  // ---------- pipeline ----------
  buildPipeline(mode, options) {
    const opts = options || {};
    const stages = [{ id: 'scope', label: 'Validasi scope & guard jaringan', run: (c) => this.stageScope(c) }];

    const push = (id, label, fn) => stages.push({ id, label, run: fn });

    const want = {
      dnsinfo: false,
      subfinder: true,
      dnsx: true,
      httpx: true,
      katana: false,
      headerProbe: false,
      nuclei: false,
      xray: false,
      secrets: false,
      ports: false,
    };
    switch (mode) {
      case 'quick':
        want.headerProbe = true;
        break;
      case 'full':
        want.katana = true;
        want.headerProbe = true;
        want.nuclei = true;
        break;
      case 'deep':
        want.subfinder = false;
        want.dnsx = false;
        want.httpx = true;
        want.katana = true;
        want.headerProbe = true;
        want.nuclei = true;
        want.secrets = true;
        break;
      case 'recon':
        want.dnsinfo = true;
        want.katana = false;
        want.ports = true;
        break;
      case 'subdomain':
        // Enumerasi subdomain saja: subfinder + dnsx + httpx (cek host hidup)
        want.dnsinfo = false;
        want.subfinder = true;
        want.dnsx = true;
        want.httpx = true;
        want.katana = false;
        break;
      case 'xss':
        // Fokus XSS: crawl endpoint berparameter + vuln scan kategori xss
        want.katana = true;
        want.headerProbe = true;
        want.nuclei = true;
        opts.nucleiTags = ['xss', 'reflected-xss', 'dalxss'];
        opts.vulnCategories = ['xss', 'header', 'cookie', 'mixed'];
        opts.deepVuln = true;
        break;
      case 'sqli':
        // Fokus SQL injection: crawl endpoint berparameter + vuln scan kategori sqli
        want.katana = true;
        want.nuclei = true;
        opts.nucleiTags = ['sqli', 'sql-injection', 'mysql', 'postgresql', 'mssql'];
        opts.vulnCategories = ['sqli'];
        opts.deepVuln = true;
        break;
      case 'sans':
        // SANS/CWE Top 25: kombinasi injection, XSS, SSRF, traversal, redirect
        want.katana = true;
        want.headerProbe = true;
        want.nuclei = true;
        opts.nucleiTags = ['xss', 'sqli', 'ssrf', 'command-injection', 'deserialization', 'code-injection', 'lfi', 'path-traversal', 'xxe', 'idor'];
        opts.vulnCategories = ['xss', 'sqli', 'redirect', 'traversal', 'cors', 'methods', 'takeover', 'info'];
        opts.deepVuln = true;
        break;
      case 'malware':
        // Deteksi malware/defacement/spam/webshell + blacklist cek pasif
        want.katana = true;
        want.nuclei = true;
        opts.nucleiTags = ['malware', 'phishing', 'deface', 'cryptominer', 'spam'];
        opts.vulnCategories = ['malware', 'info'];
        break;
      case 'owasp':
        want.subfinder = false;
        want.dnsx = false;
        want.headerProbe = true;
        want.nuclei = true;
        break;
      case 'nuclei':
      case 'deepvuln':
        want.subfinder = false;
        want.dnsx = false;
        want.nuclei = true;
        break;
      case 'secrets':
        want.subfinder = false;
        want.dnsx = false;
        want.headerProbe = false;
        want.secrets = true;
        break;
      case 'endpoints':
        want.subfinder = false;
        want.dnsx = false;
        want.katana = true;
        break;
      case 'custom':
        want.subfinder = opts.engines.includes('subfinder');
        want.dnsx = opts.engines.includes('dnsx');
        want.httpx = opts.engines.includes('httpx');
        want.katana = opts.engines.includes('katana');
        want.headerProbe = opts.engines.includes('headerProbe');
        want.nuclei = opts.engines.includes('nuclei');
        want.xray = opts.engines.includes('xray');
        want.secrets = opts.engines.includes('secrets');
        want.ports = opts.engines.includes('ports');
        break;
      default:
        break;
    }
    // httpx selalu dibutuhkan sebagai sumber target untuk tahap lain (kecuali tidak ada sama sekali)
    if (want.dnsinfo) push('dnsinfo', 'Informasi DNS & keamanan email (internal)', (c) => this.stageDnsInfo(c));
    if (want.subfinder) push('subfinder', 'Enumerasi subdomain pasif (subfinder)', (c) => this.stageSubfinder(c));
    if (want.dnsx) push('dnsx', 'Resolusi & validasi DNS (dnsx)', (c) => this.stageDnsx(c));
    if (want.httpx) push('httpx', 'Deteksi layanan HTTP (httpx)', (c) => this.stageHttpx(c));
    if (want.katana) push('katana', 'Crawling endpoint (katana)', (c) => this.stageKatana(c));
    if (want.headerProbe) push('headerProbe', 'Pemeriksaan header/TLS (internal)', (c) => this.stageHeaderProbe(c));
    if (want.secrets) push('secrets', 'Pemindaian secrets/API key (internal)', (c) => this.stageSecrets(c));
    if (want.nuclei) push('nuclei', 'Pemindaian kerentanan non-destruktif (nuclei/vulnscan)', (c) => this.stageNuclei(c));
    if (want.xray) push('xray', 'Pemindaian Xray (bila kompatibel)', (c) => this.stageXray(c));
    if (want.ports) push('ports', 'Pemindaian port web umum (internal)', (c) => this.stagePorts(c));

    push('finalize', 'Gabungkan hasil, peta OWASP, buat laporan', (c) => this.stageFinalize(c, mode, opts));
    return stages;
  }

  // ---------- util ----------
  _checkAbort(jobCtx) {
    if (jobCtx.signal && jobCtx.signal.aborted) throw abortError('Scan dibatalkan');
  }

  async _ingestFindings(jobCtx, engineName, items) {
    let added = 0;
    for (const it of items || []) {
      const engine = it.engine || engineName;
      const hash = sha16(
        `${engine}|${(it.externalId || '').toLowerCase()}|${(it.target || '').toLowerCase()}|${String(
          it.evidence || ''
        ).slice(0, 200)}`
      );
      // Enrichment: sisipkan Vuln ID, CWE, contoh payload & contoh bug dari KB
      const enrichedEvidence = this._enrichEvidence(it.externalId, it.evidence);
      const ok = this.store.saveFinding(jobCtx.scanId, {
        engine,
        externalId: it.externalId,
        name: it.name,
        severity: it.severity,
        target: it.target,
        evidence: enrichedEvidence,
        reference: it.reference,
        tags: it.tags,
        classification: it.classification || 'INDICATOR',
        owaspId: it.owaspId || null,
        dedupeHash: hash,
      });
      if (ok) {
        added++;
        this._pushRecent(jobCtx, { engine, hash, ...it, evidence: enrichedEvidence });
      }
    }
    jobCtx.counts.findings = this.store.countFindings(jobCtx.scanId);
    return added;
  }

  /** Sisipkan metadata KB (vuln_id, cwe, payload_example, bug_example) ke evidence JSON. */
  _enrichEvidence(externalId, evidence) {
    let meta = null;
    try {
      meta = ENRICH(externalId, evidence);
    } catch (_) {
      meta = null;
    }
    if (!meta) return evidence;
    let obj = {};
    try {
      obj = JSON.parse(evidence) || {};
      if (typeof obj !== 'object' || Array.isArray(obj)) obj = { detail: evidence };
    } catch (_) {
      obj = { detail: evidence };
    }
    const merged = { ...obj, ...meta };
    return JSON.stringify(merged).slice(0, 4000);
  }

  /** Simpan temuan terbaru (maks 12) untuk ditampilkan LIVE saat scan berjalan. */
  _pushRecent(jobCtx, it) {
    if (!Array.isArray(jobCtx.recent)) jobCtx.recent = [];
    let payload = '';
    let vulnId = '';
    let cwe = '';
    let example = '';
    try {
      const ev = JSON.parse(it.evidence) || {};
      payload = (ev.payload_example && ev.payload_example[0]) || '';
      vulnId = ev.vuln_id || '';
      cwe = ev.cwe || '';
      if (ev.bug_example) example = ev.bug_example.vulnerable || ev.bug_example.attack || '';
    } catch (_) {
      payload = '';
    }
    // potong path target agar ringkas
    let shortTarget = String(it.target || '');
    try {
      const u = new URL(shortTarget);
      shortTarget = u.host + u.pathname + (u.search || '');
    } catch (_) {
      /* biarkan apa adanya */
    }
    jobCtx.recent.push({
      hash: it.hash,
      vulnId,
      cwe,
      name: it.name || it.externalId || '-',
      severity: String(it.severity || 'info').toLowerCase(),
      target: shortTarget.slice(0, 120),
      payload: String(payload).slice(0, 160),
      example: String(example).slice(0, 200),
    });
    if (jobCtx.recent.length > 12) jobCtx.recent.splice(0, jobCtx.recent.length - 12);
  }

  /** Jalankan satu engine lengkap dengan pembukuan engine_runs. */
  async runEngine(jobCtx, engineName, opts) {
    const engine = this.engines.get(engineName);
    if (!engine) {
      jobCtx.engineStatuses[engineName] = { status: 'UNAVAILABLE', reason: 'engine tidak terdaftar' };
      return { status: 'UNAVAILABLE', items: [], stats: {} };
    }
    const chk = await engine.checkInstalled();
    if (chk.status !== 'AVAILABLE') {
      // Fallback otomatis ke engine internal bila ada
      const fbName = this._fallbackFor(engineName);
      if (fbName) {
        const fbChk = await this.engines.get(fbName).checkInstalled();
        if (fbChk.status === 'AVAILABLE') {
          this.logger.warn(`[${jobCtx.jobId}] ${engineName} tidak tersedia; fallback otomatis -> ${fbName}`);
          const res = await this.runEngine(jobCtx, fbName, { ...(opts || {}), _fallbackFor: engineName });
          // Catat status pada nama engine asli agar coverage OWASP tetap benar
          jobCtx.engineStatuses[engineName] = {
            status: res.status || 'COMPLETED',
            fallback: fbName,
            version: fbChk.version,
          };
          return { ...res, fellBackTo: fbName };
        }
      }
      const runId = this.store.beginEngineRun(jobCtx.scanId, engineName, {
        status: 'UNAVAILABLE',
        version: chk.version || null,
        args: { reason: chk.reason || chk.status, error: chk.error },
      });
      this.store.finishEngineRun(runId, {
        status: 'UNAVAILABLE',
        error: `Engine tidak tersedia: ${chk.reason || chk.status} - ${chk.error || ''}`.trim(),
      });
      jobCtx.engineStatuses[engineName] = { status: chk.status, reason: chk.reason };
      this.logger.warn(`[${jobCtx.jobId}] ${engineName} tidak tersedia: ${chk.reason}`);
      return { status: chk.status, items: [], stats: {}, engine: chk };
    }
    const runId = this.store.beginEngineRun(jobCtx.scanId, engineName, {
      status: 'RUNNING',
      version: chk.version,
      args: opts && opts.usedArgsLog ? opts.usedArgsLog : null,
    });
    const started = Date.now();
    try {
      const res = await engine.run(jobCtx, opts);
      this.store.finishEngineRun(runId, {
        status: res.status || 'COMPLETED',
        exitCode: res.exitCode != null ? res.exitCode : null,
        timedOut: !!res.timedOut,
        aborted: jobCtx.signal ? jobCtx.signal.aborted : false,
        stdoutBytes: res.stdoutBytes != null ? res.stdoutBytes : null,
        stderrBytes: res.stderrBytes != null ? res.stderrBytes : null,
        truncated: !!res.truncated,
        durationMs: Date.now() - started,
        error: res.error || null,
        stderrHead: res.stderrHead || null,
      });
      jobCtx.engineStatuses[engineName] = { status: res.status || 'COMPLETED', version: chk.version };
      return res;
    } catch (err) {
      if (isAbortError(err)) {
        this.store.finishEngineRun(runId, { status: 'CANCELLED', aborted: true, durationMs: Date.now() - started });
        jobCtx.engineStatuses[engineName] = { status: 'CANCELLED' };
        throw err;
      }
      this.store.finishEngineRun(runId, {
        status: 'FAILED',
        durationMs: Date.now() - started,
        error: sanitizeText(err.message, 500),
      });
      this.store.saveError(jobCtx.scanId, engineName, err.message);
      jobCtx.engineStatuses[engineName] = { status: 'FAILED', reason: sanitizeText(err.message, 120) };
      this.logger.error(`[${jobCtx.jobId}] engine ${engineName} gagal:`, err.message);
      return { status: 'FAILED', items: [], stats: {}, error: sanitizeText(err.message, 200) };
    }
  }

  _makeCtx(job) {
    const workDir = path.join(this.config.tmpDir, job.jobId);
    fs.mkdirSync(workDir, { recursive: true });
    return {
      jobId: job.jobId,
      scanId: job.scanId,
      mode: job.mode,
      target: job.target,
      scopeRoot: job.scopeRoot,
      options: job.options || {},
      config: this.config,
      store: this.store,
      validator: this.validator,
      guard: this.guard,
      logger: this.logger,
      signal: job.signal,
      workDir,
      counts: { subdomains: 0, hosts: 0, endpoints: 0, findings: 0 },
      recent: [],
      engineStatuses: {},
      // state antar tahap
      S: { targetIps: [], subdomains: [], resolved: [], live: [], endpoints: [] },
    };
  }

  // ---------- tahapan ----------
  async stageScope(c) {
    this._checkAbort(c);
    const r = await this.guard.checkHost(c.target, { scanId: c.scanId, stage: 'scope' });
    if (!r.allowed) {
      this.store.saveError(c.scanId, 'scope', `Target ditolak: ${r.reason}`);
      throw new ScopeDeniedError(r.reason);
    }
    c.S.targetIps = r.ips;
    // re-check awal segera setelah allowlist (mitigasi rebinding terdokumentasi di README)
    const re = await this.guard.recheckHost(c.target, { scanId: c.scanId, stage: 'scope-recheck' });
    if (!re.allowed) throw new ScopeDeniedError(re.reason);
    c.S.targetIps = re.ips;
  }

  async stageSubfinder(c) {
    this._checkAbort(c);
    const res = await this.runEngine(c, 'subfinder', { target: c.target });
    if (!res.items) return;
    const seen = new Set([c.target]);
    for (const it of res.items.slice(0, this.config.maxSubdomains * 2)) {
      const root = this.validator.hostInScope(it.host);
      if (!root) {
        this.store.saveDecision(c.scanId, {
          decision: 'DENY',
          host: it.host,
          reason: 'Hasil enumerasi di luar scope - dibuang',
          stage: 'subfinder',
        });
        continue;
      }
      if (seen.has(it.host)) continue;
      seen.add(it.host);
      this.store.saveSubdomain(c.scanId, it.host, it.source);
      c.S.subdomains.push(it.host);
      if (c.S.subdomains.length >= this.config.maxSubdomains) break;
    }
    c.counts.subdomains = this.store.countSubdomains(c.scanId);
  }

  async stageDnsx(c) {
    this._checkAbort(c);
    const hosts = [c.target, ...c.S.subdomains].slice(0, this.config.maxResolveTargets);
    const listFile = writeListFile(c.workDir, 'dnsx-input.txt', hosts);
    const res = await this.runEngine(c, 'dnsx', { listFile });
    if (!res.items) return;
    for (const it of res.items) {
      if (!this.validator.hostInScope(it.host) && it.host !== c.target) continue;
      const ips = [];
      for (const ip of [...it.a, ...it.aaaa]) {
        const chk = this.guard.checkIp(ip, { scanId: c.scanId, stage: 'dnsx', host: it.host });
        if (chk.allowed) ips.push(ip);
      }
      for (const ip of it.a) this.store.saveDnsRecord(c.scanId, it.host, 'A', ip);
      for (const ip of it.aaaa) this.store.saveDnsRecord(c.scanId, it.host, 'AAAA', ip);
      if (ips.length) c.S.resolved.push({ host: it.host, ips });
    }
  }

  async stageHttpx(c) {
    this._checkAbort(c);
    const hosts = (c.S.resolved.length ? c.S.resolved.map((r) => r.host) : [c.target]).slice(
      0,
      this.config.maxResolveTargets
    );
    const ipMap = new Map(c.S.resolved.map((r) => [r.host, r.ips[0]]));
    const listFile = writeListFile(c.workDir, 'httpx-input.txt', hosts);
    const res = await this.runEngine(c, 'httpx', { listFile, ipMap });
    if (!res.items) return;
    for (const it of res.items.slice(0, this.config.maxLiveHosts)) {
      const v = this.validator.validateUrl(it.url);
      if (!v.ok) {
        this.store.saveDecision(c.scanId, {
          decision: 'DENY',
          host: it.url.slice(0, 200),
          reason: `URL hasil httpx ditolak: ${v.reason}`,
          stage: 'httpx',
        });
        continue;
      }
      this.store.saveHost(c.scanId, {
        url: it.url,
        host: v.host,
        statusCode: it.statusCode,
        title: it.title,
        webserver: it.webserver,
        tech: it.tech,
        contentLength: it.contentLength,
      });
      c.S.live.push({ url: it.url, host: v.host, ip: ipMap.get(v.host) || c.S.targetIps[0] || null, meta: it });
    }
    c.counts.hosts = this.store.countHosts(c.scanId);
  }

  async stageKatana(c) {
    this._checkAbort(c);
    if (!c.S.live.length) {
      c.logger.warn(`[${c.jobId}] katana dilewati: tidak ada host hidup`);
      return;
    }
    const seeds = c.S.live.slice(0, Math.min(10, c.S.live.length)).map((l) => l.url);
    const listFile = writeListFile(c.workDir, 'katana-input.txt', seeds);
    const res = await this.runEngine(c, 'katana', { listFile, scope: c.scopeRoot || c.target });
    if (!res.items) return;
    const seen = new Set();
    for (const it of res.items) {
      if (c.S.endpoints.length >= this.config.maxEndpoints) break;
      if (seen.has(it.url)) continue;
      seen.add(it.url);
      const v = this.validator.validateUrl(it.url);
      if (!v.ok) {
        this.store.saveDecision(c.scanId, {
          decision: 'DENY',
          host: it.url.slice(0, 200),
          reason: `URL hasil crawl di luar scope - dibuang`,
          stage: 'katana',
        });
        continue;
      }
      this.store.saveEndpoint(c.scanId, it.url, it.method, it.source);
      c.S.endpoints.push(it);
    }
    c.counts.endpoints = this.store.countEndpoints(c.scanId);
  }

  async stageHeaderProbe(c) {
    this._checkAbort(c);
    if (!c.S.live.length) {
      // fallback bila engine dipilih eksplisit tanpa httpx (custom mode): pakai target langsung
      const g = await this.guard.checkHost(c.target, { scanId: c.scanId, stage: 'headerProbe' });
      if (!g.allowed) return;
      c.S.live.push({ url: `https://${c.target}`, host: c.target, ip: g.ips[0] || null, meta: {} });
    }
    const targets = [];
    for (const l of c.S.live.slice(0, this.config.maxLiveHosts)) {
      let ip = l.ip;
      if (!ip) {
        // eslint-disable-next-line no-await-in-loop
        const g = await this.guard.checkHost(l.host, { scanId: c.scanId, stage: 'headerProbe' });
        if (!g.allowed) continue;
        ip = g.ips[0] || null;
      }
      targets.push({ url: l.url, host: l.host, ip });
    }
    const res = await this.runEngine(c, 'headerProbe', { targets, usedArgsLog: { targets: targets.length } });
    if (res.items) await this._ingestFindings(c, 'headerProbe', res.items);
  }

  async stageNuclei(c) {
    this._checkAbort(c);
    // sumber URL: host hidup + endpoint hasil crawl (terbatas) agar vuln di path
    // spesifik (mis. /search?q=, /redirect?url=) ikut diperiksa
    const maxUrls = this.config.maxVulnScanUrls || 25;
    const liveUrls = c.S.live.map((l) => l.url);
    const endpointUrls = c.S.endpoints.map((e) => e.url);
    const merged = [];
    const seen = new Set();
    for (const u of [...liveUrls, ...endpointUrls]) {
      if (merged.length >= maxUrls) break;
      if (seen.has(u)) continue;
      seen.add(u);
      merged.push(u);
    }
    const urls = (merged.length ? merged : [`https://${c.target}`]).slice(0, maxUrls);
    const ipMap = new Map(c.S.live.map((l) => [l.host, l.ip]).filter(([h, ip]) => h && ip));
    const listFile = writeListFile(c.workDir, 'nuclei-input.txt', urls);
    const res = await this.runEngine(c, 'nuclei', {
      listFile,
      severity: c.options.severity || null,
      tags: c.options.nucleiTags || null,
      categories: c.options.vulnCategories || null,
      mode: c.options.deepVuln ? 'deep' : 'standard',
      ipMap,
      usedArgsLog: { urls: urls.length, severity: c.options.severity || null, tags: c.options.nucleiTags || null },
    });
    if (res.items) await this._ingestFindings(c, 'nuclei', res.items);
  }

  async stageXray(c) {
    this._checkAbort(c);
    const url = c.S.live.length ? c.S.live[0].url : `https://${c.target}`;
    const res = await this.runEngine(c, 'xray', {
      url,
      outputFile: path.join(c.workDir, 'xray-output.json'),
      htmlFile: path.join(c.workDir, 'xray-report.html'),
    });
    if (res.items) await this._ingestFindings(c, 'xray', res.items);
  }

  async stageDnsInfo(c) {
    this._checkAbort(c);
    const { fullDnsInfo } = require('../engines/internal/dnsKit');
    const runId = this.store.beginEngineRun(c.scanId, 'dnsinfo-internal', { status: 'RUNNING', version: `node-${process.version}` });
    const started = Date.now();
    try {
      const info = await fullDnsInfo(c.target);
      // simpan record DNS ke DB
      const rec = info.records || {};
      for (const ip of rec.A || []) {
        const chk = this.guard.checkIp(ip, { scanId: c.scanId, stage: 'dnsinfo', host: c.target });
        if (chk.allowed) c.S.targetIps.push(ip);
        this.store.saveDnsRecord(c.scanId, c.target, 'A', ip);
      }
      for (const ip of rec.AAAA || []) this.store.saveDnsRecord(c.scanId, c.target, 'AAAA', ip);
      for (const mx of rec.MX || []) this.store.saveDnsRecord(c.scanId, c.target, 'MX', `${mx.exchange} (${mx.priority})`);
      for (const ns of rec.NS || []) this.store.saveDnsRecord(c.scanId, c.target, 'NS', ns);
      for (const t of (rec.TXT || []).slice(0, 20)) this.store.saveDnsRecord(c.scanId, c.target, 'TXT', String(t).slice(0, 250));
      if ((rec.SOA || []).length) this.store.saveDnsRecord(c.scanId, c.target, 'SOA', String(rec.SOA[0].nsname || rec.SOA[0]).slice(0, 200));
      // temuan keamanan email
      const items = [];
      const es = info.emailSecurity || {};
      if (es.spfMissing && (rec.MX || []).length) {
        items.push({ engine: 'dnsinfo-internal', externalId: 'email:spf-missing', name: 'Record SPF tidak ada (domain punya MX)', severity: 'low', target: c.target, evidence: 'Tidak ada TXT v=spf1 meski MX terdaftar - rentan spoofing email', reference: '', tags: 'email:spf', owaspId: 'A02', classification: 'INDICATOR' });
      }
      if (es.dmarcMissing && (rec.MX || []).length) {
        items.push({ engine: 'dnsinfo-internal', externalId: 'email:dmarc-missing', name: 'Record DMARC tidak ada', severity: 'low', target: c.target, evidence: 'Tidak ada _dmarc TXT - kebijakan anti-spoofing lemah', reference: '', tags: 'email:dmarc', owaspId: 'A02', classification: 'INDICATOR' });
      }
      for (const it of items) {
        const hash = sha16(`${it.engine}|${it.externalId}|${it.target}|${String(it.evidence).slice(0, 200)}`);
        const ev = this._enrichEvidence(it.externalId, it.evidence);
        const ok = this.store.saveFinding(c.scanId, { ...it, evidence: ev, dedupeHash: hash });
        if (ok) this._pushRecent(c, { ...it, hash, evidence: ev });
      }
      c.S.dnsInfo = info;
      c.counts.dnsRecords = Object.values(rec).reduce((a, b) => a + (Array.isArray(b) ? b.length : 0), 0);
      this.store.finishEngineRun(runId, { status: 'COMPLETED', durationMs: Date.now() - started });
      c.engineStatuses['dnsinfo-internal'] = { status: 'COMPLETED' };
    } catch (err) {
      this.store.finishEngineRun(runId, { status: 'FAILED', durationMs: Date.now() - started, error: sanitizeText(err.message, 200) });
      c.engineStatuses['dnsinfo-internal'] = { status: 'FAILED', reason: sanitizeText(err.message, 120) };
    }
  }

  async stageSecrets(c) {
    this._checkAbort(c);
    let urls = c.S.live.map((l) => l.url);
    if (!urls.length) {
      // fallback: langsung target bila httpx tidak berjalan
      const g = await this.guard.checkHost(c.target, { scanId: c.scanId, stage: 'secrets' });
      if (!g.allowed) return;
      urls = [`https://${c.target}`];
      c.S.live.push({ url: urls[0], host: c.target, ip: g.ips[0] || null, meta: {} });
    }
    const ipMap = new Map(c.S.live.map((l) => [l.host, l.ip]).filter(([h, ip]) => h && ip));
    const res = await this.runEngine(c, 'secrets-internal', { urls: urls.slice(0, 10), ipMap });
    if (res.items) await this._ingestFindings(c, 'secrets-internal', res.items);
  }

  async stagePorts(c) {
    this._checkAbort(c);
    const ips = c.S.targetIps && c.S.targetIps.length ? c.S.targetIps : [];
    const res = await this.runEngine(c, 'ports-internal', { host: c.target, ips });
    if (res.items) await this._ingestFindings(c, 'ports-internal', res.items);
  }

  async stageFinalize(c, mode, opts) {
    this._checkAbort(c);
    const findingsByCat = {};
    for (const row of this.store.findingsByOwasp(c.scanId)) findingsByCat[row.cat] = Number(row.n);
    const coverage = computeCoverage({
      mode,
      options: { ...opts, exposedFilesCheck: this.config.exposedFilesCheck },
      engineStatuses: c.engineStatuses,
      findingsByCat,
    });
    this.store.saveCoverage(c.scanId, coverage);
    c.coverage = coverage;
    // generate laporan (json/txt/html) - kegagalan tidak meruntuhkan scan, dicatat sebagai error
    try {
      const scanRow = this.store.getScan(c.scanId);
      const paths = buildReportFiles(this.store, this.config, scanRow);
      c.reportPaths = paths;
    } catch (err) {
      this.store.saveError(c.scanId, 'report', `Gagal membuat laporan: ${sanitizeText(err.message, 200)}`);
      this.logger.error(`[${c.jobId}] gagal membuat laporan: ${err.message}`);
    }
    // laporan cerdas per-jenis kerentanan (dari temuan nyata) - kegagalan tidak fatal
    try {
      // eslint-disable-next-line global-require
      const { generateReportsForScan } = require('../vulnreports/generator');
      const scanRow = this.store.getScan(c.scanId);
      const gen = generateReportsForScan(this.store, scanRow);
      c.vulnReportStats = gen.stats;
      this.logger.info(
        `[${c.jobId}] laporan cerdas: ${gen.stats.reports} laporan dari ${gen.stats.findings} temuan (dedup ${gen.stats.deduped})`
      );
    } catch (err) {
      this.store.saveError(c.scanId, 'vulnreport', `Gagal membuat laporan cerdas: ${sanitizeText(err.message, 200)}`);
      this.logger.error(`[${c.jobId}] gagal membuat laporan cerdas: ${err.message}`);
    }
  }

  // ---------- eksekusi utama ----------
  async executeJob(job) {
    // job: { jobId, scanId, ownerId, ownerUsername, mode, target, scopeRoot, options, signal, onProgress }
    const stages = this.buildPipeline(job.mode, job.options);
    const stageState = new Map(stages.map((s) => [s.id, 'pending']));
    let findingsCount = 0;
    const ctx = this._makeCtx(job);
    const snapshot = () => ({
      mode: job.mode,
      target: job.target,
      stages: stages.map((s) => ({ id: s.id, label: s.label, status: stageState.get(s.id) })),
      counts: { subdomains: 0, hosts: 0, endpoints: 0, findings: findingsCount },
      // Temuan terbaru untuk ditampilkan live (dengan Vuln ID, severity, payload)
      recent: (ctx.recent || []).slice(-6).reverse(),
    });

    this.store.updateScan(job.scanId, { status: 'RUNNING', started_at: Date.now() });
    if (job.onProgress) job.onProgress(snapshot());

    let finalStatus = 'COMPLETED';
    let finalError = null;
    let hadEngineFailure = false;

    try {
      for (const stage of stages) {
        if (job.signal && job.signal.aborted) throw abortError('Scan dibatalkan');
        stageState.set(stage.id, 'running');
        this.store.updateScan(job.scanId, { stage_label: stage.label });
        if (job.onProgress) job.onProgress(snapshot());
        try {
          await stage.run(ctx);
          const engFail = Object.values(ctx.engineStatuses).some(
            (v) => v && (v.status === 'FAILED' || v.status === 'TIMEOUT')
          );
          if (engFail) hadEngineFailure = true;
          stageState.set(stage.id, 'done');
        } catch (err) {
          if (isAbortError(err)) throw err;
          if (err instanceof ScopeDeniedError) throw err;
          // kegagalan tahap non-fatal: tandai failed, lanjutkan tahap independen berikutnya
          stageState.set(stage.id, 'failed');
          hadEngineFailure = true;
          this.store.saveError(job.scanId, stage.id, sanitizeText(err.message, 300));
          this.logger.error(`[${job.jobId}] tahap ${stage.id} gagal: ${err.message}`);
        }
        findingsCount = this.store.countFindings(job.scanId);
        if (job.onProgress) job.onProgress(snapshot());
      }
      finalStatus = hadEngineFailure ? 'PARTIAL' : 'COMPLETED';
    } catch (err) {
      if (isAbortError(err)) {
        finalStatus = 'CANCELLED';
        finalError = 'Dibatalkan oleh pengguna';
        for (const [id] of stageState.entries()) {
          if (stageState.get(id) === 'running') stageState.set(id, 'cancelled');
        }
      } else if (err instanceof ScopeDeniedError) {
        finalStatus = 'FAILED';
        finalError = sanitizeText(err.message, 300);
      } else {
        finalStatus = 'FAILED';
        finalError = sanitizeText(err.message || 'kesalahan tidak diketahui', 300);
        this.logger.error(`[${job.jobId}] scan gagal:`, err);
      }
      if (job.onProgress) job.onProgress(snapshot());
    }

    // simpan progress terakhir ke kolom scan untuk /status
    const lastSnapshot = snapshot();
    this.store.updateScan(job.scanId, {
      status: finalStatus,
      finished_at: Date.now(),
      error: finalError,
      stage_label: stages.map((s) => `${s.id}:${stageState.get(s.id)}`).join(','),
      progress_message_id: null,
    });

    // bersihkan file kerja (bukan laporan)
    safeUnlinkDir(ctx.workDir);
    if (this.registry) this.registry.remove(job.jobId);
    if (job.onProgress) job.onProgress({ ...lastSnapshot, finished: finalStatus });
    return { status: finalStatus, error: finalError, coverage: ctx.coverage || [] };
  }
}

module.exports = { Orchestrator, ScopeDeniedError };
