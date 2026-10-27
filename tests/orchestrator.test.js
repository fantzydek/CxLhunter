'use strict';

/**
 * Test integrasi orchestrator + queue + worker menggunakan engine STUB (tanpa jaringan,
 * tanpa binary eksternal) dan database sementara. Memverifikasi:
 * - urutan pipeline per mode
 * - eksekusi sukses => COMPLETED + temuan tersimpan + coverage + laporan dibuat
 * - engine gagal => PARTIAL (bukan sukses kosong)
 * - engine unavailable => tercatat UNAVAILABLE
 * - abort => CANCELLED dan tidak ada tahap lanjutan
 * - scope denied => FAILED dengan alasan
 */

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { buildConfig } = require('../src/config');
const { createLogger } = require('../src/utils/logger');
const { openDatabase, createStore } = require('../src/database/db');
const { runMigrations } = require('../src/database/migrations');
const { Orchestrator } = require('../src/scanner/orchestrator');
const { ScanQueue } = require('../src/scanner/queue');
const { Worker } = require('../src/scanner/worker');
const { CancellationRegistry } = require('../src/scanner/cancellation');
const { ScopeValidator } = require('../src/scope/validator');

const logger = createLogger({ logLevel: 'error' });

function makeEnv(t, engineOverrides) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cxl-orch-'));
  t.after(() => {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (_) {
      /* diamkan */
    }
  });
  const config = buildConfig({
    CXL_ROOT: dir,
    DB_PATH: path.join(dir, 'test.db'),
    LOG_LEVEL: 'error',
    MAX_SUBDOMAINS: '20',
    MAX_LIVE_HOSTS: '10',
    MAX_ENDPOINTS: '10',
  });
  const db = openDatabase(config, logger);
  runMigrations(db, logger);
  const store = createStore(db, logger);
  const validator = new ScopeValidator({ ...config, allowedTargets: ['example.com'], labMode: false });
  const guardStub = {
    async checkHost(host) {
      if (host.startsWith('deny')) return { allowed: false, reason: 'alamat internal', ips: [] };
      return { allowed: true, reason: 'stub', ips: ['93.184.216.34'] };
    },
    async recheckHost(host) {
      return this.checkHost(host);
    },
    checkIp: (ip) => ({ allowed: !ip.startsWith('10.'), reason: 'stub', ip }),
    async filterHosts(hosts) {
      return hosts.map((h) => ({ host: h, ips: ['93.184.216.34'] }));
    },
  };
  const stubEngine = (name, impl) => ({
    name,
    checkInstalled: async () => ({ status: 'AVAILABLE', version: 'stub-1.0', reason: 'OK', error: null }),
    run: impl,
  });
  const okFindingEngine = (name, items) =>
    stubEngine(name, async () => ({
      status: 'COMPLETED',
      items,
      stats: {},
      exitCode: 0,
      timedOut: false,
      stderrHead: '',
      error: null,
      droppedFlags: [],
      usedArgs: ['stub'],
    }));
  const emptyEngine = (name) =>
    stubEngine(name, async () => ({ status: 'COMPLETED', items: [], stats: {}, exitCode: 0, timedOut: false, stderrHead: '', error: null, droppedFlags: [], usedArgs: ['stub'] }));
  // httpx stub yang menghasilkan satu host hidup (agar tahap lanjutan berjalan)
  const httpxLiveEngine = () =>
    stubEngine('httpx', async () => ({
      status: 'COMPLETED',
      items: [
        {
          url: 'https://target.example.com',
          host: 'target.example.com',
          statusCode: 200,
          title: 'T',
          webserver: 'nginx',
          tech: [],
          ips: ['93.184.216.34'],
          location: '',
          time: '5ms',
          contentLength: 10,
        },
      ],
      stats: {},
      exitCode: 0,
      timedOut: false,
      stderrHead: '',
      error: null,
      droppedFlags: [],
      usedArgs: ['stub'],
    }));

  const engines = {
    list: [],
    map: {},
    get(n) {
      return this.map[n] || null;
    },
  };
  const registry = new CancellationRegistry();
  const orchestrator = new Orchestrator({ config, store, guard: guardStub, validator, engines, logger, registry });
  const queue = new ScanQueue({ config, store, logger, orchestrator, registry });
  const worker = new Worker({ config, logger, queue, orchestrator });

  t.after(() => {
    try {
      db.close();
    } catch (_) {
      /* diamkan */
    }
  });

  function setEngines(obj) {
    engines.list = Object.values(obj);
    engines.map = obj;
    return obj;
  }

  return { config, db, store, validator, orchestrator, queue, worker, registry, okFindingEngine, emptyEngine, httpxLiveEngine, stubEngine, setEngines };
}

function runJob(queue, worker, { mode, target, options, registry, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const jobId = `job-${Math.random().toString(36).slice(2, 10)}`;
    const job = {
      jobId,
      ownerId: 7,
      ownerUsername: 'tester',
      mode,
      target,
      scopeRoot: 'example.com',
      options: options || {},
      onProgress: () => {},
    };
    queue.enqueue(job);
    worker.kick();
    const wait = setInterval(() => {
      if (queue.queuedCount === 0 && queue.runningCount === 0) {
        clearInterval(wait);
        clearTimeout(killer);
        resolve(jobId);
      }
    }, 20);
    const killer = setTimeout(() => {
      clearInterval(wait);
      reject(new Error('runJob timeout: queue tidak kunjung kosong'));
    }, timeoutMs || 30000);
    void registry;
  });
}

test('orchestrator: pipeline mode sesuai desain', (t) => {
  const env = makeEnv(t, {});
  env.setEngines({});
  const quick = env.orchestrator.buildPipeline('quick', {}).map((s) => s.id);
  assert.deepStrictEqual(quick, ['scope', 'subfinder', 'dnsx', 'httpx', 'headerProbe', 'finalize']);
  const full = env.orchestrator.buildPipeline('full', {}).map((s) => s.id);
  assert.deepStrictEqual(full, ['scope', 'subfinder', 'dnsx', 'httpx', 'katana', 'headerProbe', 'nuclei', 'finalize']);
  const owasp = env.orchestrator.buildPipeline('owasp', {}).map((s) => s.id);
  assert.ok(!owasp.includes('subfinder') && owasp.includes('nuclei') && owasp.includes('headerProbe'));
  const custom = env.orchestrator.buildPipeline('custom', { engines: ['nuclei', 'headerProbe'] }).map((s) => s.id);
  // custom hanya menyertakan engine yang dipilih (headerProbe punya fallback ke target langsung)
  assert.deepStrictEqual(custom, ['scope', 'headerProbe', 'nuclei', 'finalize']);
  const customWithHttpx = env.orchestrator.buildPipeline('custom', { engines: ['httpx', 'nuclei'] }).map((s) => s.id);
  assert.deepStrictEqual(customWithHttpx, ['scope', 'httpx', 'nuclei', 'finalize']);
});

test('orchestrator: pipeline mode baru (subdomain/xss/sqli/sans/malware)', (t) => {
  const env = makeEnv(t, {});
  env.setEngines({});
  const subdomain = env.orchestrator.buildPipeline('subdomain', {}).map((s) => s.id);
  assert.deepStrictEqual(subdomain, ['scope', 'subfinder', 'dnsx', 'httpx', 'finalize']);
  const xss = env.orchestrator.buildPipeline('xss', {});
  assert.ok(xss.map((s) => s.id).includes('nuclei'), 'xss menjalankan vuln scan');
  assert.ok(xss.map((s) => s.id).includes('katana'), 'xss melakukan crawling endpoint');
  const xssOpts = {};
  env.orchestrator.buildPipeline('xss', xssOpts);
  assert.deepStrictEqual(xssOpts.nucleiTags, ['xss', 'reflected-xss', 'dalxss']);
  assert.deepStrictEqual(xssOpts.vulnCategories.includes('xss'), true);
  const sqliOpts = {};
  env.orchestrator.buildPipeline('sqli', sqliOpts);
  assert.deepStrictEqual(sqliOpts.vulnCategories, ['sqli']);
  const sansOpts = {};
  env.orchestrator.buildPipeline('sans', sansOpts);
  assert.ok(sansOpts.vulnCategories.includes('xss') && sansOpts.vulnCategories.includes('sqli'));
  const malwareOpts = {};
  env.orchestrator.buildPipeline('malware', malwareOpts);
  assert.deepStrictEqual(malwareOpts.vulnCategories, ['malware', 'info']);
});

test('orchestrator: full run stub => COMPLETED, temuan & laporan tersedia', async (t) => {
  const env = makeEnv(t);
  env.setEngines({
    subfinder: env.emptyEngine('subfinder'),
    dnsx: env.emptyEngine('dnsx'),
    httpx: env.httpxLiveEngine(),
    katana: env.emptyEngine('katana'),
    headerProbe: env.okFindingEngine('headerProbe', [
      {
        engine: 'headerProbe',
        externalId: 'header:strict-transport-security',
        name: 'HSTS tidak diatur',
        severity: 'low',
        target: 'https://target.example.com/',
        evidence: '{"detail":"x"}',
        reference: '',
        tags: 'header:strict-transport-security',
        owaspId: 'A04',
        classification: 'INDICATOR',
      },
    ]),
    nuclei: env.okFindingEngine('nuclei', [
      {
        engine: 'nuclei',
        externalId: 'tpl-a',
        name: 'Tpl A',
        severity: 'high',
        target: 'https://target.example.com/',
        evidence: '{"matcher":true}',
        reference: '',
        tags: 'sqli',
        owaspId: 'A05',
        classification: 'TEMPLATE_MATCH',
      },
    ]),
  });
  const jobId = await runJob(env.queue, env.worker, { mode: 'full', target: 'target.example.com' });
  const scan = env.store.getScanByJobId(jobId);
  assert.strictEqual(scan.status, 'COMPLETED', `status: ${scan.status}, error: ${scan.error}`);
  assert.strictEqual(env.store.countFindings(scan.id), 2);
  const cov = env.store.getCoverage(scan.id);
  assert.strictEqual(cov.length, 10, '10 kategori OWASP terekam');
  const a05 = cov.find((c) => c.category === 'A05');
  assert.strictEqual(a05.status, 'CHECKED_FINDINGS');
  // laporan dibuat
  assert.ok(scan.report_txt_path && fs.existsSync(scan.report_txt_path), 'TXT laporan ada');
  assert.ok(scan.report_html_path && fs.existsSync(scan.report_html_path), 'HTML laporan ada');
  const html = fs.readFileSync(scan.report_html_path, 'utf8');
  assert.ok(html.includes('Matriks Coverage OWASP') || html.includes('Coverage OWASP'));
  assert.ok(!/<script[\s>]/i.test(html), 'HTML laporan bebas script');
});

test('orchestrator: engine gagal => PARTIAL (bukan sukses kosong)', async (t) => {
  const env = makeEnv(t);
  env.setEngines({
    httpx: env.httpxLiveEngine(),
    headerProbe: env.stubEngine('headerProbe', async () => {
      throw new Error('boom simulasi kegagalan engine');
    }),
    nuclei: env.okFindingEngine('nuclei', []),
  });
  const jobId = await runJob(env.queue, env.worker, { mode: 'owasp', target: 'target.example.com' });
  const scan = env.store.getScanByJobId(jobId);
  assert.strictEqual(scan.status, 'PARTIAL', `status: ${scan.status}`);
  const runs = env.store.listEngineRuns(scan.id);
  const hp = runs.find((r) => r.engine === 'headerProbe');
  assert.strictEqual(hp.status, 'FAILED');
  assert.ok(/boom/.test(hp.error));
});

test('orchestrator: engine tidak terpasang => UNAVAILABLE tercatat', async (t) => {
  const env = makeEnv(t);
  env.setEngines({
    httpx: env.httpxLiveEngine(),
    headerProbe: {
      name: 'headerProbe',
      checkInstalled: async () => ({ status: 'UNAVAILABLE', reason: 'NOT_INSTALLED', error: 'tidak ada', version: null }),
      run: async () => {
        throw new Error('harusnya tidak dipanggil');
      },
    },
    nuclei: env.okFindingEngine('nuclei', []),
  });
  const jobId = await runJob(env.queue, env.worker, { mode: 'owasp', target: 'target.example.com' });
  const scan = env.store.getScanByJobId(jobId);
  const runs = env.store.listEngineRuns(scan.id);
  const hp = runs.find((r) => r.engine === 'headerProbe');
  assert.strictEqual(hp.status, 'UNAVAILABLE');
  const cov = env.store.getCoverage(scan.id);
  const a02 = cov.find((c) => c.category === 'A02');
  assert.strictEqual(a02.status, 'PARTIAL', 'A02: headerProbe unavailable + nuclei ok => PARTIAL');
  const a04 = cov.find((c) => c.category === 'A04');
  assert.strictEqual(a04.status, 'PARTIAL');
});

test('orchestrator: scope ditolak => FAILED dengan alasan jelas', async (t) => {
  const env = makeEnv(t);
  env.setEngines({});
  const jobId = await runJob(env.queue, env.worker, { mode: 'quick', target: 'deny-target.example.com' });
  const scan = env.store.getScanByJobId(jobId);
  assert.strictEqual(scan.status, 'FAILED');
  assert.ok(/ditolak/.test(scan.error || ''), `error: ${scan.error}`);
});

test('orchestrator: abort => CANCELLED', async (t) => {
  const env = makeEnv(t);
  let abortSignal = null;
  env.setEngines({
    httpx: env.httpxLiveEngine(),
    headerProbe: env.stubEngine('headerProbe', async (jobCtx) => {
      abortSignal = jobCtx.signal;
      // menunggu sampai di-abort
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => resolve({ status: 'COMPLETED', items: [] }), 15000);
        jobCtx.signal.addEventListener(
          'abort',
          () => {
            clearTimeout(timer);
            const e = new Error('Dibatalkan');
            e.name = 'AbortError';
            reject(e);
          },
          { once: true }
        );
      });
    }),
    nuclei: env.okFindingEngine('nuclei', []),
  });
  const jobId = `job-${Math.random().toString(36).slice(2, 10)}`;
  const job = {
    jobId,
    ownerId: 7,
    mode: 'owasp',
    target: 'target.example.com',
    scopeRoot: 'example.com',
    options: {},
    onProgress: () => {},
  };
  env.queue.enqueue(job);
  env.worker.kick();
  // tunggu sampai signal ada (engine headerProbe berjalan), lalu abort
  await new Promise((r) => {
    const w = setInterval(() => {
      if (abortSignal) {
        clearInterval(w);
        r();
      }
    }, 10);
  });
  env.registry.abort(jobId, 'tes');
  await new Promise((r, j) => {
    const w = setInterval(() => {
      if (env.queue.queuedCount === 0 && env.queue.runningCount === 0) {
        clearInterval(w);
        clearTimeout(kt);
        r();
      }
    }, 20);
    const kt = setTimeout(() => {
      clearInterval(w);
      j(new Error('abort test timeout'));
    }, 30000);
  });
  const scan = env.store.getScanByJobId(jobId);
  assert.strictEqual(scan.status, 'CANCELLED', `status: ${scan.status}`);
});

test('queue: batas antrean dan per pengguna', (t) => {
  const env = makeEnv(t);
  env.setEngines({});
  env.config.queueMax = 2;
  env.config.maxScansPerUser = 1;
  const j1 = { jobId: 'q1', ownerId: 1, mode: 'quick', target: 'a.example.com', scopeRoot: 'example.com', options: {} };
  env.queue.enqueue(j1);
  assert.ok(!env.queue.canEnqueue(1).ok, 'user 1 sudah punya 1 job');
  assert.ok(env.queue.canEnqueue(2).ok, 'user 2 masih bisa');
  env.queue.enqueue({ jobId: 'q2', ownerId: 2, mode: 'quick', target: 'b.example.com', scopeRoot: 'example.com', options: {} });
  assert.ok(!env.queue.canEnqueue(3).ok, 'antrean penuh (2)');
  // cancel milik orang lain ditolak
  const res = env.queue.cancel('q2', 1, false);
  assert.ok(!res.ok);
  const res2 = env.queue.cancel('q2', 2, false);
  assert.ok(res2.ok);
  assert.strictEqual(env.queue.queuedCount, 1);
});

test('worker: job dalam antrean dibatalkan => status CANCELLED tanpa eksekusi', async (t) => {
  const env = makeEnv(t);
  env.setEngines({
    httpx: env.emptyEngine('httpx'),
    headerProbe: env.emptyEngine('headerProbe'),
    nuclei: env.emptyEngine('nuclei'),
  });
  const job = {
    jobId: 'q-cancel',
    ownerId: 9,
    mode: 'owasp',
    target: 'target.example.com',
    scopeRoot: 'example.com',
    options: {},
  };
  env.queue.enqueue(job);
  const res = env.queue.cancel('q-cancel', 9, false);
  assert.ok(res.ok);
  const scan = env.store.getScanByJobId('q-cancel');
  assert.strictEqual(scan.status, 'CANCELLED');
});
