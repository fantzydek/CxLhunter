'use strict';

/**
 * Test modul src/reports (rekonstruksi v1.2.0):
 * - buildReport menyusun data NYATA dari store (temuan, engine_runs, coverage, guard)
 * - buildReportFiles menulis 3 file + memperbarui kolom report_*_path pada scan
 * - TXT/HTML bebas <script>, HTML memuat matriks coverage, data di-escape
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
const { buildReport, buildReportFiles } = require('../src/reports/json');
const { renderTextReport } = require('../src/reports/text');
const { renderHtmlReport } = require('../src/reports/html');

const logger = createLogger({ logLevel: 'error' });

function makeEnv(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cxl-reports-'));
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
  });
  const db = openDatabase(config, logger);
  runMigrations(db, logger);
  const store = createStore(db, logger);
  t.after(() => {
    try {
      db.close();
    } catch (_) {
      /* diamkan */
    }
  });
  return { config, store, dir };
}

test('reports: buildReportFiles menulis 3 file, update scan row, konten jujur & ter-escape', (t) => {
  const { config, store } = makeEnv(t);
  const scanId = store.createScan({
    jobId: 'job-rep1',
    ownerId: 5,
    ownerUsername: 'pemilik',
    mode: 'full',
    target: 'target.example.com',
    scopeRoot: 'example.com',
    options: { severity: 'high' },
    labMode: false,
  });

  // temuan nyata (dua severity)
  store.saveFinding(scanId, {
    engine: 'nuclei',
    externalId: 'tpl-sqli',
    name: 'SQL Error Based <script>',
    severity: 'high',
    target: 'https://target.example.com/?id=1<script>',
    evidence: '{"matcher":true,"curl":"curl -s ..." }',
    reference: '',
    tags: 'sqli',
    classification: 'TEMPLATE_MATCH',
    owaspId: 'A05',
    dedupeHash: 'h1',
  });
  store.saveFinding(scanId, {
    engine: 'headerProbe',
    externalId: 'header:hsts',
    name: 'HSTS tidak diatur',
    severity: 'low',
    target: 'https://target.example.com/',
    evidence: '{"detail":"x"}',
    reference: '',
    tags: 'header',
    classification: 'INDICATOR',
    owaspId: 'A04',
    dedupeHash: 'h2',
  });

  // engine runs: satu COMPLETED, satu UNAVAILABLE
  const r1 = store.beginEngineRun(scanId, 'nuclei', { status: 'RUNNING', version: '3.2.9', args: null });
  store.finishEngineRun(r1, { status: 'COMPLETED', exitCode: 0, durationMs: 1234, timedOut: false });
  const r2 = store.beginEngineRun(scanId, 'xray', { status: 'UNAVAILABLE', version: null, args: { reason: 'NOT_INSTALLED' } });
  store.finishEngineRun(r2, { status: 'UNAVAILABLE', error: 'Engine tidak tersedia: NOT_INSTALLED' });

  // data enumerasi
  store.saveSubdomain(scanId, 'www.example.com', 'subfinder');
  store.saveHost(scanId, { url: 'https://target.example.com', host: 'target.example.com', statusCode: 200, title: 'T', webserver: 'nginx', tech: [], contentLength: 10 });
  store.saveEndpoint(scanId, 'https://target.example.com/login', 'GET', 'katana');
  store.saveDecision(scanId, { decision: 'DENY', host: '10.0.0.1', reason: 'alamat internal', stage: 'dnsx' });

  // coverage manual (shape sama dengan computeCoverage)
  store.saveCoverage(scanId, [
    { category: 'A01', status: 'MANUAL_REQUIRED', checks: [], findings: 0, notes: 'Kategori ini memang tidak dapat diperiksa otomatis.' },
    { category: 'A02', status: 'CHECKED_NO_FINDINGS', checks: ['exposed_files'], findings: 0, notes: 'tanpa indikator. CHECKED_NO_FINDINGS BUKAN jaminan aman.' },
    { category: 'A05', status: 'CHECKED_FINDINGS', checks: ['nuclei'], findings: 1, notes: '1 temuan terkait.' },
    { category: 'A07', status: 'ENGINE_UNAVAILABLE', checks: [], findings: 0, notes: 'Engine xray tidak tersedia.' },
  ]);

  const scanRow = store.getScan(scanId);
  const report = buildReport(store, config, scanRow);

  // meta & summary
  assert.strictEqual(report.meta.tool, 'CxL Scanner');
  assert.strictEqual(report.meta.owaspFramework, 'OWASP Top 10:2025');
  assert.ok(report.meta.disclaimer.includes('BUKAN berarti target aman'));
  assert.strictEqual(report.scan.jobId, 'job-rep1');
  assert.strictEqual(report.summary.findingsTotal, 2);
  assert.strictEqual(report.summary.bySeverity.high, 1);
  assert.strictEqual(report.summary.bySeverity.low, 1);
  assert.strictEqual(report.summary.subdomains, 1);
  assert.strictEqual(report.summary.hosts, 1);
  assert.strictEqual(report.summary.endpoints, 1);
  assert.strictEqual(report.summary.deniedRequests, 1);
  assert.strictEqual(report.summary.coverage.checked, 2);
  assert.strictEqual(report.summary.coverage.manualRequired, 1);
  assert.strictEqual(report.summary.coverage.notTested, 1);
  assert.strictEqual(report.tools.length, 2);
  const xrayTool = report.tools.find((x) => x.engine === 'xray');
  assert.strictEqual(xrayTool.status, 'UNAVAILABLE');
  // keterbatasan jujur
  assert.ok(report.limitations.some((l) => l.includes('A02') && l.includes('BUKAN jaminan aman')));
  assert.ok(report.limitations.some((l) => l.includes('A07') && l.includes('tidak teruji')));
  // rekomendasi dari kategori dengan temuan (A05 ada mitigasinya)
  assert.ok(report.recommendations.some((r) => r.startsWith('A05:')));
  // judul temuan dengan <script> TIDAK di-render mentah di HTML
  const { jsonPath, txtPath, htmlPath } = buildReportFiles(store, config, scanRow);
  assert.ok(fs.existsSync(jsonPath) && fs.existsSync(txtPath) && fs.existsSync(htmlPath));

  const scanAfter = store.getScan(scanId);
  assert.strictEqual(scanAfter.report_json_path, jsonPath, 'kolom report_json_path diperbarui');
  assert.strictEqual(scanAfter.report_txt_path, txtPath);
  assert.strictEqual(scanAfter.report_html_path, htmlPath);

  const parsed = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
  assert.strictEqual(parsed.scan.jobId, 'job-rep1');

  const txt = fs.readFileSync(txtPath, 'utf8');
  assert.ok(txt.includes('MATRIKS COVERAGE OWASP'));
  assert.ok(txt.includes('BUKAN jaminan aman'));
  assert.ok(txt.includes('DISCLAIMER'));

  const html = fs.readFileSync(htmlPath, 'utf8');
  assert.ok(html.includes('Coverage OWASP'), 'HTML memuat matriks coverage');
  assert.ok(!/<script[\s>]/i.test(html), 'HTML bebas tag <script>');
  assert.ok(!html.includes('<script>alert'), 'tidak ada injeksi');
  assert.ok(html.includes('SQL Error Based &lt;script&gt;'), 'judul temuan ter-escape');
  assert.ok(html.includes('?id=1&lt;script&gt;'), 'target ter-escape');
});

test('reports: renderer tahan terhadap objek minimal (selfTest dummy)', () => {
  const dummy = {
    meta: { tool: 'T', version: '1', generatedAt: 'now', owaspFramework: 'OWASP Top 10:2025', disclaimer: 'd' },
    scan: {
      jobId: 'j1',
      mode: 'quick',
      target: '<script>alert(1)</script>',
      scopeRoot: 'x',
      status: 'COMPLETED',
      labMode: false,
      startedAt: null,
      finishedAt: null,
      error: null,
      options: {},
    },
    summary: { findingsTotal: 0, bySeverity: {}, subdomains: 0, hosts: 0, endpoints: 0, deniedRequests: 0, coverage: {} },
    tools: [],
    owasp: [],
    findings: [],
    manualRequiredCategories: [],
    limitations: [],
    recommendations: [],
    nextSteps: [],
  };
  const html = renderHtmlReport(dummy);
  const txt = renderTextReport(dummy);
  assert.ok(!html.includes('<script>alert(1)</script>'), 'target berbahaya ter-escape di HTML');
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  assert.ok(txt.includes('TIDAK ADA TEMUAN OTOMATIS'));
  assert.ok(txt.includes('BUKAN pernyataan bahwa target aman'));
});
