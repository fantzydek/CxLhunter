'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { buildConfig } = require('../src/config');
const { createLogger } = require('../src/utils/logger');
const { openDatabase, createStore } = require('../src/database/db');
const { runMigrations } = require('../src/database/migrations');

function makeTmpCfg(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cxl-dbtest-'));
  t.after(() => {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (_) {
      /* diamkan */
    }
  });
  return buildConfig({
    CXL_ROOT: dir,
    DB_PATH: path.join(dir, 'test.db'),
    DB_DRIVER: 'auto',
    LOG_LEVEL: 'error',
  });
}

const logger = createLogger({ logLevel: 'error' });

test('database: migrasi idempotent dan roundtrip dasar', (t) => {
  const config = makeTmpCfg(t);
  const db = openDatabase(config, logger);
  assert.ok(['better-sqlite3', 'node:sqlite'].includes(db.driver), `driver: ${db.driver}`);
  const applied1 = runMigrations(db, logger);
  const applied2 = runMigrations(db, logger);
  assert.ok(applied1.length >= 1);
  assert.strictEqual(applied2.length, 0, 'migrasi kedua tidak menjalankan apa pun');

  const store = createStore(db, logger);
  const scanId = store.createScan({
    jobId: 'job-test-1',
    ownerId: 42,
    ownerUsername: 'tester',
    mode: 'quick',
    target: 'target.example.com',
    scopeRoot: 'example.com',
    options: { severity: ['low'] },
    labMode: false,
  });
  assert.ok(Number.isFinite(scanId));
  const scan = store.getScan(scanId);
  assert.strictEqual(scan.status, 'QUEUED');

  store.updateScan(scanId, { status: 'RUNNING', started_at: Date.now(), stage_label: 'dnsx' });
  assert.strictEqual(store.getScan(scanId).status, 'RUNNING');

  // temuan + dedup
  const f = {
    engine: 'nuclei',
    externalId: 'tpl-1',
    name: 'Test',
    severity: 'high',
    target: 'https://x/',
    evidence: 'e',
    reference: '',
    tags: 'a,b',
    classification: 'TEMPLATE_MATCH',
    owaspId: 'A02',
    dedupeHash: 'hash-1',
  };
  assert.ok(store.saveFinding(scanId, f));
  assert.ok(!store.saveFinding(scanId, f), 'duplikat (scan_id, dedupe_hash) diabaikan');
  assert.strictEqual(store.countFindings(scanId), 1);

  // engine run
  const runId = store.beginEngineRun(scanId, 'nuclei', { status: 'RUNNING', version: 'v3', args: { a: 1 } });
  store.finishEngineRun(runId, { status: 'COMPLETED', exitCode: 0, durationMs: 1234, stdoutBytes: 10 });
  const runs = store.listEngineRuns(scanId);
  assert.strictEqual(runs.length, 1);
  assert.strictEqual(runs[0].status, 'COMPLETED');
  assert.strictEqual(runs[0].duration_ms, 1234);

  // subdomain, dns, hosts, endpoints
  assert.ok(store.saveSubdomain(scanId, 'a.target.example.com', 'crtsh'));
  assert.ok(!store.saveSubdomain(scanId, 'a.target.example.com', 'crtsh'), 'subdomain duplikat diabaikan');
  store.saveDnsRecord(scanId, 'a.target.example.com', 'A', '1.2.3.4');
  store.saveHost(scanId, { url: 'https://a.target.example.com', host: 'a.target.example.com', statusCode: 200, title: 'T', webserver: 'nginx', tech: ['Nginx'] });
  store.saveEndpoint(scanId, 'https://a.target.example.com/login', 'GET', 'crawl');
  assert.strictEqual(store.countSubdomains(scanId), 1);
  assert.strictEqual(store.countHosts(scanId), 1);
  assert.strictEqual(store.countEndpoints(scanId), 1);

  // coverage
  store.saveCoverage(scanId, [
    { category: 'A02', status: 'CHECKED_FINDINGS', checks: ['header_security'], findings: 1, notes: 'n' },
    { category: 'A06', status: 'MANUAL_REQUIRED', checks: [], findings: 0, notes: 'manual' },
  ]);
  store.saveCoverage(scanId, [
    { category: 'A02', status: 'CHECKED_NO_FINDINGS', checks: ['header_security'], findings: 0, notes: 'n2' },
  ]);
  const cov = store.getCoverage(scanId);
  assert.strictEqual(cov.length, 2, 'upsert coverage: tetap 2 baris');
  assert.strictEqual(cov.find((c) => c.category === 'A02').status, 'CHECKED_NO_FINDINGS');

  // keputusan guard
  store.saveDecision(scanId, { decision: 'DENY', host: 'out.example.org', reason: 'luar scope', stage: 'scope' });
  assert.strictEqual(store.countDeniedDecisions(scanId), 1);

  // riwayat & statistik
  assert.ok(store.listScans({ ownerId: 42, limit: 5 }).length === 1);
  store.updateScan(scanId, { status: 'COMPLETED', finished_at: Date.now() });
  assert.ok(store.lastFinishedScan(42));
  const stats = store.globalStats();
  assert.ok(stats.scansByStatus.COMPLETED >= 1);
  db.close();
});

test('database: recovery restart menandai RUNNING/QUEUED lama sebagai FAILED', (t) => {
  const config = makeTmpCfg(t);
  const db = openDatabase(config, logger);
  runMigrations(db, logger);
  const store = createStore(db, logger);
  const id1 = store.createScan({ jobId: 'j-a', ownerId: 1, mode: 'quick', target: 'a.example.com', scopeRoot: 'a.example.com', options: {} });
  const id2 = store.createScan({ jobId: 'j-b', ownerId: 1, mode: 'quick', target: 'b.example.com', scopeRoot: 'b.example.com', options: {} });
  store.updateScan(id1, { status: 'RUNNING' });
  const n = store.markStaleRunningAsFailed('recovery');
  assert.strictEqual(n, 2, 'id1 RUNNING + id2 QUEUED');
  assert.strictEqual(store.getScan(id1).status, 'FAILED');
  assert.strictEqual(store.getScan(id2).status, 'FAILED');
  assert.strictEqual(store.markStaleRunningAsFailed('recovery'), 0);
  db.close();
});

test('database: DB_DRIVER=better-sqlite3 dipaksa tapi tidak ada => error jelas', (t) => {
  const config = makeTmpCfg(t);
  config.dbDriver = 'better-sqlite3';
  // Pada sandbox dengan better-sqlite3 terpasang ini akan sukses; uji hanya pola error bila modul tidak ada
  try {
    const db = openDatabase(config, logger);
    db.close(); // modul ada - tidak masalah
    assert.ok(true);
  } catch (err) {
    assert.ok(/DB_DRIVER=better-sqlite3 dipaksa|driver SQLite/.test(err.message));
  }
});
