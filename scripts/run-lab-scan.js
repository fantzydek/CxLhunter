'use strict';

/**
 * E2E lab scan: start server lab rentan, jalankan orchestrator mode full,
 * tampilkan temuan LIVE (dengan Vuln ID + severity + payload) dari onProgress,
 * lalu ringkasan akhir. Jalankan: node scripts/run-lab-scan.js [mode]
 */

process.env.LAB_MODE = 'true';
process.env.LAB_ALLOWED_TARGETS = '127.0.0.1';
process.env.ALLOWED_PORTS = '7777,443,80,8443';
process.env.DB_PATH = 'data/lab-e2e.db';
process.env.LOG_LEVEL = 'warn';

const path = require('path');
const ROOT = path.join(__dirname, '..');
const { loadConfig } = require(path.join(ROOT, 'src/config'));
const { openDatabase, createStore } = require(path.join(ROOT, 'src/database/db'));
const { runMigrations } = require(path.join(ROOT, 'src/database/migrations'));
const { createLogger } = require(path.join(ROOT, 'src/utils/logger'));
const { createEngines } = require(path.join(ROOT, 'src/engines'));
const { Orchestrator } = require(path.join(ROOT, 'src/scanner/orchestrator'));
const { NetworkGuard } = require(path.join(ROOT, 'src/scope/networkGuard'));
const { ScopeValidator } = require(path.join(ROOT, 'src/scope/validator'));

const MODE = process.argv[2] || 'full';
const TARGET = '127.0.0.1'; // orchestrator menerima HOST; port diikuti lewat ALLOWED_PORTS
const BASE_URL = 'http://127.0.0.1:7777';

async function main() {
  const config = loadConfig();
  const logger = createLogger(config);
  const db = openDatabase(config, logger);
  runMigrations(db, logger);
  const store = createStore(db, logger);
  const validator = new ScopeValidator(config);
  const guard = new NetworkGuard({ config, store, logger });
  const engines = createEngines(config, logger);
  const orchestrator = new Orchestrator({ config, store, guard, validator, engines, logger });

  // lab server: listen manual (modul hanya listen bila dijalankan langsung)
  const { server, PORT } = require(path.join(ROOT, 'lab/lab-server.js'));
  if (!server.listening) {
    server.listen(PORT, '127.0.0.1');
  }
  await new Promise((r) => setTimeout(r, 500));

  const jobId = `lab-${Date.now()}`;
  const scanId = store.createScan({
    jobId,
    ownerId: 1,
    ownerUsername: 'lab',
    mode: MODE,
    target: TARGET,
    scopeRoot: TARGET,
    options: {},
  });

  let seenRecent = 0;
  const job = {
    jobId,
    scanId,
    ownerId: 1,
    mode: MODE,
    target: TARGET,
    scopeRoot: '127.0.0.1',
    options: {},
    signal: null,
    onProgress: (snap) => {
      if (Array.isArray(snap.recent) && snap.recent.length > seenRecent) {
        for (const f of snap.recent.slice(0, Math.max(0, snap.recent.length - seenRecent))) {
          console.log(`  [LIVE] ${f.severity.toUpperCase().padEnd(8)} [${f.vulnId || '-'}${f.cwe ? ' ' + f.cwe : ''}] ${f.name}`);
          console.log(`         target: ${f.target}`);
          if (f.payload) console.log(`         payload: ${f.payload}`);
        }
        seenRecent = snap.recent.length;
      }
    },
  };

  console.log(`\n=== E2E LAB SCAN mode=${MODE} target=${BASE_URL} ===\n`);
  const res = await orchestrator.executeJob(job);
  console.log(`\n=== SELESAI: status=${res.status} ===`);

  const rows = store.topFindings(scanId, 50);
  console.log(`\nTop findings (${rows.length}):`);
  for (const f of rows.slice(0, 25)) {
    let vuln = '';
    try {
      const ev = JSON.parse(f.evidence || '{}');
      vuln = `${ev.vuln_id || '-'} ${ev.cwe || ''} ${ev.payload_example && ev.payload_example[0] ? 'payload=' + ev.payload_example[0].slice(0, 40) : ''}`;
    } catch (_) {
      vuln = '(evidence polos)';
    }
    console.log(`  [${f.severity.toUpperCase().padEnd(8)}] ${f.name.padEnd(46)} | ${vuln}`);
  }
  const kbCovered = rows.filter((f) => {
    try {
      const ev = JSON.parse(f.evidence || '{}');
      return !!ev.vuln_id;
    } catch (_) {
      return false;
    }
  }).length;
  console.log(`\nTemuan ter-enrich KB: ${kbCovered}/${rows.length}`);
  console.log(`LIVE progress menampilkan ${seenRecent} temuan terbaru.\n`);

  server.close();
  db.close();
  process.exit(res.status === 'COMPLETED' || res.status === 'PARTIAL' ? 0 : 1);
}

main().catch((err) => {
  console.error('E2E GAGAL:', err);
  process.exit(1);
});
