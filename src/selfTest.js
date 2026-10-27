'use strict';

/**
 * Self-test (--self-test): memeriksa dependensi, database, parser, scope/guard,
 * konfigurasi, dan kompatibilitas dasar TANPA memindai target publik.
 * Semua pemeriksaan bersifat lokal (fixture inline, DB, klasifikasi IP, parser).
 * Hasil: PASS / FAIL / SKIP / WARN per bagian; exit 1 bila ada FAIL.
 */

const fs = require('fs');
const path = require('path');

async function runSelfTest({ config, logger, openStore }) {
  const results = [];
  const p = (name, status, detail) => {
    results.push({ name, status, detail: detail || '' });
    process.stdout.write(`[${status.padEnd(4)}] ${name}${detail ? ` - ${detail}` : ''}\n`);
  };

  process.stdout.write(`\n=== CXL SELF-TEST ===\nNode: ${process.version} | Platform: ${process.platform} ${process.arch}\n\n`);

  // 1. Node version
  const major = parseInt(process.version.slice(1), 10);
  if (major >= 20) {
    p('Node.js >= 20', 'PASS', major >= 22 ? 'node:sqlite tersedia' : 'gunakan Node >= 22.5 agar fallback node:sqlite aktif');
  } else {
    p('Node.js >= 20', 'FAIL', `terdeteksi ${process.version}`);
  }

  // 2. Platform info (informasi saja)
  p('Platform', 'INFO', `${process.platform}/${process.arch}${process.platform === 'android' ? ' (Termux)' : ' - kompatibilitas Termux/divais harus diverifikasi di perangkat'}`);

  // 3. Konfigurasi
  if (config.botToken) p('BOT_TOKEN', 'PASS', 'terisi (nilai tidak ditampilkan)');
  else p('BOT_TOKEN', 'SKIP', 'belum diisi - mode bot tidak dapat dijalankan; isi .env');

  if (config.allowedTargets.length) p('ALLOWED_TARGETS', 'PASS', config.allowedTargets.join(', '));
  else p('ALLOWED_TARGETS', 'INFO', 'kosong - MODE TERBUKA: scanner menerima domain publik apa pun (isi untuk mengunci ke domain Anda)');

  if (!config.adminIds.length) p('ADMIN_IDS', 'WARN', 'kosong - tidak ada admin');
  else p('ADMIN_IDS', 'PASS', `${config.adminIds.length} admin`);

  if (config.labMode) {
    p('LAB_MODE', 'WARN', `AKTIF - pastikan hanya host lab (${config.labTargets.join(', ') || 'belum ada'}) yang diizinkan`);
  } else {
    p('LAB_MODE', 'PASS', 'mati (default aman)');
  }

  // 4. Database
  try {
    const { db, store } = openStore(config, logger);
    p(`Database (${db.driver})`, 'PASS', config.dbPath);
    const probeKey = `selftest-${Date.now()}`;
    store.db.prepare('INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)').run(probeKey, 'ok');
    const back = store.db.prepare('SELECT value FROM meta WHERE key = ?').get(probeKey);
    if (back && back.value === 'ok') p('DB read/write', 'PASS');
    else p('DB read/write', 'FAIL', 'roundtrip gagal');
    store.db.prepare('DELETE FROM meta WHERE key = ?').run(probeKey);
    db.close();
  } catch (err) {
    p('Database', 'FAIL', err.message.split('\n')[0]);
  }

  // 5. Scope validator (kasus inline)
  try {
    const { ScopeValidator } = require('./scope/validator');
    const v = new ScopeValidator({ ...config, allowedTargets: ['example.com'], labMode: false });
    const t1 = v.validateTargetInput('sub.example.com');
    const t2 = v.validateTargetInput('example.org');
    const t3 = v.validateTargetInput('192.168.1.1');
    const u1 = v.validateUrl('https://sub.example.com/x');
    const u2 = v.validateUrl('ftp://sub.example.com');
    const u3 = v.validateUrl('https://user:pass@sub.example.com');
    const u4 = v.validateUrl('https://evil.com');
    if (t1.ok && !t2.ok && !t3.ok && u1.ok && !u2.ok && !u3.ok && !u4.ok) {
      p('Scope validator', 'PASS', 'subdomain ok, luar-scope/IP/ftp/userinfo/luar-scope URL ditolak');
    } else {
      p('Scope validator', 'FAIL', JSON.stringify({ t1: t1.ok, t2: t2.ok, t3: t3.ok, u1: u1.ok, u2: u2.ok, u3: u3.ok, u4: u4.ok }));
    }
  } catch (err) {
    p('Scope validator', 'FAIL', err.message);
  }

  // 6. Network guard klasifikasi IP
  try {
    const { isPrivateIp } = require('./scope/networkGuard');
    const cases = [
      ['10.0.0.1', true], ['172.16.5.4', true], ['172.32.0.1', false], ['192.168.1.1', true],
      ['127.0.0.1', true], ['169.254.1.1', true], ['100.64.0.1', true], ['8.8.8.8', false],
      ['224.0.0.1', true], ['240.0.0.1', true], ['::1', true], ['fe80::1', true],
      ['fd00::1', true], ['ff02::1', true], ['::ffff:10.0.0.1', true], ['::ffff:8.8.8.8', false],
      ['2001:db8::1', true], ['2606:4700::1111', false],
    ];
    const bad = cases.filter(([ip, wantPriv]) => isPrivateIp(ip) !== wantPriv);
    if (!bad.length) p('Network guard (klasifikasi IP)', 'PASS', `${cases.length} kasus`);
    else p('Network guard (klasifikasi IP)', 'FAIL', `salah: ${bad.map((b) => b[0]).join(', ')}`);
  } catch (err) {
    p('Network guard', 'FAIL', err.message);
  }

  // 7. Parser (fixture inline)
  try {
    const nuclei = require('./engines/nuclei');
    const good = nuclei.parseLine('{"template-id":"x","info":{"name":"X","severity":"high","tags":["sqli"]},"matcher-status":true,"matched-at":"https://t/a"}');
    const skip = nuclei.parseLine('{"template-id":"y","info":{"name":"Y","severity":"info"},"matcher-status":false}');
    const bad = nuclei.parseLine('{broken json');
    const httpx = require('./engines/httpx');
    const h = httpx.parseLine('{"url":"https://t/","status_code":200,"title":"Hi"}');
    if (good && good.finding && good.finding.owaspId === 'A05' && skip && skip.skipped && bad && bad.malformed && h && h.statusCode === 200) {
      p('Parser JSONL', 'PASS', 'nuclei (temuan/skip/malformed) + httpx');
    } else {
      p('Parser JSONL', 'FAIL', 'hasil parser tidak sesuai ekspektasi');
    }
  } catch (err) {
    p('Parser JSONL', 'FAIL', err.message);
  }

  // 8. OWASP mapping & coverage
  try {
    const { mapTagsToOwasp } = require('./owasp/mapping');
    const { computeCoverage } = require('./owasp/coverage');
    const m1 = mapTagsToOwasp(['sqli']);
    const rows = computeCoverage({
      mode: 'owasp',
      options: {},
      engineStatuses: { headerProbe: { status: 'COMPLETED' }, nuclei: { status: 'UNAVAILABLE' } },
      findingsByCat: {},
    });
    const a05 = rows.find((r) => r.category === 'A05');
    const a06 = rows.find((r) => r.category === 'A06');
    if (m1 === 'A05' && a05 && a05.status === 'ENGINE_UNAVAILABLE' && a06 && a06.status === 'MANUAL_REQUIRED') {
      p('OWASP mapping & coverage', 'PASS', 'A05<-sqli; nuclei unavailable -> ENGINE_UNAVAILABLE; A06 -> MANUAL_REQUIRED');
    } else {
      p('OWASP mapping & coverage', 'FAIL', `m1=${m1} a05=${a05 && a05.status} a06=${a06 && a06.status}`);
    }
  } catch (err) {
    p('OWASP mapping & coverage', 'FAIL', err.message);
  }

  // 9. Laporan (render dari data dummy minimal, memastikan tidak ada <script> lolos)
  try {
    const { renderHtmlReport } = require('./reports/html');
    const { renderTextReport } = require('./reports/text');
    const dummy = {
      meta: { tool: 'T', version: '1', generatedAt: 'now', owaspFramework: 'OWASP Top 10:2025', disclaimer: 'd' },
      scan: { jobId: 'j1', mode: 'quick', target: '<script>alert(1)</script>', scopeRoot: 'x', status: 'COMPLETED', labMode: false, startedAt: null, finishedAt: null, error: null, options: {} },
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
    const leaked = html.includes('<script>alert(1)</script>');
    if (!leaked && html.includes('&lt;script&gt;') && txt.includes('LAPORAN')) {
      p('Report renderer', 'PASS', 'XSS pada target ter-escape; TXT ter-render');
    } else {
      p('Report renderer', leaked ? 'FAIL' : 'PASS', leaked ? 'payload script lolos!' : 'ok');
    }
  } catch (err) {
    p('Report renderer', 'FAIL', err.message);
  }

  // 11. Laporan kerentanan cerdas (klasifikasi, sensor, ekspor, status)
  try {
    const { classifyFinding } = require('./vulnreports/classifier');
    const { redactText } = require('./vulnreports/redactor');
    const clsSqli = classifyFinding({ engine: 'nuclei', externalId: 'sql-injection-error-based', name: 'SQL Injection', severity: 'high', target: 'https://t/a', evidence: JSON.stringify({ matcher: true, cwe: 'CWE-89' }), tags: 'sqli', classification: 'TEMPLATE_MATCH' });
    const clsUnknown = classifyFinding({ engine: 'nuclei', externalId: 'zqx-unknown-xyz', name: 'Unknown XYZ', severity: 'info', target: 'https://t/b', evidence: '', tags: '', classification: 'TEMPLATE_MATCH' });
    const red = redactText('password=hunter2 token="abc123def"');
    const okRed = !red.text.includes('hunter2') && !red.text.includes('abc123def');
    if (clsSqli.type === 'sqli' && clsSqli.needsReview === false && clsUnknown.type === 'fallback' && clsUnknown.needsReview === true && okRed) {
      p('Laporan cerdas (klasifikasi/sensor)', 'PASS', 'SQLi->TPL-SQLI; tak dikenal->fallback+NEEDS_REVIEW; secret disensor');
    } else {
      p('Laporan cerdas (klasifikasi/sensor)', 'FAIL', `sqli=${clsSqli.type}/${clsSqli.needsReview} unknown=${clsUnknown.type} red=${okRed}`);
    }
  } catch (err) {
    p('Laporan cerdas (klasifikasi/sensor)', 'FAIL', err.message);
  }

  // 12. Status engine (jujur; bukan kegagalan self-test)
  try {
    const { createEngines } = require('./engines');
    const engines = createEngines(config, logger);
    const lines = [];
    for (const eng of engines.list) {
      // eslint-disable-next-line no-await-in-loop
      const chk = await eng.checkInstalled(true);
      lines.push(`${eng.name}=${chk.status}${chk.version ? ` (${chk.version})` : ''}`);
    }
    const anyUnavailable = lines.some((l) => l.includes('UNAVAILABLE') || l.includes('INCOMPATIBLE'));
    p('Engine CLI', anyUnavailable ? 'WARN' : 'PASS', lines.join(', ') + (anyUnavailable ? ' - jalankan install.sh --tools-only untuk instalasi' : ''));
  } catch (err) {
    p('Engine CLI', 'FAIL', err.message);
  }

  // 13. Vuln KB (kamus bug: Vuln ID, CWE, payload, contoh bug detail)
  try {
    const { kbFor, kbList, ENRICH } = require('./engines/internal/vulnKB');
    const xss = kbFor('xss:reflected:q', '');
    const env = kbFor('exposed:/.env', '');
    const sqli = kbFor('sqli:error-signature:id', 'You have an error in your SQL syntax (MySQL)');
    const enr = ENRICH('xss:reflected:q', '{}');
    const ok =
      kbList().length >= 30 &&
      xss && xss.vulnId === 'CXL-021' && xss.cwe === 'CWE-79' && Array.isArray(xss.payloads) && xss.payloads.length > 0 && !!xss.vulnerable &&
      env && env.severity === 'critical' &&
      sqli && sqli.vulnId === 'CXL-022' &&
      enr && enr.vuln_id && enr.payload_example && enr.bug_example;
    if (ok) {
      p('Vuln KB (kamus bug)', 'PASS', `${kbList().length} jenis bug; Vuln ID + CWE + payload + contoh bug detail`);
    } else {
      p('Vuln KB (kamus bug)', 'FAIL', `xss=${!!xss} env=${env && env.severity} sqli=${sqli && sqli.vulnId} enrich=${!!enr} total=${kbList().length}`);
    }
  } catch (err) {
    p('Vuln KB (kamus bug)', 'FAIL', err.message);
  }

  // 11. Direktori kerja
  try {
    for (const dir of [config.dataDirSafe || config.dbPath, config.reportsDir, config.logsDir, config.tmpDir]) {
      fs.mkdirSync(path.dirname(dir), { recursive: true });
    }
    fs.mkdirSync(config.reportsDir, { recursive: true });
    p('Direktori kerja', 'PASS', `${config.reportsDir}, ${config.logsDir}, ${config.tmpDir}`);
  } catch (err) {
    p('Direktori kerja', 'FAIL', err.message);
  }

  const fails = results.filter((r) => r.status === 'FAIL').length;
  const warns = results.filter((r) => r.status === 'WARN' || r.status === 'SKIP').length;
  process.stdout.write(`\n=== SELESAI: ${results.length - fails - warns} PASS, ${warns} WARN/SKIP/INFO, ${fails} FAIL ===\n`);
  if (fails > 0) process.stdout.write('Perbaiki item FAIL sebelum menjalankan bot.\n');
  return fails > 0 ? 1 : 0;
}

module.exports = { runSelfTest };
