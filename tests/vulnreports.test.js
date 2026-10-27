'use strict';

/**
 * Unit test Intelligent Vulnerability Report Generator.
 * Mencakup kriteria keberhasilan spesifikasi:
 * - SQLi -> template SQLi; XSS -> template XSS; access control -> template access control
 * - Mapping OWASP/CWE tidak dibuat tanpa dasar
 * - Data sensitif disensor
 * - Bukti kosong tidak menghasilkan laporan seolah terkonfirmasi
 * - Temuan tak dikenali -> fallback
 * - Ekspor TXT/Markdown/JSON/HTML
 * - Deduplikasi, metodologi severity, siklus status manual, idempotensi regenerasi
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
const { sha16 } = require('../src/utils/validation');
const { classifyFinding } = require('../src/vulnreports/classifier');
const { normalizeCwe, resolveMappingMetadata } = require('../src/vulnreports/mappings');
const { redactText, redactEvidence, hasConcreteEvidence } = require('../src/vulnreports/redactor');
const { generateReportsForScan, summarizeForTelegram, normalizeFinding, dedupeKeyFor, assessSeverity } = require('../src/vulnreports/generator');
const { createVulnReportStore, VALIDATION_STATUSES, MANUAL_STATUSES } = require('../src/vulnreports/store');
const { renderVReportText, renderVReportMarkdown, renderVReportJson, renderVReportHtml, writeVReportFile, writeVReportBundle } = require('../src/vulnreports/exporters');

const logger = createLogger({ logLevel: 'error' });

const SQLI_FINDING = {
  engine: 'nuclei',
  externalId: 'sql-injection-error-based',
  name: 'SQL Injection (error based)',
  severity: 'high',
  target: 'https://target.example.com/search?q=1',
  evidence: JSON.stringify({
    matcher: true,
    curl: 'curl -i "https://target.example.com/search?q=1%27" -H "Authorization: Bearer sk-test-abc123"',
    cwe: 'CWE-89',
  }),
  tags: 'sqli',
  classification: 'TEMPLATE_MATCH',
  owaspId: 'A05',
};

let findingSeq = 0;
function insertFinding(store, scanId, f) {
  const hash = sha16(`${f.engine}|${f.externalId}|${f.target}|${String(f.evidence).slice(0, 200)}|${++findingSeq}`);
  const ok = store.saveFinding(scanId, {
    engine: f.engine,
    externalId: f.externalId,
    name: f.name,
    severity: f.severity,
    target: f.target,
    evidence: f.evidence,
    reference: f.reference || '',
    tags: f.tags || '',
    classification: f.classification || 'INDICATOR',
    owaspId: f.owaspId || null,
    dedupeHash: hash,
  });
  assert.ok(ok, 'temuan tersimpan');
}

function makeScan(store, jobId, target) {
  const scanId = store.createScan({
    jobId,
    ownerId: 42,
    ownerUsername: 'tester',
    mode: 'full',
    target,
    scopeRoot: 'example.com',
    options: {},
    labMode: false,
  });
  store.updateScan(scanId, { status: 'COMPLETED', finished_at: Date.now() });
  return store.getScan(scanId);
}

/** Proyek DB sementara per pemanggilan. */
function setupProjectProxy() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cxl-vreport-'));
  const config = buildConfig({ CXL_ROOT: dir, DB_PATH: path.join(dir, 'test.db'), DB_DRIVER: 'auto', LOG_LEVEL: 'error' });
  const db = openDatabase(config, logger);
  runMigrations(db, logger);
  const store = createStore(db, logger);
  return { config, store, dir };
}

test('klasifikasi: temuan SQL Injection memakai template SQL Injection', () => {
  const cls = classifyFinding(normalizeFinding(SQLI_FINDING));
  assert.strictEqual(cls.type, 'sqli');
  assert.ok(cls.confidence === 'HIGH' || cls.confidence === 'MEDIUM', `confidence=${cls.confidence}`);
  assert.strictEqual(cls.needsReview, false, 'sinyal kuat tunggal tidak perlu review');

  const { store } = setupProjectProxy();
  const scan = makeScan(store, 'job-sqli', 'target.example.com');
  insertFinding(store, scan.id, SQLI_FINDING);
  const gen = generateReportsForScan(store, scan);
  assert.strictEqual(gen.reports.length, 1);
  const r = gen.reports[0];
  assert.strictEqual(r.vulnerabilityType.key, 'sqli');
  assert.strictEqual(r.templateId, 'TPL-SQLI');
  assert.strictEqual(r.mapping.cwe, 'CWE-89', 'CWE dari metadata engine dipertahankan');
  assert.ok(/A03:2021/.test(r.mapping.owaspFromCwe), 'pemetaan OWASP dari CWE 2021 berlabel sumber');
  assert.ok(r.validationStatus === 'DETECTED' || r.validationStatus === 'NEEDS_MANUAL_VERIFICATION');
  assert.ok(!r.validationStatus.includes('CONFIRMED') || r.validationStatus === 'DETECTED');
  assert.strictEqual(r.severity.cvss, null, 'tidak ada CVSS karangan');
  assert.ok(r.stepsToReproduce.join(' ').includes('curl'), 'repro memakai curl nyata dari engine');
});

test('klasifikasi: temuan XSS memakai template XSS; jenis hanya bila terbukti', () => {
  const { store } = setupProjectProxy();
  const scan = makeScan(store, 'job-xss', 'target.example.com');
  insertFinding(store, scan.id, {
    engine: 'nuclei',
    externalId: 'reflected-xss',
    name: 'Reflected XSS',
    severity: 'medium',
    target: 'https://target.example.com/search?x=1',
    evidence: JSON.stringify({ matcher: true, curl: 'curl -i "https://target.example.com/search?x=<script>"' }),
    tags: 'xss',
    classification: 'TEMPLATE_MATCH',
    owaspId: 'A05',
  });
  const gen = generateReportsForScan(store, scan);
  assert.strictEqual(gen.reports.length, 1);
  const r = gen.reports[0];
  assert.strictEqual(r.vulnerabilityType.key, 'xss');
  assert.strictEqual(r.templateId, 'TPL-XSS');
  const jenisField = r.title;
  assert.ok(jenisField.length > 0);
  // varian disebut dari penamaan template, bukan dikarang
  assert.ok(r.summary.includes('indikasi'));
});

test('klasifikasi: temuan access control memakai template access control + disclaimer IDOR', () => {
  const { store } = setupProjectProxy();
  const scan = makeScan(store, 'job-idor', 'target.example.com');
  insertFinding(store, scan.id, {
    engine: 'nuclei',
    externalId: 'idor-bypass',
    name: 'IDOR check',
    severity: 'high',
    target: 'https://target.example.com/api/users/1',
    evidence: JSON.stringify({ matcher: true }),
    tags: 'idor,unauth',
    classification: 'TEMPLATE_MATCH',
    owaspId: 'A01',
  });
  const gen = generateReportsForScan(store, scan);
  const r = gen.reports[0];
  assert.strictEqual(r.vulnerabilityType.key, 'access-control');
  assert.strictEqual(r.templateId, 'TPL-ACCESS-CONTROL');
  const allText = JSON.stringify(r);
  assert.ok(/IDOR|BUKAN bukti|TIDAK membandingkan/i.test(allText), 'disclaimer IDOR hadir');
});

test('pemetaan: OWASP/CWE tidak dikarang tanpa dasar', () => {
  assert.strictEqual(normalizeCwe('CWE-89'), 'CWE-89');
  assert.strictEqual(normalizeCwe('cwe-089'), 'CWE-89');
  assert.strictEqual(normalizeCwe('SQL Injection'), null, 'teks bebas bukan CWE');
  assert.strictEqual(normalizeCwe(undefined), null);

  // temuan tanpa metadata CWE -> mapping null, bukan tebakan dari nama template
  const f = {
    engine: 'nuclei',
    externalId: 'some-exposure-thing',
    name: 'Exposure thing',
    severity: 'low',
    target: 'https://t.example.com/x',
    evidence: JSON.stringify({ matcher: true }),
    tags: 'exposure',
    classification: 'TEMPLATE_MATCH',
  };
  const meta = resolveMappingMetadata(f);
  assert.strictEqual(meta.cwe, null);
  assert.strictEqual(meta.cweName, null);
  assert.strictEqual(meta.owaspFromCwe, null);
});

test('sensor: data sensitif disensor di seluruh laporan', () => {
  const secretJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
  const raw = 'Authorization: Bearer sk-live-abcdef123456 password=hunter2 token="abc123def" cookie: session=xyz789; AKIAIOSFODNN7EXAMPLE';
  const r1 = redactText(raw);
  assert.ok(!r1.text.includes('hunter2'));
  assert.ok(!r1.text.includes('sk-live-abcdef123456'));
  assert.ok(!r1.text.includes('abc123def"'));
  assert.ok(!r1.text.includes('AKIAIOSFODNN7EXAMPLE'));
  assert.ok(r1.text.includes('[REDACTED]'));

  const r2 = redactText(`Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sigvalue12345678`);
  assert.ok(!r2.text.includes('eyJhbGciOiJIUzI1NiJ9'), 'JWT utuh disensor');

  const ev = redactEvidence(JSON.stringify({ curl: `curl -H "Cookie: session=supersecret" https://t/`, detail: 'api_key=zzz999yyy' }));
  const s = JSON.stringify(ev);
  assert.ok(!s.includes('supersecret'));
  assert.ok(!s.includes('zzz999yyy'));

  assert.strictEqual(hasConcreteEvidence(''), false);
  assert.strictEqual(hasConcreteEvidence(null), false);
  assert.strictEqual(hasConcreteEvidence(JSON.stringify({ matcher: true, curl: 'curl -i https://t/x' })), true);

  // laporan end-to-end tidak memuat secret mentah
  const { store, config } = setupProjectProxy();
  const scan = makeScan(store, 'job-secret', 'target.example.com');
  insertFinding(store, scan.id, {
    ...SQLI_FINDING,
    evidence: JSON.stringify({
      matcher: true,
      curl: `curl -i "https://target.example.com/search?q=1" -H "Cookie: session=TOPSECRETVALUE" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sigvalue12345678"`,
    }),
  });
  const gen = generateReportsForScan(store, scan);
  const payload = JSON.stringify(gen.reports[0]);
  assert.ok(!payload.includes('TOPSECRETVALUE'), 'cookie sesi disensor');
  assert.ok(!payload.includes('eyJhbGciOiJIUzI1NiJ9'), 'JWT disensor');
});

test('bukti kosong: tidak menghasilkan laporan seolah terkonfirmasi', () => {
  const { store } = setupProjectProxy();
  const scan = makeScan(store, 'job-empty-evidence', 'target.example.com');
  insertFinding(store, scan.id, {
    engine: 'nuclei',
    externalId: 'xss-thing',
    name: 'XSS thing',
    severity: 'medium',
    target: 'https://target.example.com/x',
    evidence: '',
    tags: 'xss',
    classification: 'TEMPLATE_MATCH',
  });
  const gen = generateReportsForScan(store, scan);
  const r = gen.reports[0];
  assert.strictEqual(r.vulnerabilityType.key, 'xss');
  assert.strictEqual(r.validationStatus, 'NEEDS_MANUAL_VERIFICATION', 'bukti kosong => wajib verifikasi manual');
  assert.ok(!['CONFIRMED', 'FALSE_POSITIVE', 'NOT_REPRODUCED'].includes(r.validationStatus));
  assert.ok(r.gaps.some((g) => /bukti kosong/i.test(g)), 'gap bukti kosong tercatat');
  assert.ok(r.evidence.isEmpty === true);
  assert.ok(/BUKAN bukti aman/i.test(r.actualResult));
});

test('temuan tidak dikenali memakai template fallback + NEEDS_REVIEW', () => {
  const f = {
    engine: 'nuclei',
    externalId: 'zqx-totally-unknown-signature',
    name: 'Weird Unknown Signature XYZ',
    severity: 'info',
    target: 'https://target.example.com/w',
    evidence: JSON.stringify({ matcher: true }),
    tags: 'weird-tag',
    classification: 'TEMPLATE_MATCH',
  };
  const cls = classifyFinding(f);
  assert.strictEqual(cls.type, 'fallback');
  assert.strictEqual(cls.needsReview, true);

  const { store } = setupProjectProxy();
  const scan = makeScan(store, 'job-fallback', 'target.example.com');
  insertFinding(store, scan.id, f);
  const gen = generateReportsForScan(store, scan);
  const r = gen.reports[0];
  assert.strictEqual(r.templateId, 'TPL-FALLBACK');
  assert.strictEqual(r.classification.needsReview, true);
  assert.ok(r.gaps.some((g) => /fallback|NEEDS_REVIEW/i.test(g)));
});

test('klasifikasi engine internal: headerProbe checkId -> tipe tepat + cap severity INDICATOR', () => {
  // exposed:/.env -> info-exposure; INDICATOR high -> assessed medium (cap metodologi)
  const f = {
    engine: 'headerProbe',
    externalId: 'exposed:/.env',
    name: 'File .env terekspos',
    severity: 'high',
    target: 'https://target.example.com/.env',
    evidence: JSON.stringify({ detail: 'respons 200; isi tidak diunduh', evidence: 'status=200' }),
    tags: '',
    classification: 'INDICATOR',
    owaspId: 'A02',
  };
  const cls = classifyFinding(f);
  assert.strictEqual(cls.type, 'info-exposure');
  const nf = normalizeFinding({ id: 1, engine: 'headerProbe', external_id: 'exposed:/.env', name: 'x', severity: 'high', target: 'https://t/.env', evidence: f.evidence, reference: '', tags: '', owasp_id: 'A02', classification: 'INDICATOR' });
  assert.strictEqual(assessSeverity(nf), 'medium', 'INDICATOR dibatasi medium sampai verifikasi');
  assert.strictEqual(assessSeverity({ ...nf, classification: 'TEMPLATE_MATCH' }), 'high', 'TEMPLATE_MATCH mengikuti engine');

  // tls:version -> tls-crypto
  const tls = classifyFinding({
    engine: 'headerProbe',
    externalId: 'tls:version',
    name: 'Versi TLS lemah (TLSv1.0)',
    severity: 'medium',
    target: 'https://target.example.com/',
    evidence: JSON.stringify({ detail: 'protocol: TLSv1.0' }),
    tags: '',
    classification: 'INDICATOR',
  });
  assert.strictEqual(tls.type, 'tls-crypto');

  // cookie flags -> auth-session
  const cookie = classifyFinding({
    engine: 'headerProbe',
    externalId: 'cookie:flags',
    name: 'Cookie tanpa proteksi: session',
    severity: 'medium',
    target: 'https://target.example.com/',
    evidence: JSON.stringify({ detail: 'Cookie session tanpa Secure, tanpa HttpOnly' }),
    tags: '',
    classification: 'INDICATOR',
  });
  assert.strictEqual(cookie.type, 'auth-session');
});

test('deduplikasi: tipe+endpoint sama digabung; endpoint beda tetap terpisah', () => {
  assert.strictEqual(dedupeKeyFor('sqli', 'https://T.example.com/a?q=1#frag'), 'sqli|https://t.example.com/a?q=1');
  const { store } = setupProjectProxy();
  const scan = makeScan(store, 'job-dedupe', 'target.example.com');
  insertFinding(store, scan.id, {
    engine: 'nuclei',
    externalId: 'sql-injection-error-based',
    name: 'SQLi A',
    severity: 'high',
    target: 'https://target.example.com/search?q=1',
    evidence: JSON.stringify({ matcher: true, curl: 'curl https://target.example.com/search?q=1%27' }),
    tags: 'sqli',
    classification: 'TEMPLATE_MATCH',
  });
  insertFinding(store, scan.id, {
    engine: 'nuclei',
    externalId: 'sql-injection-union',
    name: 'SQLi B',
    severity: 'high',
    target: 'https://target.example.com/search?q=1',
    evidence: JSON.stringify({ matcher: true }),
    tags: 'sqli',
    classification: 'TEMPLATE_MATCH',
  });
  insertFinding(store, scan.id, {
    engine: 'nuclei',
    externalId: 'reflected-xss',
    name: 'XSS lain',
    severity: 'medium',
    target: 'https://target.example.com/search?q=1',
    evidence: JSON.stringify({ matcher: true }),
    tags: 'xss',
    classification: 'TEMPLATE_MATCH',
  });
  const gen = generateReportsForScan(store, scan);
  assert.strictEqual(gen.reports.length, 2, '3 temuan -> 2 laporan (2 SQLi digabung)');
  const sqliReport = gen.reports.find((r) => r.vulnerabilityType.key === 'sqli');
  assert.strictEqual(sqliReport.scanner.sourceFindingIds.length, 2, 'kedua sumber dirujuk');
  assert.deepStrictEqual(sqliReport.scanner.templates.sort(), ['sql-injection-error-based', 'sql-injection-union']);
});

test('ekspor: TXT, Markdown, JSON, HTML + escape HTML + bundle', (t) => {
  const { store, config } = setupProjectProxy();
  const scan = makeScan(store, 'job-export', 'target.example.com');
  insertFinding(store, scan.id, {
    ...SQLI_FINDING,
    name: 'SQL Injection <script>alert(1)</script>',
    evidence: JSON.stringify({
      matcher: true,
      curl: 'curl -i "https://target.example.com/search?q=1%27" -H "X-Marker: <script>alert(1)</script>"',
      cwe: 'CWE-89',
    }),
  });
  const gen = generateReportsForScan(store, scan);
  const r = gen.reports[0];

  const txt = renderVReportText(r);
  assert.ok(txt.includes('LAPORAN KERENTANAN CERDAS'));
  assert.ok(txt.includes(r.title));
  assert.ok(txt.includes('Status validasi'));
  assert.ok(txt.includes(r.reportUid));

  const md = renderVReportMarkdown(r);
  assert.ok(md.startsWith(`# ${r.title}`));
  assert.ok(md.includes('## Evidence (redacted)'));
  assert.ok(md.includes('## Steps to Reproduce'));

  const json = renderVReportJson(r);
  const parsed = JSON.parse(json);
  assert.strictEqual(parsed.reportUid, r.reportUid);
  assert.strictEqual(parsed.vulnerabilityType.key, 'sqli');

  const html = renderVReportHtml(r);
  assert.ok(html.includes('<!DOCTYPE html>'));
  assert.ok(!html.includes('<script>alert(1)</script>'), 'payload XSS pada nama temuan ter-escape');
  assert.ok(html.includes('&lt;script&gt;'));

  // tulis file semua format
  for (const fmt of ['txt', 'md', 'json', 'html']) {
    // eslint-disable-next-line no-await-in-loop
    const p = writeVReportFile(config, scan, r, fmt);
    assert.ok(fs.existsSync(p), `file ${fmt} ditulis`);
    assert.ok(fs.statSync(p).size > 100);
  }
  const bundle = writeVReportBundle(config, scan, gen.reports, 'html');
  assert.ok(fs.existsSync(bundle));
  const bundleJson = writeVReportBundle(config, scan, gen.reports, 'json');
  const bj = JSON.parse(fs.readFileSync(bundleJson, 'utf8'));
  assert.strictEqual(bj.reports.length, 1);
});

test('store & status: siklus manual + idempotensi regenerasi + versi', () => {
  const { store } = setupProjectProxy();
  const scan = makeScan(store, 'job-lifecycle', 'target.example.com');
  insertFinding(store, scan.id, SQLI_FINDING);
  const gen = generateReportsForScan(store, scan);
  const vrStore = createVulnReportStore(store.db);
  const row = vrStore.getReportByUid(gen.reports[0].reportUid);
  assert.ok(row, 'laporan tersimpan di DB');
  assert.strictEqual(row.validation_status, 'DETECTED');

  // status tidak sah ditolak
  assert.throws(() => vrStore.setStatus(row.id, 'MAYBE_OK', 42), /Status tidak valid/);

  // manusia mengubah status -> tercatat versi
  vrStore.setStatus(row.id, 'CONFIRMED', 42);
  vrStore.setNote(row.id, 'sudah diverifikasi dengan akun uji', 42);
  vrStore.markReviewed(row.id, 42);
  const after = vrStore.getReport(row.id);
  assert.strictEqual(after.validation_status, 'CONFIRMED');
  assert.strictEqual(after.review_status, 'REVIEWED');
  assert.strictEqual(after.reviewed_by, 42);
  assert.ok(after.review_note.includes('akun uji'));

  // regenerasi (scan ulang / finalize ulang) mempertahankan status manual & review
  const gen2 = generateReportsForScan(store, scan);
  assert.strictEqual(gen2.reports[0].validationStatus, 'CONFIRMED', 'status manual manusia tidak ditimpa otomatis');
  const after2 = vrStore.getReportByUid(gen.reports[0].reportUid);
  assert.strictEqual(after2.validation_status, 'CONFIRMED');
  assert.strictEqual(after2.review_status, 'REVIEWED');

  const versions = vrStore.versions(row.id);
  const events = versions.map((v) => v.event);
  assert.ok(events.includes('GENERATED'));
  assert.ok(events.includes('STATUS_CHANGED'));
  assert.ok(events.includes('REVIEWED'));
  assert.ok(events.includes('REGENERATED'));

  assert.deepStrictEqual([...VALIDATION_STATUSES].sort(), ['CONFIRMED', 'DETECTED', 'FALSE_POSITIVE', 'NEEDS_MANUAL_VERIFICATION', 'NOT_REPRODUCED']);
  assert.deepStrictEqual([...MANUAL_STATUSES].sort(), ['CONFIRMED', 'FALSE_POSITIVE', 'NOT_REPRODUCED']);
});

test('scan tanpa temuan: tidak ada laporan; ringkasan jujur', () => {
  const { store } = setupProjectProxy();
  const scan = makeScan(store, 'job-nofindings', 'target.example.com');
  const gen = generateReportsForScan(store, scan);
  assert.strictEqual(gen.reports.length, 0);
  const sum = summarizeForTelegram(store, scan, 5);
  assert.strictEqual(sum.total, 0);
});
