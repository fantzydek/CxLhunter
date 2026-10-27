'use strict';

/**
 * Penyusun objek laporan ringkasan scan (JSON) + penulisan file laporan
 * dalam tiga format: JSON, TXT (via ./text), HTML (via ./html).
 *
 * Prinsip jujur:
 * - Semua angka berasal dari database scan yang NYATA (temuan, engine_runs, coverage).
 * - "CHECKED_NO_FINDINGS" ditampilkan apa adanya dan BUKAN diartikan aman.
 * - Evidence dipotong (truncate) di laporan ringkasan; detail tetap ada di DB.
 */

const fs = require('fs');
const path = require('path');
const { sanitizeText } = require('../utils/validation');
const { renderTextReport } = require('./text');
const { renderHtmlReport } = require('./html');
const { OWASP_CATEGORIES } = require('../owasp/categories');

function packageVersion() {
  try {
    // eslint-disable-next-line global-require
    return require('../../package.json').version || 'unknown';
  } catch (_) {
    return 'unknown';
  }
}

const OWASP_FRAMEWORK = 'OWASP Top 10:2025';

const DISCLAIMER =
  'Dokumen ini dihasilkan OTOMATIS dari hasil pemindaian non-destruktif terhadap target yang ' +
  'terdaftar di allowlist. Setiap temuan berstatus INDICATOR atau TEMPLATE_MATCH dan WAJIB ' +
  'diverifikasi manual sebelum dilaporkan ke program bug bounty. Scanner otomatis hanya ' +
  'menjangkau sebagian permukaan serangan; tidak ada temuan BUKAN berarti target aman. ' +
  'Dokumen ini TIDAK mengandung penilaian CVSS buatan - nilai severity adalah milik engine sumber.';

function safeParseJson(text, fallback) {
  try {
    return JSON.parse(text);
  } catch (_) {
    return fallback;
  }
}

function isoOrNull(ms) {
  return ms ? new Date(Number(ms)).toISOString() : null;
}

function sanitizeFilenamePart(s) {
  return String(s || 'scan')
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80) || 'scan';
}

function catById(id) {
  return OWASP_CATEGORIES.find((c) => c.id === String(id || '').toUpperCase()) || null;
}

function evidencePreview(evidence, max) {
  const raw = String(evidence || '');
  if (!raw) return '';
  return raw.length > (max || 300) ? raw.slice(0, max || 300) + '...[dipotong]' : raw;
}

/**
 * Bangun objek laporan lengkap dari data scan yang tersimpan.
 * store: createStore(...) ; config: buildConfig(...) ; scanRow: store.getScan(id)
 */
function buildReport(store, config, scanRow) {
  const scanId = scanRow.id;
  const bySeverityRows = store.findingsBySeverity(scanId) || [];
  const bySeverity = {};
  for (const r of bySeverityRows) bySeverity[String(r.severity || 'unknown').toLowerCase()] = Number(r.n || 0);

  const findingsTotal = store.countFindings(scanId);
  const findingsRows = store.listFindings(scanId, { limit: 100 }) || [];
  const findings = findingsRows.map((f) => ({
    id: f.id,
    engine: f.engine,
    externalId: sanitizeText(f.external_id || '', 200),
    name: sanitizeText(f.name || '', 300),
    severity: String(f.severity || 'info').toLowerCase(),
    owaspId: f.owasp_id || 'UNMAPPED',
    target: sanitizeText(f.target || '', 400),
    classification: f.classification || 'INDICATOR',
    evidence: evidencePreview(f.evidence, 300),
    reference: sanitizeText(f.reference || '', 400),
  }));

  const tools = (store.listEngineRuns(scanId) || []).map((r) => ({
    engine: r.engine,
    status: r.status,
    version: r.version || null,
    durationMs: r.duration_ms != null ? Number(r.duration_ms) : null,
    exitCode: r.exit_code != null ? Number(r.exit_code) : null,
    timedOut: !!r.timed_out,
    aborted: !!r.aborted,
    truncated: !!r.truncated,
    error: sanitizeText(r.error || '', 300) || null,
  }));

  const coverageRows = store.getCoverage(scanId) || [];
  const owasp = coverageRows.map((r) => {
    const cat = catById(r.category);
    let checks = safeParseJson(r.checks_json, []);
    if (!Array.isArray(checks)) checks = [];
    return {
      id: r.category,
      name: cat ? cat.name : r.category,
      status: r.status,
      findingsCount: Number(r.findings_count || 0),
      checks,
      notes: sanitizeText(r.notes || '', 300) || null,
    };
  });

  const manualRequiredCategories = coverageRows
    .filter((r) => r.status === 'MANUAL_REQUIRED' || r.status === 'NOT_TESTED')
    .map((r) => {
      const cat = catById(r.category);
      return {
        id: r.category,
        name: cat ? cat.name : r.category,
        status: r.status,
        manualChecklist: cat ? cat.manualChecklist : [],
      };
    });

  // Keterbatasan yang jujur, dinamis per scan + keterbatasan struktural scanner
  const limitations = [];
  for (const row of owasp) {
    if (row.status === 'CHECKED_NO_FINDINGS') {
      limitations.push(`${row.id} (${row.name}): pemeriksaan otomatis berjalan tanpa indikator - BUKAN jaminan aman.`);
    } else if (row.status === 'PARTIAL') {
      limitations.push(`${row.id} (${row.name}): hanya sebagian pemeriksaan otomatis yang dapat dijalankan.`);
    } else if (row.status === 'ENGINE_UNAVAILABLE') {
      limitations.push(`${row.id} (${row.name}): engine yang dibutuhkan tidak tersedia, kategori ini tidak teruji.`);
    } else if (row.status === 'NOT_TESTED') {
      limitations.push(`${row.id} (${row.name}): belum diperiksa pada mode scan ini.`);
    } else if (row.status === 'MANUAL_REQUIRED') {
      limitations.push(`${row.id} (${row.name}): butuh penilaian manual/akses kredensial uji.`);
    }
  }
  limitations.push('Scanner TIDAK melakukan pengujian destruktif, brute force, DoS, atau uji dengan kredensial produksi.');
  limitations.push('IDOR/kontrol akses, logika bisnis, dan kualitas kriptografi server tidak dapat dipastikan dari pemindaian eksternal pasif/semi-aktif.');
  limitations.push('Hasil hanya mencakup permukaan yang dapat dijangkau dari luar pada saat scan berlangsung.');

  // Rekomendasi mitigasi dari kategori yang memiliki temuan (sumber: definisi OWASP 2025)
  const recommendations = [];
  const recSeen = new Set();
  for (const row of owasp) {
    if (row.findingsCount > 0) {
      const cat = catById(row.id);
      for (const m of (cat && cat.mitigations) || []) {
        const key = sanitizeText(m, 200);
        if (!recSeen.has(key)) {
          recSeen.add(key);
          recommendations.push(`${row.id}: ${key}`);
        }
      }
    }
  }
  if (!recommendations.length) {
    recommendations.push('Tidak ada temuan otomatis pada scan ini - gunakan checklist manual kategori OWASP untuk pemeriksaan lanjutan.');
  }

  const nextSteps = [
    'Verifikasi manual setiap temuan (buka URL, ulangi permintaan, pastikan dampak nyata) sebelum dilaporkan.',
    'Jalankan perintah /vreports pada bot untuk membuka LAPORAN CERDAS per-jenis kerentanan (dengan langkah verifikasi aman).',
    'Ekspor laporan melalui tombol Export (JSON/TXT/HTML) atau /report <jobId> bila dibutuhkan untuk dokumentasi.',
  ];
  if (config && config.labMode) {
    nextSteps.push('LAB_MODE aktif: pastikan target lab untuk pengujian yang lebih dalam sebelum menyentuh target produksi.');
  }
  if (findingsTotal === 0) {
    nextSteps.push('Scan ini tidak menghasilkan temuan - jalankan mode full dan/atau periksa checklist manual; jangan menyimpulkan target aman.');
  }

  const checkedCount = coverageRows.filter((r) => r.status === 'CHECKED_FINDINGS' || r.status === 'CHECKED_NO_FINDINGS').length;
  const manualCount = coverageRows.filter((r) => r.status === 'MANUAL_REQUIRED').length;
  const notTestedCount = coverageRows.filter((r) => r.status === 'NOT_TESTED' || r.status === 'ENGINE_UNAVAILABLE').length;

  return {
    meta: {
      tool: 'CxL Scanner',
      version: packageVersion(),
      generatedAt: new Date().toISOString(),
      owaspFramework: OWASP_FRAMEWORK,
      disclaimer: DISCLAIMER,
    },
    scan: {
      jobId: scanRow.job_id,
      mode: scanRow.mode,
      target: sanitizeText(scanRow.target || '', 300),
      scopeRoot: sanitizeText(scanRow.scope_root || '', 300),
      status: scanRow.status,
      labMode: !!scanRow.lab_mode,
      startedAt: isoOrNull(scanRow.started_at),
      finishedAt: isoOrNull(scanRow.finished_at),
      error: sanitizeText(scanRow.error || '', 300) || null,
      options: safeParseJson(scanRow.options_json, {}) || {},
    },
    summary: {
      findingsTotal,
      bySeverity,
      subdomains: store.countSubdomains(scanId),
      hosts: store.countHosts(scanId),
      endpoints: store.countEndpoints(scanId),
      deniedRequests: store.countDeniedDecisions(scanId),
      coverage: {
        checked: checkedCount,
        manualRequired: manualCount,
        notTested: notTestedCount,
        total: coverageRows.length,
      },
    },
    tools,
    owasp,
    findings,
    findingsTruncated: findingsTotal > findings.length,
    manualRequiredCategories,
    limitations,
    recommendations,
    nextSteps,
  };
}

/**
 * Bangun laporan dan tulis tiga file (json/txt/html) ke config.reportsDir.
 * Kolom report_*_path pada baris scan diperbarui.
 * Mengembalikan { report, jsonPath, txtPath, htmlPath }.
 */
function buildReportFiles(store, config, scanRow) {
  const report = buildReport(store, config, scanRow);
  const dir = config.reportsDir;
  fs.mkdirSync(dir, { recursive: true });
  const base = `cxl-${sanitizeFilenamePart(scanRow.job_id)}`;
  const jsonPath = path.join(dir, `${base}.json`);
  const txtPath = path.join(dir, `${base}.txt`);
  const htmlPath = path.join(dir, `${base}.html`);

  fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2), 'utf8');
  fs.writeFileSync(txtPath, renderTextReport(report), 'utf8');
  fs.writeFileSync(htmlPath, renderHtmlReport(report), 'utf8');

  store.updateScan(scanRow.id, {
    report_json_path: jsonPath,
    report_txt_path: txtPath,
    report_html_path: htmlPath,
  });

  return { report, jsonPath, txtPath, htmlPath };
}

module.exports = { buildReport, buildReportFiles, DISCLAIMER, OWASP_FRAMEWORK };
