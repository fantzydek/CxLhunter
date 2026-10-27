'use strict';

/**
 * Intelligent Vulnerability Report Generator - pipeline utama.
 *
 * Saat scan selesai (stageFinalize):
 *   1. Parse hasil NYATA dari DB temuan semua engine yang benar-benar berjalan.
 *   2. Normalisasi nama/temuan.
 *   3. Klasifikasi jenis celah (multi-sinyal; NEEDS_REVIEW bila tidak pasti).
 *   4. Pilih template laporan khusus; fallback bila tak dikenali.
 *   5. Isi HANYA data yang tersedia; bukti kurang dicatat pada `gaps`.
 *   6. Sensor bukti (tidak ada rahasia di laporan).
 *   7. Deduplikasi lintas-temuan (tipe + endpoint).
 *   8. Simpan laporan + versi + status verifikasi (idempoten per scan).
 *
 * JUJUR HASIL: status awal selalu DETECTED / NEEDS_MANUAL_VERIFICATION.
 * CONFIRMED / FALSE_POSITIVE / NOT_REPRODUCED hanya lewat tindakan manusia.
 * Tidak ada skor CVSS. Scan kosong BUKAN pernyataan aman.
 */

const { sha16 } = require('../utils/validation');
const { VULN_TYPES, resolveMappingMetadata, minSeverity } = require('./mappings');
const { classifyFinding } = require('./classifier');
const { redactEvidence, hasConcreteEvidence } = require('./redactor');
const { buildSpecifics, parseTargetUrl } = require('./templates');
const { createVulnReportStore } = require('./store');
const { VALIDATION_STATUSES, MANUAL_STATUSES } = require('./generator-constants');

const SEVERITY_METHODOLOGY = [
  'Severity sumber dipertahankan apa adanya dari engine.',
  'Penilaian ulang sistem (terpisah): TEMPLATE_MATCH mengikuti severity engine; INDICATOR (pemeriksaan internal tanpa pencocokan template) dibatasi maksimum "medium" sampai diverifikasi manual.',
  'Sistem TIDAK menghasilkan skor CVSS.',
];

/** Ekspektasi verifikasi per tipe (kriteria apa yang membuktikan temuan). */
const EXPECTED_RESULTS = {
  sqli: 'Verifikasi menunjukkan input memengaruhi query database secara tidak semestinya (pola error SQL konsisten / perubahan hasil yang tidak wajar) sesuai bukti.',
  xss: 'Verifikasi menunjukkan input direfleksikan/tereksekusi pada konteks keluaran tanpa encoding memadai, sesuai bukti.',
  'access-control': 'Verifikasi antar-akun uji menunjukkan akses objek/fungsi tanpa otorisasi yang sah.',
  ssrf: 'Verifikasi dengan callback milik Anda menunjukkan server melakukan request ke tujuan yang dikontrol uji.',
  lfi: 'Verifikasi dengan file uji menunjukkan path di luar izin tetap dapat diakses aplikasi.',
  'auth-session': 'Verifikasi menunjukkan atribut keamanan sesi/cookie memang tidak diterapkan server.',
  misconfig: 'Verifikasi menunjukkan kondisi konfigurasi tidak aman tetap ada pada respons server.',
  'info-exposure': 'Verifikasi menunjukkan informasi sensitif memang dapat diakses tanpa otorisasi.',
  rce: 'Verifikasi aman di lingkungan uji menunjukkan eksekusi kode benar-benar terjadi; sampai saat itu temuan tetap berstatus indikasi.',
  'open-redirect': 'Verifikasi menunjukkan redirect menuju tujuan arbitrer yang dikontrol penguji.',
  cors: 'Verifikasi menunjukkan origin arbitrer diterima (refleksi) dan, bila berlaku, kredensial ikut diizinkan.',
  'tls-crypto': 'Negosiasi ulang menunjukkan protokol/cipher lemah memang diterima server.',
  'known-component': 'Verifikasi menunjukkan versi/konfigurasi komponen benar-benar berada pada rentang terdampak advisori.',
  fallback: 'Review manual menentukan hasil verifikasi - belum dapat dirumuskan otomatis.',
};

/** Normalisasi satu baris temuan dari DB. */
function normalizeFinding(row) {
  return {
    findingId: row.id,
    engine: row.engine,
    externalId: row.external_id || '',
    name: row.name || '',
    severity: String(row.severity || 'info').toLowerCase(),
    target: row.target || '',
    evidence: row.evidence || '',
    reference: row.reference || '',
    tags: String(row.tags || '')
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean),
    owaspId: row.owasp_id || null,
    classification: row.classification || 'INDICATOR',
  };
}

/** URL tanpa fragment (host lowercase) - dipakai dedup & identitas unik laporan. */
function urlNoFragment(target) {
  try {
    const u = new URL(String(target || ''));
    u.hash = '';
    return `${u.protocol}//${u.host.toLowerCase()}${u.pathname}${u.search}`;
  } catch (_) {
    return String(target || '').toLowerCase();
  }
}

/** Kunci dedup: tipe + URL tanpa fragment (host lowercase; query dipertahankan). */
function dedupeKeyFor(type, target) {
  return `${type}|${urlNoFragment(target)}`;
}

/** Severity hasil penilaian ulang (metodologi terdokumentasi; tidak pernah menaikkan). */
function assessSeverity(finding) {
  if (finding.classification === 'INDICATOR') {
    return minSeverity(finding.severity, 'medium');
  }
  return finding.severity;
}

/** Status validasi awal - TIDAK PERNAH terkonfirmasi otomatis. */
function initialValidationStatus(finding) {
  const concrete = hasConcreteEvidence(finding.evidence);
  return concrete ? 'DETECTED' : 'NEEDS_MANUAL_VERIFICATION';
}

/** Ringkasan jujur sesuai sumber temuan. */
function composeSummary(finding, cls, urls) {
  const where = urls.ok ? `"${urls.host}${urls.path}"` : `"${String(urls.raw).slice(0, 80)}"`;
  if (cls.type === 'fallback') {
    return `Engine ${finding.engine} merekam temuan pada ${where} yang tidak dapat diklasifikasikan secara otomatis dengan keyakinan memadai. Temuan dipertahankan apa adanya dan ditandai NEEDS_REVIEW untuk penelaahan manual.`;
  }
  if (finding.classification === 'INDICATOR') {
    return `Pemeriksaan internal menemukan kondisi terkait ${cls.typeLabel} pada ${where}. Temuan berstatus indikator (bukan pencocokan template) dan memerlukan verifikasi manual sebelum dinyatakan terkonfirmasi.`;
  }
  return `Scanner mendeteksi indikasi ${cls.typeLabel} pada ${where} melalui template "${finding.externalId || '-'}". Temuan ini memerlukan validasi konteks/bukti sebelum dinyatakan sebagai kerentanan terkonfirmasi.`;
}

/** Bangun objek laporan lengkap untuk satu temuan (atau gabungan dedup). */
function buildReport(scanRow, primary, merged, cls) {
  const meta = resolveMappingMetadata(primary);
  const urls = parseTargetUrl(primary.target);
  const ev = redactEvidence(primary.evidence);
  const sevAssessed = assessSeverity(primary);
  const validationStatus = initialValidationStatus(primary);
  const spec = buildSpecifics(cls.type, {
    finding: primary,
    meta,
    urls,
    cls,
    evidenceRedacted: ev.redacted,
  });

  const typeInfo = VULN_TYPES[cls.type];
  const assetLabel = urls.ok ? `${urls.host}${urls.path}` : String(urls.raw).slice(0, 100);
  const gaps = [];
  if (!primary.evidence) gaps.push('Bukti kosong pada temuan sumber - laporan TIDAK dinyatakan terkonfirmasi.');
  else if (ev.isEmpty) gaps.push('Bukti kosong setelah normalisasi.');
  if (!urls.ok) gaps.push('Target tidak berbentuk URL valid - endpoint/parameter tidak terurai.');
  if (cls.type === 'fallback') gaps.push('Jenis kerentanan tidak dikenali - template fallback dipakai, NEEDS_REVIEW.');
  if (cls.needsReview && cls.type !== 'fallback') gaps.push('Klasifikasi tidak pasti (sinyal lemah/konflik) - NEEDS_REVIEW.');
  if (spec.repro.some((s) => /tidak (dapat|tersedia|ada)/i.test(s))) gaps.push('Langkah reproduksi otomatis tidak dapat disusun sepenuhnya dari bukti.');

  const report = {
    reportUid: `VR-${sha16(`${scanRow.id}|${cls.type}|${urlNoFragment(primary.target)}`)}`,
    templateId: typeInfo.templateId,
    generatedAt: new Date().toISOString(),
    scan: {
      jobId: scanRow.job_id,
      scanId: scanRow.id,
      target: scanRow.target,
      mode: scanRow.mode,
    },
    title: `[${sevAssessed.toUpperCase()}] ${typeInfo.label} pada "${assetLabel}"`,
    summary: composeSummary(primary, cls, urls),
    affectedAsset: {
      url: urls.ok ? urls.url : urls.raw,
      host: urls.host,
      path: urls.path || null,
      parameters: urls.params.length ? urls.params : null,
    },
    vulnerabilityType: {
      key: cls.type,
      label: typeInfo.label,
      engineClassification: primary.classification,
      enginePipelineOwasp2025: primary.owaspId || 'UNMAPPED',
      enginePipelineOwaspSource: 'pipeline scan (pemetaan tag/check engine)',
    },
    severity: {
      source: primary.severity,
      sourceNote: `severity sumber dari engine ${primary.engine}`,
      assessed: sevAssessed,
      methodology: SEVERITY_METHODOLOGY,
      cvss: null,
      cvssNote: 'sistem tidak mengarang skor CVSS',
    },
    confidence: cls.confidence,
    mapping: {
      cwe: meta.cwe,
      cweName: meta.cweName,
      cweSource: meta.cweSource,
      cve: meta.cve,
      owaspFromCwe: meta.owaspFromCwe,
      owaspFromCweSource: meta.owaspFromCweSource,
      owasp2025Pipeline: primary.owaspId || 'UNMAPPED',
    },
    evidence: {
      redacted: ev.redacted,
      redactionsApplied: ev.redactions,
      isEmpty: ev.isEmpty,
    },
    stepsToReproduce: spec.repro,
    expectedResult: EXPECTED_RESULTS[cls.type] || EXPECTED_RESULTS.fallback,
    actualResult: ev.isEmpty
      ? 'Tidak ada bukti tercatat pada temuan sumber - hasil aktual belum dapat dirumuskan (bukan bukti aman).'
      : 'Yang teramati scanner: kondisi sebagaimana pada bagian Evidence (telah disensor).',
    impact: spec.impact,
    remediation: spec.remediation,
    references: spec.references,
    scanner: {
      engines: Array.from(new Set([primary.engine, ...merged.map((m) => m.engine)])),
      templates: Array.from(new Set([primary.externalId, ...merged.map((m) => m.externalId)].filter(Boolean))),
      classification: primary.classification,
      sourceFindingIds: [primary.findingId, ...merged.map((m) => m.findingId)],
    },
    classification: {
      confidence: cls.confidence,
      needsReview: cls.needsReview,
      signals: cls.signals,
    },
    validationStatus,
    reviewStatus: 'UNREVIEWED',
    limitations: [
      'Temuan dihasilkan scanner otomatis dan bukan konfirmasi kerentanan.',
      'Tidak ada hasil scan kosong yang diartikan target aman.',
    ],
    gaps,
  };
  return report;
}

/**
 * Generate seluruh laporan cerdas untuk satu scan.
 * Hasil: { reports: [...], stats: { findings, reports, deduped } }
 */
function generateReportsForScan(store, scanRow) {
  const db = store.db;
  const rows = db.prepare('SELECT * FROM findings WHERE scan_id = ? ORDER BY severity ASC, id ASC').all(scanRow.id);
  const findings = rows.map(normalizeFinding);

  if (!findings.length) {
    // Tidak ada temuan: tidak ada laporan baru. Scan kosong BUKAN pernyataan aman.
    return { reports: [], stats: { findings: 0, reports: 0, deduped: 0 } };
  }

  // klasifikasi + pengelompokan dedup
  const groups = new Map(); // dedupeKey -> { primary, merged[], cls }
  for (const f of findings) {
    const cls = classifyFinding(f);
    const key = dedupeKeyFor(cls.type, f.target);
    const existing = groups.get(key);
    if (existing) {
      existing.merged.push(f);
    } else {
      groups.set(key, { primary: f, merged: [], cls });
    }
  }

  const reports = [];
  for (const g of groups.values()) {
    const report = buildReport(scanRow, g.primary, g.merged, g.cls);
    reports.push(report);
  }

  // simpan (idempoten; mempertahankan status manual & review), lalu sinkronkan
  // status efektif dari DB ke objek laporan agar pemanggil melihat kondisi final
  const vrStore = createVulnReportStore(db);
  const saved = reports.map((r) => {
    const id = vrStore.upsertGenerated(scanRow.id, r);
    const row = vrStore.getReport(id);
    if (row) {
      r.validationStatus = row.validation_status;
      r.reviewStatus = row.review_status;
      r.reviewNote = row.review_note || null;
    }
    return id;
  });

  return {
    reports,
    savedIds: saved,
    stats: {
      findings: findings.length,
      reports: reports.length,
      deduped: findings.length - reports.length,
    },
  };
}

/** Ringkas laporan untuk pesan Telegram. */
function summarizeForTelegram(store, scanRow, limit) {
  const db = store.db;
  const vrStore = createVulnReportStore(db);
  const list = vrStore.listReports(scanRow.id, { limit: limit || 50 });
  const byType = {};
  const byStatus = {};
  for (const r of list) {
    byType[r.vuln_type] = (byType[r.vuln_type] || 0) + 1;
    byStatus[r.validation_status] = (byStatus[r.validation_status] || 0) + 1;
  }
  return { total: vrStore.countReports(scanRow.id), byType, byStatus, list };
}

module.exports = {
  generateReportsForScan,
  summarizeForTelegram,
  normalizeFinding,
  dedupeKeyFor,
  urlNoFragment,
  assessSeverity,
  initialValidationStatus,
  VALIDATION_STATUSES,
  MANUAL_STATUSES,
  SEVERITY_METHODOLOGY,
};
