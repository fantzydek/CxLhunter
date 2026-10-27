'use strict';

/**
 * Renderer laporan ringkasan scan format TEKS murni (tanpa emoji).
 * Struktur: meta -> ringkasan -> engine -> matriks OWASP -> temuan ->
 *           kategori butuh manual -> keterbatasan -> rekomendasi -> langkah lanjut.
 * Semua konten berasal dari objek report (buildReport) - tidak ada data fiktif.
 */

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 };

function line(ch, n) {
  return ch.repeat(n || 72);
}

function fmtWhen(iso) {
  return iso || '-';
}

function renderTextReport(report) {
  const out = [];
  const meta = report.meta || {};
  const scan = report.scan || {};
  const summary = report.summary || {};

  out.push(line('='));
  out.push('CXL SCANNER - LAPORAN RINGKASAN PEMINDAIAN');
  out.push(line('='));
  out.push(`Alat           : ${meta.tool || 'CxL Scanner'} v${meta.version || '?'}`);
  out.push(`Dibuat         : ${meta.generatedAt || '-'}`);
  out.push(`Kerangka OWASP : ${meta.owaspFramework || '-'}`);
  out.push('');
  out.push('INFORMASI SCAN');
  out.push(line('-'));
  out.push(`Job ID      : ${scan.jobId || '-'}`);
  out.push(`Mode        : ${scan.mode || '-'}`);
  out.push(`Target      : ${scan.target || '-'}`);
  out.push(`Scope root  : ${scan.scopeRoot || '-'}`);
  out.push(`Status      : ${scan.status || '-'}`);
  out.push(`Lab mode    : ${scan.labMode ? 'AKTIF' : 'tidak'}`);
  out.push(`Mulai       : ${fmtWhen(scan.startedAt)}`);
  out.push(`Selesai     : ${fmtWhen(scan.finishedAt)}`);
  if (scan.error) out.push(`Error       : ${scan.error}`);
  out.push('');

  out.push('RINGKASAN');
  out.push(line('-'));
  out.push(`Total temuan     : ${summary.findingsTotal != null ? summary.findingsTotal : 0}`);
  const sev = summary.bySeverity || {};
  for (const s of ['critical', 'high', 'medium', 'low', 'info']) {
    if (sev[s]) out.push(`  ${s.toUpperCase().padEnd(8)}: ${sev[s]}`);
  }
  out.push(`Subdomain        : ${summary.subdomains != null ? summary.subdomains : 0}`);
  out.push(`Host hidup       : ${summary.hosts != null ? summary.hosts : 0}`);
  out.push(`Endpoint         : ${summary.endpoints != null ? summary.endpoints : 0}`);
  out.push(`Permintaan ditolak (guard) : ${summary.deniedRequests != null ? summary.deniedRequests : 0}`);
  const cov = summary.coverage || {};
  out.push(
    `Coverage OWASP   : ${cov.checked || 0} terpindai, ${cov.manualRequired || 0} butuh manual, ${cov.notTested || 0} tidak teruji (dari ${cov.total || 0} kategori)`
  );
  out.push('');

  out.push('STATUS ENGINE');
  out.push(line('-'));
  const tools = report.tools || [];
  if (!tools.length) {
    out.push('(tidak ada riwayat engine)');
  } else {
    for (const t of tools) {
      const bits = [t.engine, t.status || '-'];
      if (t.version) bits.push(`v${t.version}`);
      if (t.durationMs != null) bits.push(`${t.durationMs}ms`);
      if (t.timedOut) bits.push('TIMEOUT');
      if (t.aborted) bits.push('ABORTED');
      if (t.truncated) bits.push('OUTPUT-DIPOTONG');
      out.push(`- ${bits.join(' | ')}${t.error ? ` -- ${t.error}` : ''}`);
    }
  }
  out.push('');

  out.push(`MATRIKS COVERAGE OWASP (${meta.owaspFramework || 'OWASP Top 10:2025'})`);
  out.push(line('-'));
  const owasp = report.owasp || [];
  if (!owasp.length) {
    out.push('(belum ada data coverage)');
  } else {
    for (const o of owasp) {
      out.push(`- ${o.id} ${o.name || ''} : ${o.status} (temuan: ${o.findingsCount})${o.notes ? ` -- ${o.notes}` : ''}`);
    }
  }
  out.push('');

  out.push('TEMUAN (maksimum yang direkam pada laporan ringkas)');
  out.push(line('-'));
  const findings = report.findings || [];
  if (!findings.length) {
    out.push('TIDAK ADA TEMUAN OTOMATIS. Ini BUKAN pernyataan bahwa target aman - lihat matriks coverage dan keterbatasan.');
  } else {
    const sorted = [...findings].sort(
      (a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5)
    );
    sorted.forEach((f, i) => {
      out.push(`${i + 1}. [${String(f.severity || 'info').toUpperCase()}] ${f.name || f.externalId || '(tanpa nama)'}`);
      out.push(`   Engine       : ${f.engine} (${f.classification || 'INDICATOR'})`);
      out.push(`   ID/Template  : ${f.externalId || '-'}`);
      out.push(`   Target       : ${f.target || '-'}`);
      out.push(`   OWASP        : ${f.owaspId || 'UNMAPPED'}`);
      if (f.reference) out.push(`   Referensi    : ${f.reference}`);
      if (f.evidence) out.push(`   Evidence     : ${f.evidence}`);
    });
    if (report.findingsTruncated) {
      out.push('CATATAN: jumlah temuan melebihi kapasitas laporan ringkas; lihat file JSON / database untuk daftar lengkap.');
    }
  }
  out.push('');

  const manual = report.manualRequiredCategories || [];
  if (manual.length) {
    out.push('KATEGORI YANG BUTUH PEMERIKSAAN MANUAL');
    out.push(line('-'));
    for (const m of manual) {
      out.push(`- ${m.id} ${m.name || ''} (${m.status})`);
      for (const c of m.manualChecklist || []) out.push(`    * ${c}`);
    }
    out.push('');
  }

  out.push('KETERBATASAN PEMINDAIAN INI');
  out.push(line('-'));
  for (const l of report.limitations || []) out.push(`- ${l}`);
  out.push('');

  out.push('REKOMENDASI');
  out.push(line('-'));
  for (const r of report.recommendations || []) out.push(`- ${r}`);
  out.push('');

  out.push('LANGKAH LANJUTAN');
  out.push(line('-'));
  for (const n of report.nextSteps || []) out.push(`- ${n}`);
  out.push('');

  out.push('DISCLAIMER');
  out.push(line('-'));
  out.push(meta.disclaimer || '');
  out.push(line('='));
  return out.join('\n');
}

module.exports = { renderTextReport };
