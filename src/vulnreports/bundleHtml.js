'use strict';

/** Render HTML gabungan beberapa laporan (bundle) - semua konten di-escape. */

const { escapeHtml } = require('../utils/format');

function renderVReportsBundleHtml(scanRow, payloads) {
  const esc = escapeHtml;
  const cards = payloads
    .map((r) => {
      const a = r.affectedAsset || {};
      const cls = r.classification || {};
      return `<article class="report">
  <h2>${esc(r.title)}</h2>
  <p class="meta">ID: <code>${esc(r.reportUid)}</code> | Template: ${esc(r.templateId)} | Status: ${esc(r.validationStatus)} | Review: ${esc(r.reviewStatus || 'UNREVIEWED')}</p>
  <p>${esc(r.summary || '-')}</p>
  <p><b>Aset:</b> ${esc(a.url || '-')}</p>
  <p><b>Severity:</b> sumber ${esc((r.severity || {}).source)} / penilaian ulang ${esc((r.severity || {}).assessed)} | <b>Confidence:</b> ${esc(r.confidence)} | <b>Klasifikasi:</b> confidence=${esc(cls.confidence)}, needsReview=${esc(cls.needsReview ? 'YA' : 'TIDAK')}</p>
  <p><b>Remediasi:</b></p>
  <ul>${(r.remediation || []).map((x) => `<li>${esc(x)}</li>`).join('') || '<li>-</li>'}</ul>
  ${r.gaps && r.gaps.length ? `<p><b>Bukti kurang:</b></p><ul>${r.gaps.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>` : ''}
</article>`;
    })
    .join('\n');

  return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<title>Laporan Kerentanan Cerdas - ${esc(scanRow.job_id)}</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem auto; max-width: 860px; color: #1a202c; }
  h1 { font-size: 1.4rem; border-bottom: 2px solid #2b6cb0; padding-bottom: .4rem; }
  article.report { border: 1px solid #e2e8f0; border-radius: 8px; padding: 1rem 1.2rem; margin: 1rem 0; }
  .meta { color: #4a5568; font-size: .85rem; }
</style>
</head>
<body>
<h1>Laporan Kerentanan Cerdas</h1>
<p class="meta">Job: ${esc(scanRow.job_id)} | Target: ${esc(scanRow.target)} | Total: ${payloads.length} laporan</p>
${cards || '<p>Tidak ada laporan.</p>'}
</body>
</html>`;
}

module.exports = { renderVReportsBundleHtml };
