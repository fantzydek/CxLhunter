'use strict';

/**
 * Ekspor laporan cerdas ke TXT, Markdown, JSON, dan HTML.
 * Semua nilai ditampilkan dari payload terstruktur; HTML meng-escape seluruh konten.
 */

const fs = require('fs');
const path = require('path');
const { escapeHtml } = require('../utils/format');
const { sanitizeFilename } = require('../utils/validation');

function fmtList(items, bullet) {
  return (items || []).map((x) => `${bullet} ${x}`).join('\n');
}

function fmtFields(fields) {
  return (fields || []).map((f) => `${f.label}: ${f.value}`).join('\n');
}

function mappingText(r) {
  const m = r.mapping || {};
  const parts = [];
  if (m.cwe) parts.push(`CWE: ${m.cwe}${m.cweName ? ` (${m.cweName})` : ''}${m.cweSource ? ` [sumber: ${m.cweSource}]` : ''}`);
  if (m.cve) parts.push(`CVE: ${m.cve}`);
  if (m.owaspFromCwe) parts.push(`OWASP: ${m.owaspFromCwe} [sumber: ${m.owaspFromCweSource}]`);
  if (m.owasp2025Pipeline) parts.push(`OWASP pipeline scan (2025): ${m.owasp2025Pipeline}`);
  return parts.length ? parts.join('\n') : 'Tidak ada pemetaan dengan dasar valid (tidak dipaksakan).';
}

function evidenceText(r) {
  const e = r.evidence || {};
  if (e.isEmpty) return '(bukti kosong - laporan TIDAK dinyatakan terkonfirmasi)';
  if (e.redacted === null || e.redacted === undefined) return '(tidak ada bukti tersimpan)';
  if (typeof e.redacted === 'string') return e.redacted;
  try {
    return JSON.stringify(e.redacted, null, 2);
  } catch (_) {
    return String(e.redacted);
  }
}

/** --- TXT --- */
function renderVReportText(r) {
  const out = [];
  const push = (...a) => out.push(a.join(' '));
  const line = (ch) => ch.repeat(72);

  push(line('='));
  push('LAPORAN KERENTANAN CERDAS - CxL Bug Bounty Scanner');
  push(line('='));
  push(`1. Judul           : ${r.title}`);
  push(`ID Laporan         : ${r.reportUid}`);
  push(`Template           : ${r.templateId}`);
  push('');
  push('2. RINGKASAN');
  push(r.summary);
  push('');
  const a = r.affectedAsset || {};
  push('3. ASET TERDAMPAK');
  push(`   URL : ${a.url || '-'}`);
  if (a.path) push(`   Path: ${a.path}`);
  if (a.parameters) push(`   Parameter: ${a.parameters.join(', ')}`);
  push('');
  const v = r.vulnerabilityType || {};
  push(`4. JENIS KERENTANAN: ${v.label || v.key}`);
  push(`   Klasifikasi engine: ${v.engineClassification || '-'} | OWASP pipeline: ${v.enginePipelineOwasp2025 || 'UNMAPPED'}`);
  push('');
  const s = r.severity || {};
  push('5. SEVERITY');
  push(`   Sumber   : ${s.source} (${s.sourceNote || 'engine'})`);
  push(`   Penilaian ulang: ${s.assessed}`);
  push('');
  push(`6. CONFIDENCE     : ${r.confidence}`);
  push('');
  push('7. PEMETAAN CWE / CVE / OWASP');
  push(mappingText(r));
  push('');
  push('8. BUKTI (telah disensor)');
  push(evidenceText(r));
  push('');
  push('9. LANGKAH REPRODUKSI');
  push(fmtList(r.stepsToReproduce, '   -'));
  push('');
  push('10. HASIL DIHARAPKAN');
  push(r.expectedResult || '-');
  push('');
  push('11. HASIL AKTUAL');
  push(r.actualResult || '-');
  push('');
  push('12. DAMPAK');
  push(fmtList(r.impact, '   -'));
  push('');
  push('13. REKOMENDASI REMEDIASI');
  push(r.remediation && r.remediation.length ? fmtList(r.remediation, '   -') : '   - (determinasi setelah klasifikasi manual)');
  push('');
  push('14. REFERENSI');
  push(r.references && r.references.length ? fmtList(r.references, '   -') : '   - (tidak ada referensi dengan dasar valid)');
  push('');
  const sc = r.scanner || {};
  push('15. SCANNER & TEMPLATE');
  push(`   Engine   : ${(sc.engines || []).join(', ') || '-'}`);
  push(`   Template : ${(sc.templates || []).join(', ') || '-'}`);
  push(`   Klasifikasi: ${sc.classification || '-'}`);
  push(`   Sumber temuan (finding id): ${(sc.sourceFindingIds || []).join(', ') || '-'}`);
  push('');
  const cls = r.classification || {};
  push('16. STATUS VALIDASI & KETERBATASAN');
  push(`   Status validasi: ${r.validationStatus}`);
  push(`   Review: ${r.reviewStatus || 'UNREVIEWED'}${r.reviewNote ? ` | catatan: ${r.reviewNote}` : ''}`);
  push(`   Klasifikasi: confidence=${cls.confidence} needsReview=${cls.needsReview ? 'YA' : 'TIDAK'}`);
  if (r.gaps && r.gaps.length) push(`   Bukti kurang:\n${fmtList(r.gaps, '     - ')}`);
  push(`   Keterbatasan:\n${fmtList(r.limitations, '     - ')}`);
  push('');
  push('METODOLOGI SEVERITY');
  push(fmtList(s.methodology, '-'));
  push(line('='));
  return out.join('\n');
}

/** --- Markdown --- */
function renderVReportMarkdown(r) {
  const a = r.affectedAsset || {};
  const v = r.vulnerabilityType || {};
  const s = r.severity || {};
  const sc = r.scanner || {};
  const md = [];
  md.push(`# ${r.title}`);
  md.push('');
  md.push(`- **ID Laporan:** \`${r.reportUid}\``);
  md.push(`- **Template:** ${r.templateId}`);
  md.push('');
  md.push('## Summary');
  md.push('');
  md.push(r.summary || '-');
  md.push('');
  md.push('## Affected Asset');
  md.push('');
  md.push(`- URL: ${a.url || '-'}`);
  if (a.path) md.push(`- Path: ${a.path}`);
  if (a.parameters) md.push(`- Parameter: ${a.parameters.join(', ')}`);
  md.push('');
  md.push('## Vulnerability Type');
  md.push('');
  md.push(`${v.label || v.key} (klasifikasi engine: ${v.engineClassification || '-'}, OWASP pipeline: ${v.enginePipelineOwasp2025 || 'UNMAPPED'})`);
  md.push('');
  md.push('## Severity');
  md.push('');
  md.push(`- Sumber: **${s.source}** (${s.sourceNote || 'engine'})`);
  md.push(`- Penilaian ulang: **${s.assessed}**`);
  md.push(`- Confidence: **${r.confidence}**`);
  md.push('');
  md.push('## CWE / CVE / OWASP Mapping');
  md.push('');
  md.push(mappingText(r));
  md.push('');
  md.push('## Evidence (redacted)');
  md.push('');
  md.push('```');
  md.push(evidenceText(r));
  md.push('```');
  md.push('');
  md.push('## Steps to Reproduce');
  md.push('');
  md.push(fmtList(r.stepsToReproduce, '1.'.replace('1.', '-')));
  md.push('');
  md.push('## Expected Result');
  md.push('');
  md.push(r.expectedResult || '-');
  md.push('');
  md.push('## Actual Result');
  md.push('');
  md.push(r.actualResult || '-');
  md.push('');
  md.push('## Impact');
  md.push('');
  md.push(fmtList(r.impact, '-'));
  md.push('');
  md.push('## Recommended Remediation');
  md.push('');
  md.push(r.remediation && r.remediation.length ? fmtList(r.remediation, '-') : '- (determinasi setelah klasifikasi manual)');
  md.push('');
  md.push('## References');
  md.push('');
  md.push(r.references && r.references.length ? fmtList(r.references, '-') : '- (tidak ada referensi dengan dasar valid)');
  md.push('');
  md.push('## Scanner & Template');
  md.push('');
  md.push(`- Engine: ${(sc.engines || []).join(', ') || '-'}`);
  md.push(`- Template: ${(sc.templates || []).join(', ') || '-'}`);
  md.push(`- Sumber temuan (finding id): ${(sc.sourceFindingIds || []).join(', ') || '-'}`);
  md.push('');
  md.push('## Validation Status & Limitations');
  md.push('');
  md.push(`- **Status:** ${r.validationStatus}`);
  md.push(`- **Review:** ${r.reviewStatus || 'UNREVIEWED'}${r.reviewNote ? ` - ${r.reviewNote}` : ''}`);
  md.push(`- **Klasifikasi:** confidence=${(r.classification || {}).confidence}, needsReview=${(r.classification || {}).needsReview ? 'YA' : 'TIDAK'}`);
  if (r.gaps && r.gaps.length) md.push(`- **Bukti kurang:**\n${fmtList(r.gaps, '  - ')}`);
  md.push(`- **Keterbatasan:**\n${fmtList(r.limitations, '  - ')}`);
  md.push('');
  md.push('## Severity Methodology');
  md.push('');
  md.push(fmtList(s.methodology, '-'));
  return md.join('\n');
}

/** --- JSON: payload terstruktur apa adanya --- */
function renderVReportJson(r) {
  return JSON.stringify(r, null, 2);
}

/** --- HTML (semua konten di-escape) --- */
function renderVReportHtml(r) {
  const esc = escapeHtml;
  const section = (title, body) => `<h2>${esc(title)}</h2>\n${body}`;
  const ul = (items) => `<ul>${(items || []).map((x) => `<li>${esc(x)}</li>`).join('')}</ul>` || '<ul><li>-</li></ul>';
  const p = (t) => `<p>${esc(t == null || t === '' ? '-' : t)}</p>`;
  const pre = (t) => `<pre class="evidence">${esc(t)}</pre>`;
  const a = r.affectedAsset || {};
  const v = r.vulnerabilityType || {};
  const s = r.severity || {};
  const sc = r.scanner || {};
  const cls = r.classification || {};

  return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<title>${esc(r.title)}</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem auto; max-width: 860px; color: #1a202c; }
  h1 { font-size: 1.4rem; border-bottom: 2px solid #2b6cb0; padding-bottom: .4rem; }
  h2 { font-size: 1.05rem; margin-top: 1.6rem; color: #2b6cb0; }
  pre.evidence { background: #f7fafc; border: 1px solid #e2e8f0; padding: .8rem; overflow-x: auto; white-space: pre-wrap; }
  .badge { display: inline-block; padding: .1rem .5rem; border-radius: 4px; background: #edf2f7; margin-right: .4rem; font-size: .85rem; }
  .meta { color: #4a5568; font-size: .9rem; }
</style>
</head>
<body>
<h1>${esc(r.title)}</h1>
<p class="meta">ID: <code>${esc(r.reportUid)}</code> | Template: ${esc(r.templateId)} | Dibuat: ${esc(r.generatedAt)}</p>
${section('1. Summary', p(r.summary))}
${section('3. Affected Asset', `<p>${esc(a.url || '-')}</p>${a.parameters ? `<p>Parameter: ${esc(a.parameters.join(', '))}</p>` : ''}`)}
${section('4. Vulnerability Type', `<p><span class="badge">${esc(v.label || v.key)}</span><span class="badge">${esc(v.engineClassification || '-')}</span><span class="badge">OWASP pipeline: ${esc(v.enginePipelineOwasp2025 || 'UNMAPPED')}</span></p>`)}
${section('5. Severity & Confidence', `<p><span class="badge">Sumber: ${esc(s.source)}</span><span class="badge">Penilaian ulang: ${esc(s.assessed)}</span><span class="badge">Confidence: ${esc(r.confidence)}</span></p>`)}
${section('7. CWE / CVE / OWASP Mapping', `<pre>${esc(mappingText(r))}</pre>`)}
${section('8. Evidence (redacted)', pre(evidenceText(r)))}
${section('9. Steps to Reproduce', ul(r.stepsToReproduce))}
${section('10. Expected Result', p(r.expectedResult))}
${section('11. Actual Result', p(r.actualResult))}
${section('12. Impact', ul(r.impact))}
${section('13. Recommended Remediation', r.remediation && r.remediation.length ? ul(r.remediation) : p('(determinasi setelah klasifikasi manual)'))}
${section('14. References', r.references && r.references.length ? ul(r.references) : p('(tidak ada referensi dengan dasar valid)'))}
${section('15. Scanner & Template', `<p>Engine: ${esc((sc.engines || []).join(', '))}<br>Template: ${esc((sc.templates || []).join(', '))}<br>Klasifikasi: ${esc(sc.classification || '-')}<br>Sumber temuan: ${esc((sc.sourceFindingIds || []).join(', '))}</p>`)}
${section('16. Validation Status & Limitations', `<p><span class="badge">Status: ${esc(r.validationStatus)}</span><span class="badge">Review: ${esc(r.reviewStatus || 'UNREVIEWED')}</span><span class="badge">Confidence klasifikasi: ${esc(cls.confidence)}</span></p>${r.gaps && r.gaps.length ? `<p><b>Bukti kurang:</b></p>${ul(r.gaps)}` : ''}${ul(r.limitations)}`)}
${section('Severity Methodology', ul(s.methodology))}
</body>
</html>`;
}

const RENDERERS = {
  txt: { render: renderVReportText, ext: 'txt' },
  md: { render: renderVReportMarkdown, ext: 'md' },
  json: { render: renderVReportJson, ext: 'json' },
  html: { render: renderVReportHtml, ext: 'html' },
};

/** Tulis satu laporan ke file. Hasil: path file. */
function writeVReportFile(config, scanRow, payload, fmt) {
  const renderer = RENDERERS[fmt];
  if (!renderer) throw new Error(`Format ekspor tidak didukung: ${fmt}`);
  const dir = path.join(config.reportsDir, sanitizeFilename(scanRow.job_id, 80));
  fs.mkdirSync(dir, { recursive: true });
  const p = path.join(dir, `vreport-${sanitizeFilename(payload.reportUid, 60)}.${renderer.ext}`);
  fs.writeFileSync(p, renderer.render(payload), 'utf8');
  return p;
}

/** Tulis seluruh laporan satu scan ke satu berkas gabungan. */
function writeVReportBundle(config, scanRow, payloads, fmt) {
  const renderer = RENDERERS[fmt];
  if (!renderer) throw new Error(`Format ekspor tidak didukung: ${fmt}`);
  const dir = path.join(config.reportsDir, sanitizeFilename(scanRow.job_id, 80));
  fs.mkdirSync(dir, { recursive: true });
  const p = path.join(dir, `vulnerability-reports.${renderer.ext}`);
  let content;
  if (fmt === 'json') {
    content = JSON.stringify({ meta: { tool: 'CxL Bug Bounty Scanner', jobId: scanRow.job_id, generatedAt: new Date().toISOString(), total: payloads.length }, reports: payloads }, null, 2);
  } else if (fmt === 'html') {
    const { renderVReportsBundleHtml } = require('./bundleHtml');
    content = renderVReportsBundleHtml(scanRow, payloads);
  } else {
    content = payloads.map((r) => renderer.render(r)).join(`\n\n${'='.repeat(72)}\n\n`);
  }
  fs.writeFileSync(p, content, 'utf8');
  return p;
}

module.exports = {
  RENDERERS,
  renderVReportText,
  renderVReportMarkdown,
  renderVReportJson,
  renderVReportHtml,
  writeVReportFile,
  writeVReportBundle,
};
