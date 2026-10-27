'use strict';

/**
 * Renderer laporan ringkasan scan format HTML.
 * - SEMUA nilai di-escape (tidak ada innerHTML mentah, tanpa <script>, tanpa inline JS).
 * - Severity memakai kelas CSS berwarna; dokumen mandiri (tanpa aset eksternal).
 */

function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 };

const STATUS_LABEL = {
  CHECKED_FINDINGS: 'Terpindai - ada temuan',
  CHECKED_NO_FINDINGS: 'Terpindai - tanpa indikator (BUKAN jaminan aman)',
  PARTIAL: 'Sebagian terpindai',
  MANUAL_REQUIRED: 'Butuh pemeriksaan manual',
  NOT_TESTED: 'Belum diuji',
  ENGINE_UNAVAILABLE: 'Engine tidak tersedia',
};

function renderHtmlReport(report) {
  const meta = report.meta || {};
  const scan = report.scan || {};
  const summary = report.summary || {};
  const e = escapeHtml;

  const sev = summary.bySeverity || {};
  const sevHtml = ['critical', 'high', 'medium', 'low', 'info']
    .filter((s) => sev[s])
    .map((s) => `<span class="pill sev-${s}">${s}: ${sev[s]}</span>`)
    .join(' ');

  const toolsRows = (report.tools || [])
    .map(
      (t) => `<tr><td>${e(t.engine)}</td><td>${e(t.status || '-')}${t.version ? ` <span class="dim">(v${e(t.version)})</span>` : ''}</td><td>${
        t.durationMs != null ? e(String(t.durationMs)) + ' ms' : '-'
      }</td><td>${t.error ? `<span class="err">${e(t.error)}</span>` : '-'}${
        t.timedOut ? ' <span class="pill warn">TIMEOUT</span>' : ''
      }${t.truncated ? ' <span class="pill warn">OUTPUT DIPOTONG</span>' : ''}</td></tr>`
    )
    .join('\n');

  const owaspRows = (report.owasp || [])
    .map(
      (o) => `<tr><td>${e(o.id)}</td><td>${e(o.name || '')}</td><td><span class="status ${e(o.status)}" title="${e(
        STATUS_LABEL[o.status] || o.status
      )}">${e(o.status)}</span></td><td class="num">${e(String(o.findingsCount || 0))}</td><td>${
        o.notes ? e(o.notes) : ''
      }</td></tr>`
    )
    .join('\n');

  const findings = [...(report.findings || [])].sort(
    (a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5)
  );
  const findingsHtml = findings.length
    ? findings
        .map(
          (f) => `<li class="finding sev-border-${e(f.severity || 'info')}">
  <div class="fhead"><span class="pill sev-${e(f.severity || 'info')}">${e(String(f.severity || 'info').toUpperCase())}</span>
  <strong>${e(f.name || f.externalId || '(tanpa nama)')}</strong></div>
  <table class="kv">
    <tr><th>Engine</th><td>${e(f.engine)} (${e(f.classification || 'INDICATOR')})</td></tr>
    <tr><th>ID/Template</th><td>${e(f.externalId || '-')}</td></tr>
    <tr><th>Target</th><td>${e(f.target || '-')}</td></tr>
    <tr><th>OWASP</th><td>${e(f.owaspId || 'UNMAPPED')}</td></tr>
    ${f.reference ? `<tr><th>Referensi</th><td>${e(f.reference)}</td></tr>` : ''}
    ${f.evidence ? `<tr><th>Evidence</th><td><pre class="ev">${e(f.evidence)}</pre></td></tr>` : ''}
  </table>
</li>`
        )
        .join('\n')
    : '<p class="warnbox">TIDAK ADA TEMUAN OTOMATIS. Ini BUKAN pernyataan bahwa target aman - lihat matriks coverage dan keterbatasan.</p>';

  const manualHtml = (report.manualRequiredCategories || [])
    .map(
      (m) => `<li><strong>${e(m.id)}</strong> ${e(m.name || '')} <span class="dim">(${e(m.status)})</span><ul>${(
        m.manualChecklist || []
      )
        .map((c) => `<li>${e(c)}</li>`)
        .join('')}</ul></li>`
    )
    .join('\n');

  const limitationsHtml = (report.limitations || []).map((l) => `<li>${e(l)}</li>`).join('\n');
  const recsHtml = (report.recommendations || []).map((r) => `<li>${e(r)}</li>`).join('\n');
  const nextHtml = (report.nextSteps || []).map((n) => `<li>${e(n)}</li>`).join('\n');

  return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Laporan ${e(scan.jobId || 'scan')} - CxL Scanner</title>
<style>
  :root { --bg:#0f1420; --card:#171f30; --fg:#e8edf7; --dim:#8b97ad; --line:#2a3750; }
  * { box-sizing: border-box; }
  body { background: var(--bg); color: var(--fg); font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 24px; line-height: 1.55; }
  .wrap { max-width: 980px; margin: 0 auto; }
  h1 { font-size: 1.5rem; margin: 0 0 4px; }
  h2 { font-size: 1.1rem; margin: 28px 0 8px; border-bottom: 1px solid var(--line); padding-bottom: 6px; }
  .card { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 16px 18px; margin: 12px 0; }
  table { width: 100%; border-collapse: collapse; font-size: 0.92rem; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { color: var(--dim); font-weight: 600; white-space: nowrap; }
  td.num { text-align: right; }
  .dim { color: var(--dim); }
  .err { color: #ff8f8f; }
  .warnbox { background: #3a2a12; border: 1px solid #6b4a1a; color: #ffd9a0; padding: 10px 12px; border-radius: 8px; }
  .pill { display: inline-block; border-radius: 999px; padding: 1px 10px; font-size: 0.78rem; font-weight: 700; margin-right: 4px; background: #22304a; }
  .pill.sev-critical { background: #5c0f18; color: #ffb3bd; }
  .pill.sev-high { background: #5a2a0d; color: #ffc08a; }
  .pill.sev-medium { background: #54460d; color: #ffe28a; }
  .pill.sev-low { background: #12405c; color: #a8d8ff; }
  .pill.sev-info { background: #22304a; color: #c6d4ee; }
  .pill.warn { background: #54460d; color: #ffe28a; }
  .status { font-family: ui-monospace, monospace; font-size: 0.8rem; }
  .status.CHECKED_NO_FINDINGS, .status.PARTIAL { color: #ffd9a0; }
  .status.CHECKED_FINDINGS { color: #ffb3bd; }
  .status.MANUAL_REQUIRED, .status.NOT_TESTED, .status.ENGINE_UNAVAILABLE { color: var(--dim); }
  .finding { list-style: none; border: 1px solid var(--line); border-left-width: 4px; border-radius: 8px; padding: 10px 12px; margin: 10px 0; background: var(--card); }
  .sev-border-critical { border-left-color: #c2253c; }
  .sev-border-high { border-left-color: #d97706; }
  .sev-border-medium { border-left-color: #d4b106; }
  .sev-border-low { border-left-color: #2b7fb8; }
  .sev-border-info { border-left-color: #3f4d68; }
  .fhead { margin-bottom: 6px; }
  .kv th { width: 130px; }
  pre.ev { white-space: pre-wrap; word-break: break-all; margin: 0; font-size: 0.8rem; color: #c6d4ee; font-family: ui-monospace, monospace; }
  footer { color: var(--dim); font-size: 0.82rem; margin-top: 32px; border-top: 1px solid var(--line); padding-top: 12px; }
</style>
</head>
<body>
<div class="wrap">
  <h1>Laporan Pemindaian - CxL Scanner</h1>
  <div class="dim">v${e(meta.version || '?')} &middot; Kerangka ${e(meta.owaspFramework || '-')} &middot; Dibuat ${e(meta.generatedAt || '-')}</div>

  <h2>Informasi Scan</h2>
  <div class="card">
    <table class="kv">
      <tr><th>Job ID</th><td>${e(scan.jobId || '-')}</td></tr>
      <tr><th>Mode</th><td>${e(scan.mode || '-')}</td></tr>
      <tr><th>Target</th><td>${e(scan.target || '-')}</td></tr>
      <tr><th>Scope root</th><td>${e(scan.scopeRoot || '-')}</td></tr>
      <tr><th>Status</th><td>${e(scan.status || '-')}</td></tr>
      <tr><th>Lab mode</th><td>${scan.labMode ? 'AKTIF' : 'tidak'}</td></tr>
      <tr><th>Mulai</th><td>${e(scan.startedAt || '-')}</td></tr>
      <tr><th>Selesai</th><td>${e(scan.finishedAt || '-')}</td></tr>
      ${scan.error ? `<tr><th>Error</th><td class="err">${e(scan.error)}</td></tr>` : ''}
    </table>
  </div>

  <h2>Ringkasan</h2>
  <div class="card">
    <p><strong>Total temuan: ${e(String(summary.findingsTotal != null ? summary.findingsTotal : 0))}</strong> ${sevHtml}</p>
    <p class="dim">Subdomain: ${e(String(summary.subdomains != null ? summary.subdomains : 0))} &middot;
       Host hidup: ${e(String(summary.hosts != null ? summary.hosts : 0))} &middot;
       Endpoint: ${e(String(summary.endpoints != null ? summary.endpoints : 0))} &middot;
       Permintaan ditolak guard: ${e(String(summary.deniedRequests != null ? summary.deniedRequests : 0))}</p>
  </div>

  <h2>Status Engine</h2>
  <div class="card">
    <table>
      <tr><th>Engine</th><th>Status</th><th>Durasi</th><th>Error</th></tr>
      ${toolsRows || '<tr><td colspan="4" class="dim">tidak ada riwayat engine</td></tr>'}
    </table>
  </div>

  <h2>Matriks Coverage OWASP (${e(meta.owaspFramework || 'OWASP Top 10:2025')})</h2>
  <div class="card">
    <table>
      <tr><th>Kategori</th><th>Nama</th><th>Status</th><th class="num">Temuan</th><th>Catatan</th></tr>
      ${owaspRows || '<tr><td colspan="5" class="dim">belum ada data coverage</td></tr>'}
    </table>
    <p class="dim">Status CHECKED_NO_FINDINGS berarti pemeriksaan otomatis berjalan tanpa indikator - BUKAN pernyataan aman.</p>
  </div>

  <h2>Temuan</h2>
  ${findingsHtml}
  ${report.findingsTruncated ? '<p class="dim">Jumlah temuan melebihi kapasitas laporan ringkas; lihat file JSON / database.</p>' : ''}

  ${
    manualHtml
      ? `<h2>Kategori yang Butuh Pemeriksaan Manual</h2><div class="card"><ul>${manualHtml}</ul></div>`
      : ''
  }

  <h2>Keterbatasan Pemindaian Ini</h2>
  <div class="card"><ul>${limitationsHtml || '<li>-</li>'}</ul></div>

  <h2>Rekomendasi</h2>
  <div class="card"><ul>${recsHtml || '<li>-</li>'}</ul></div>

  <h2>Langkah Lanjutan</h2>
  <div class="card"><ul>${nextHtml || '<li>-</li>'}</ul></div>

  <footer><strong>Disclaimer:</strong> ${e(meta.disclaimer || '')}</footer>
</div>
</body>
</html>
`;
}

module.exports = { renderHtmlReport };
