'use strict';

/**
 * Perhitungan status coverage OWASP per kategori.
 * Status (WAJIB dipakai apa adanya, tanpa pelunakan):
 *   CHECKED_FINDINGS    - pemeriksaan berjalan dan menghasilkan temuan
 *   CHECKED_NO_FINDINGS - pemeriksaan berjalan, tidak ada indikator (BUKAN jaminan aman)
 *   PARTIAL             - hanya sebagian pemeriksaan yang dapat dilakukan
 *   MANUAL_REQUIRED     - butuh penilaian manual / akses tambahan
 *   NOT_TESTED          - belum diperiksa
 *   ENGINE_UNAVAILABLE  - engine yang dibutuhkan tidak tersedia
 */

const { OWASP_CATEGORIES, VALID_STATUSES, byId } = require('./categories');
const { AUTO_CHECKS, ALWAYS_MANUAL, plannedChecksForMode } = require('./mapping');

function normalizeEngineStatusMap(engineStatuses) {
  const map = {};
  for (const [k, v] of engineStatuses instanceof Map ? engineStatuses.entries() : Object.entries(engineStatuses || {})) {
    map[k] = typeof v === 'string' ? { status: v } : v;
  }
  return map;
}

/**
 * Hitung matriks coverage.
 * Param:
 *   mode            - mode scan
 *   options         - opsi job (engines untuk custom, exposedFilesCheck)
 *   engineStatuses  - Map/Object { engineName: {status: COMPLETED|FAILED|UNAVAILABLE|...} }
 *   findingsByCat   - Object { A01: n, ... } (dari DB)
 *   ranChecks       - array check id yang BENAR-BENAR selesai dijalankan (opsional;
 *                     default: check yang engine-nya berstatus COMPLETED)
 */
function computeCoverage({ mode, options, engineStatuses, findingsByCat, ranChecks }) {
  const statusMap = normalizeEngineStatusMap(engineStatuses);
  const findings = findingsByCat || {};
  const planned = plannedChecksForMode(mode, options);

  const completedChecks = ranChecks
    ? planned.filter((c) => ranChecks.includes(c))
    : planned.filter((c) => {
        const eng = AUTO_CHECKS[c] && AUTO_CHECKS[c].engine;
        if (!eng) return true; // scope_validation selalu dianggap berjalan bila ada barisnya
        return statusMap[eng] && statusMap[eng].status === 'COMPLETED';
      });

  const rows = [];
  for (const cat of OWASP_CATEGORIES) {
    const id = cat.id;
    const relevant = planned.filter((c) => AUTO_CHECKS[c] && AUTO_CHECKS[c].categories.includes(id));
    const ran = relevant.filter((c) => completedChecks.includes(c));
    const findingsCount = Number(findings[id] || 0);

    let status;
    let notes = '';
    const checks = ran;

    if (ALWAYS_MANUAL.includes(id) || !relevant.length) {
      status = 'MANUAL_REQUIRED';
      notes = relevant.length
        ? 'Kategori ini memang tidak dapat diperiksa otomatis dari luar; gunakan checklist manual.'
        : 'Tidak ada pemeriksaan otomatis yang direncanakan untuk kategori ini pada mode terpilih; wajib penilaian manual.';
      if (findingsCount > 0) {
        notes += ` (Ada ${findingsCount} temuan terkait dari kategori lain yang menyinggung area ini.)`;
      }
    } else if (ran.length === relevant.length) {
      if (findingsCount > 0) {
        status = 'CHECKED_FINDINGS';
        notes = `${ran.length}/${relevant.length} pemeriksaan berjalan; ${findingsCount} temuan terkait.`;
      } else {
        status = 'CHECKED_NO_FINDINGS';
        notes = `${ran.length}/${relevant.length} pemeriksaan berjalan; tidak ada indikator. CHECKED_NO_FINDINGS BUKAN jaminan aman.`;
      }
    } else if (ran.length > 0) {
      status = 'PARTIAL';
      const missingEng = Array.from(
        new Set(
          relevant
            .filter((c) => !ran.includes(c))
            .map((c) => AUTO_CHECKS[c].engine)
            .filter(Boolean)
        )
      );
      const unavailable = missingEng.filter((e) => statusMap[e] && statusMap[e].status === 'UNAVAILABLE');
      if (unavailable.length) {
        notes = `Sebagian pemeriksaan berjalan; engine tidak tersedia: ${unavailable.join(', ')}.`;
      } else {
        notes = `Sebagian pemeriksaan berjalan (${ran.length}/${relevant.length}); sisanya gagal/tidak dijalankan.`;
      }
    } else {
      const eng = AUTO_CHECKS[relevant[0]].engine;
      const st = statusMap[eng] && statusMap[eng].status;
      if (st === 'UNAVAILABLE' || st === 'INCOMPATIBLE') {
        status = 'ENGINE_UNAVAILABLE';
        notes = `Engine ${eng} tidak tersedia; pemeriksaan tidak dijalankan.`;
      } else if (st === 'FAILED' || st === 'TIMEOUT' || st === 'CANCELLED') {
        status = 'PARTIAL';
        notes = `Engine ${eng} berstatus ${st}; pemeriksaan kategori ini tidak lengkap.`;
      } else {
        status = 'NOT_TESTED';
        notes = 'Pemeriksaan belum dijalankan.';
      }
    }

    if (!VALID_STATUSES.includes(status)) status = 'NOT_TESTED';
    rows.push({ category: id, status, checks, findings: findingsCount, notes });
  }
  return rows;
}

function coverageSummary(rows) {
  const out = {};
  for (const r of rows) out[r.status] = (out[r.status] || 0) + 1;
  return out;
}

function categoryInfo(id) {
  return byId(id);
}

module.exports = { computeCoverage, coverageSummary, plannedChecksForMode, AUTO_CHECKS };
