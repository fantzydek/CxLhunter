'use strict';

/**
 * Penyimpanan laporan cerdas (tabel vuln_reports + vuln_report_versions).
 * - Idempoten per scan: regenerasi mempertahankan status manual (CONFIRMED /
 *   FALSE_POSITIVE / NOT_REPRODUCED) dan status review milik manusia.
 * - Setiap perubahan penting (generate/ubah status/review/note) membuat versi
 *   baru dengan snapshot payload penuh (jejak audit).
 */

const { sanitizeText } = require('../utils/validation');
const { VALIDATION_STATUSES, MANUAL_STATUSES } = require('./generator-constants');

function now() {
  return Date.now();
}

function createVulnReportStore(db) {
  function nextVersion(reportId) {
    const row = db.prepare('SELECT MAX(version) AS v FROM vuln_report_versions WHERE report_id = ?').get(reportId);
    return (row && row.v ? Number(row.v) : 0) + 1;
  }

  function appendVersion(reportId, event, status, payloadJson, actorId) {
    db.prepare(
      `INSERT INTO vuln_report_versions (report_id, version, event, validation_status, payload_json, actor_id, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).run(reportId, nextVersion(reportId), event, status || null, payloadJson, actorId || null, now());
  }

  function loadPayload(row) {
    try {
      return JSON.parse(row.payload_json || '{}');
    } catch (_) {
      return {};
    }
  }

  const store = {
    /** Sisipkan/perbarui laporan hasil generasi otomatis. Mengembalikan id baris. */
    upsertGenerated(scanId, report) {
      const payloadJson = JSON.stringify(report);
      const existing = db.prepare('SELECT * FROM vuln_reports WHERE report_uid = ?').get(report.reportUid);
      if (existing) {
        const keepManual = MANUAL_STATUSES.includes(existing.validation_status);
        const finalStatus = keepManual ? existing.validation_status : report.validationStatus;
        const payload = loadPayload(existing);
        payload.validationStatus = finalStatus;
        payload.reviewStatus = existing.review_status || 'UNREVIEWED';
        payload.reviewNote = existing.review_note || null;
        const merged = JSON.stringify(payload);
        db.prepare(
          `UPDATE vuln_reports SET
             title = ?, severity_source = ?, severity_assessed = ?, confidence = ?,
             validation_status = ?, needs_review = ?, cwe = ?, cve = ?, owasp_id = ?,
             source_finding_ids = ?, payload_json = ?, updated_at = ?
           WHERE id = ?`
        ).run(
          sanitizeText(report.title, 300),
          report.severity.source,
          report.severity.assessed,
          report.confidence,
          finalStatus,
          report.classification.needsReview ? 1 : 0,
          report.mapping.cwe || null,
          report.mapping.cve || null,
          report.vulnerabilityType.enginePipelineOwasp2025 || null,
          JSON.stringify(report.scanner.sourceFindingIds),
          merged,
          now(),
          existing.id
        );
        appendVersion(existing.id, 'REGENERATED', finalStatus, merged, null);
        return existing.id;
      }
      const r = db
        .prepare(
          `INSERT INTO vuln_reports
             (scan_id, report_uid, vuln_type, template_id, title, severity_source, severity_assessed,
              confidence, validation_status, needs_review, cwe, cve, owasp_id, source_finding_ids,
              payload_json, review_status, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'UNREVIEWED', ?, ?)`
        )
        .run(
          scanId,
          report.reportUid,
          report.vulnerabilityType.key,
          report.templateId,
          sanitizeText(report.title, 300),
          report.severity.source,
          report.severity.assessed,
          report.confidence,
          report.validationStatus,
          report.classification.needsReview ? 1 : 0,
          report.mapping.cwe || null,
          report.mapping.cve || null,
          report.vulnerabilityType.enginePipelineOwasp2025 || null,
          JSON.stringify(report.scanner.sourceFindingIds),
          payloadJson,
          now(),
          now()
        );
      const id = Number(r.lastInsertRowid);
      appendVersion(id, 'GENERATED', report.validationStatus, payloadJson, null);
      return id;
    },

    /** Ubah status validasi (aksi manusia). Tolak status di luar kosa kata resmi. */
    setStatus(reportId, status, actorId) {
      if (!VALIDATION_STATUSES.includes(status)) {
        throw new Error(`Status tidak valid: ${status}. Gunakan: ${VALIDATION_STATUSES.join(', ')}`);
      }
      const row = db.prepare('SELECT * FROM vuln_reports WHERE id = ?').get(reportId);
      if (!row) return null;
      const payload = loadPayload(row);
      payload.validationStatus = status;
      const merged = JSON.stringify(payload);
      db.prepare(
        'UPDATE vuln_reports SET validation_status = ?, payload_json = ?, updated_at = ? WHERE id = ?'
      ).run(status, merged, now(), reportId);
      appendVersion(reportId, 'STATUS_CHANGED', status, merged, actorId);
      return status;
    },

    /** Tandai sudah direview. */
    markReviewed(reportId, actorId, note) {
      const row = db.prepare('SELECT * FROM vuln_reports WHERE id = ?').get(reportId);
      if (!row) return null;
      const payload = loadPayload(row);
      payload.reviewStatus = 'REVIEWED';
      const merged = JSON.stringify(payload);
      db.prepare(
        `UPDATE vuln_reports SET review_status = 'REVIEWED', reviewed_by = ?, reviewed_at = ?,
           payload_json = ?, updated_at = ?
         WHERE id = ?`
      ).run(actorId || null, now(), merged, now(), reportId);
      if (note) store.setNote(reportId, note, actorId, true);
      else appendVersion(reportId, 'REVIEWED', row.validation_status, merged, actorId);
      return true;
    },

    /** Simpan catatan review. bumpNoVersion untuk pemanggilan internal. */
    setNote(reportId, note, actorId, bumpNoVersion) {
      const row = db.prepare('SELECT * FROM vuln_reports WHERE id = ?').get(reportId);
      if (!row) return null;
      const clean = sanitizeText(note, 1000);
      const payload = loadPayload(row);
      payload.reviewNote = clean;
      const merged = JSON.stringify(payload);
      db.prepare('UPDATE vuln_reports SET review_note = ?, payload_json = ?, updated_at = ? WHERE id = ?').run(
        clean,
        merged,
        now(),
        reportId
      );
      if (!bumpNoVersion) appendVersion(reportId, 'NOTE_ADDED', row.validation_status, merged, actorId);
      return clean;
    },

    getReport(reportId) {
      return db.prepare('SELECT * FROM vuln_reports WHERE id = ?').get(reportId) || null;
    },
    getReportByUid(uid) {
      return db.prepare('SELECT * FROM vuln_reports WHERE report_uid = ?').get(uid) || null;
    },
    /** Gabungkan dengan data scan untuk otorisasi. */
    getReportWithScan(uidOrId) {
      const row =
        typeof uidOrId === 'number' || /^\d+$/.test(String(uidOrId))
          ? store.getReport(Number(uidOrId))
          : store.getReportByUid(String(uidOrId));
      if (!row) return null;
      const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(row.scan_id);
      return { report: row, scan: scan || null };
    },
    listReports(scanId, { limit, offset, type, status } = {}) {
      const lim = Math.min(limit || 20, 100);
      if (type) {
        return db
          .prepare('SELECT * FROM vuln_reports WHERE scan_id = ? AND vuln_type = ? ORDER BY id LIMIT ? OFFSET ?')
          .all(scanId, type, lim, offset || 0);
      }
      if (status) {
        return db
          .prepare('SELECT * FROM vuln_reports WHERE scan_id = ? AND validation_status = ? ORDER BY id LIMIT ? OFFSET ?')
          .all(scanId, status, lim, offset || 0);
      }
      return db
        .prepare('SELECT * FROM vuln_reports WHERE scan_id = ? ORDER BY id LIMIT ? OFFSET ?')
        .all(scanId, lim, offset || 0);
    },
    countReports(scanId) {
      const r = db.prepare('SELECT COUNT(*) AS n FROM vuln_reports WHERE scan_id = ?').get(scanId);
      return Number(r.n);
    },
    versions(reportId) {
      return db
        .prepare('SELECT * FROM vuln_report_versions WHERE report_id = ? ORDER BY version DESC')
        .all(reportId);
    },
  };

  return store;
}

module.exports = { createVulnReportStore, MANUAL_STATUSES, VALIDATION_STATUSES };
