'use strict';

/**
 * Lapisan database SQLite dengan driver adapter:
 *   1. better-sqlite3 (utama; butuh kompilasi native di Termux: pkg install clang python make binutils)
 *   2. node:sqlite DatabaseSync (bawaan Node.js >= 22.5; tanpa kompilasi)
 *
 * Trade-off didokumentasikan di README: keduanya SQLite sinkron yang sama-sama layak produksi
 * untuk bot tunggal; better-sqlite3 lebih matang, node:sqlite menghilangkan beban kompilasi
 * native di Termux. Koneksi tunggal + WAL + busy_timeout; migrasi dilindungi transaksi.
 */

const fs = require('fs');
const path = require('path');

function toNum(v) {
  if (v === undefined || v === null) return v;
  return typeof v === 'bigint' ? Number(v) : v;
}

function wrapBetter(raw) {
  return {
    driver: 'better-sqlite3',
    raw,
    exec(sql) {
      raw.exec(sql);
    },
    prepare(sql) {
      const st = raw.prepare(sql);
      return {
        run: (...p) => {
          const r = st.run(...p);
          return { changes: toNum(r.changes), lastInsertRowid: toNum(r.lastInsertRowid) };
        },
        get: (...p) => st.get(...p),
        all: (...p) => st.all(...p),
      };
    },
    transaction(fn) {
      // Transaksi eksplisit; bekerja untuk kedua driver
      raw.exec('BEGIN IMMEDIATE');
      try {
        const out = fn();
        raw.exec('COMMIT');
        return out;
      } catch (err) {
        try {
          raw.exec('ROLLBACK');
        } catch (_) {
          /* diamkan */
        }
        throw err;
      }
    },
    close() {
      raw.close();
    },
  };
}

function wrapNodeSqlite(raw) {
  return {
    driver: 'node:sqlite',
    raw,
    exec(sql) {
      raw.exec(sql);
    },
    prepare(sql) {
      const st = raw.prepare(sql);
      return {
        run: (...p) => {
          const r = st.run(...p);
          return { changes: toNum(r.changes), lastInsertRowid: toNum(r.lastInsertRowid) };
        },
        get: (...p) => st.get(...p),
        all: (...p) => st.all(...p),
      };
    },
    transaction(fn) {
      raw.exec('BEGIN IMMEDIATE');
      try {
        const out = fn();
        raw.exec('COMMIT');
        return out;
      } catch (err) {
        try {
          raw.exec('ROLLBACK');
        } catch (_) {
          /* diamkan */
        }
        throw err;
      }
    },
    close() {
      raw.close();
    },
  };
}

/** Buka database dengan driver yang tersedia. dbDriver: auto | better-sqlite3 | node:sqlite */
function openDatabase(config, logger) {
  const file = config.dbPath;
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const attempts = [];

  const wantBetter = config.dbDriver === 'auto' || config.dbDriver === 'better-sqlite3';
  if (wantBetter) {
    try {
      // eslint-disable-next-line global-require
      const BetterSqlite3 = require('better-sqlite3');
      const raw = new BetterSqlite3(file);
      raw.pragma('journal_mode = WAL');
      raw.pragma('foreign_keys = ON');
      raw.pragma('busy_timeout = 5000');
      if (logger) logger.info(`Database (better-sqlite3): ${file}`);
      return wrapBetter(raw);
    } catch (err) {
      attempts.push(`better-sqlite3: ${err.message}`);
      if (config.dbDriver === 'better-sqlite3') {
        throw new Error(
          `DB_DRIVER=better-sqlite3 dipaksa tetap gagal. Coba DB_DRIVER=auto. Detail: ${err.message}`
        );
      }
    }
  }

  const wantNode = config.dbDriver === 'auto' || config.dbDriver === 'node:sqlite';
  if (wantNode) {
    try {
      // eslint-disable-next-line global-require
      const { DatabaseSync } = require('node:sqlite');
      const raw = new DatabaseSync(file);
      raw.exec('PRAGMA journal_mode = WAL');
      raw.exec('PRAGMA foreign_keys = ON');
      raw.exec('PRAGMA busy_timeout = 5000');
      if (logger) logger.info(`Database (node:sqlite bawaan Node): ${file}`);
      return wrapNodeSqlite(raw);
    } catch (err) {
      attempts.push(`node:sqlite: ${err.message}`);
    }
  }

  throw new Error(
    [
      'Tidak ada driver SQLite yang dapat dipakai. Pilihan perbaikan:',
      '  1) Gunakan Node.js >= 22.5 (pkg install nodejs-lts di Termux) untuk driver node:sqlite bawaan;',
      "  2) Atau pastikan better-sqlite3 dapat dikompilasi: pkg install clang python make binutils lalu 'npm rebuild better-sqlite3'.",
      'Detail kegagalan:',
      ...attempts,
    ].join('\n')
  );
}

/** Store: seluruh akses data aplikasi. */
function createStore(db, logger) {
  const log = logger || { warn: () => {}, error: () => {} };

  const store = {
    driver: db.driver,
    db,

    // ---- users ----
    upsertUser({ id, username, isAdmin }) {
      const now = Date.now();
      db.prepare(
        `INSERT INTO users (id, username, first_seen, last_seen, is_admin)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET username = excluded.username, last_seen = excluded.last_seen, is_admin = excluded.is_admin`
      ).run(id, username || null, now, now, isAdmin ? 1 : 0);
    },

    // ---- scans ----
    createScan({ jobId, ownerId, ownerUsername, mode, target, scopeRoot, options, labMode }) {
      const r = db
        .prepare(
          `INSERT INTO scans (job_id, owner_id, owner_username, mode, target, scope_root, status, lab_mode, options_json, created_at)
           VALUES (?, ?, ?, ?, ?, ?, 'QUEUED', ?, ?, ?)`
        )
        .run(
          jobId,
          ownerId,
          ownerUsername || null,
          mode,
          target,
          scopeRoot || '',
          labMode ? 1 : 0,
          JSON.stringify(options || {}),
          Date.now()
        );
      return Number(r.lastInsertRowid);
    },

    updateScan(id, fields) {
      const allowed = [
        'status',
        'stage_label',
        'progress_chat_id',
        'progress_message_id',
        'report_json_path',
        'report_txt_path',
        'report_html_path',
        'error',
        'started_at',
        'finished_at',
      ];
      const sets = [];
      const vals = [];
      for (const k of allowed) {
        if (Object.prototype.hasOwnProperty.call(fields, k)) {
          sets.push(`${k} = ?`);
          vals.push(fields[k]);
        }
      }
      if (!sets.length) return;
      vals.push(id);
      db.prepare(`UPDATE scans SET ${sets.join(', ')} WHERE id = ?`).run(...vals);
    },

    getScanByJobId(jobId) {
      return db.prepare('SELECT * FROM scans WHERE job_id = ?').get(jobId) || null;
    },
    getScan(id) {
      return db.prepare('SELECT * FROM scans WHERE id = ?').get(id) || null;
    },
    listScans({ ownerId, limit, offset } = {}) {
      const lim = Math.min(limit || 10, 50);
      if (ownerId) {
        return db
          .prepare('SELECT * FROM scans WHERE owner_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?')
          .all(ownerId, lim, offset || 0);
      }
      return db.prepare('SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?').all(lim, offset || 0);
    },
    lastFinishedScan(ownerId) {
      return (
        db
          .prepare(
            `SELECT * FROM scans WHERE owner_id = ? AND status IN ('COMPLETED','PARTIAL')
             ORDER BY finished_at DESC LIMIT 1`
          )
          .get(ownerId) || null
      );
    },
    countScansByStatus() {
      return db.prepare('SELECT status, COUNT(*) AS n FROM scans GROUP BY status').all();
    },
    countScansByOwner(ownerId) {
      return db.prepare('SELECT COUNT(*) AS n FROM scans WHERE owner_id = ?').get(ownerId).n;
    },

    /** Tandai scan RUNNING dari proses sebelumnya sebagai FAILED (recovery restart). */
    markStaleRunningAsFailed(message) {
      const now = Date.now();
      const rows = db.prepare("SELECT id FROM scans WHERE status IN ('RUNNING','QUEUED')").all();
      if (!rows.length) return 0;
      db.prepare(
        "UPDATE scans SET status = 'FAILED', error = ?, finished_at = ? WHERE status IN ('RUNNING','QUEUED')"
      ).run(message, now);
      return rows.length;
    },

    // ---- engine runs ----
    beginEngineRun(scanId, engine, info) {
      const r = db
        .prepare(
          `INSERT INTO engine_runs (scan_id, engine, status, version, args_json, dropped_flags, started_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          scanId,
          engine,
          info.status || 'RUNNING',
          info.version || null,
          JSON.stringify(info.args || {}),
          info.droppedFlags ? JSON.stringify(info.droppedFlags) : null,
          Date.now()
        );
      return Number(r.lastInsertRowid);
    },
    finishEngineRun(runId, f) {
      db.prepare(
        `UPDATE engine_runs SET
           status = COALESCE(?, status),
           exit_code = COALESCE(?, exit_code),
           timed_out = COALESCE(?, timed_out),
           aborted = COALESCE(?, aborted),
           stdout_bytes = COALESCE(?, stdout_bytes),
           stderr_bytes = COALESCE(?, stderr_bytes),
           truncated = COALESCE(?, truncated),
           duration_ms = COALESCE(?, duration_ms),
           error = COALESCE(?, error),
           stderr_head = COALESCE(?, stderr_head),
           finished_at = ?
         WHERE id = ?`
      ).run(
        f.status || null,
        f.exitCode != null ? f.exitCode : null,
        f.timedOut ? 1 : f.timedOut === false ? 0 : null,
        f.aborted ? 1 : f.aborted === false ? 0 : null,
        f.stdoutBytes != null ? f.stdoutBytes : null,
        f.stderrBytes != null ? f.stderrBytes : null,
        f.truncated != null ? (f.truncated ? 1 : 0) : null,
        f.durationMs != null ? f.durationMs : null,
        f.error || null,
        f.stderrHead || null,
        Date.now(),
        runId
      );
    },
    listEngineRuns(scanId) {
      return db.prepare('SELECT * FROM engine_runs WHERE scan_id = ? ORDER BY id').all(scanId);
    },

    // ---- findings ----
    saveFinding(scanId, f) {
      const r = db
        .prepare(
          `INSERT OR IGNORE INTO findings
           (scan_id, engine, external_id, name, severity, owasp_id, target, evidence, reference, tags, classification, dedupe_hash, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          scanId,
          f.engine,
          f.externalId || null,
          f.name || null,
          String(f.severity || 'info').toLowerCase(),
          f.owaspId || null,
          f.target || null,
          f.evidence ? String(f.evidence).slice(0, 4000) : null,
          f.reference ? String(f.reference).slice(0, 1500) : null,
          f.tags ? String(f.tags).slice(0, 500) : null,
          f.classification || 'INDICATOR',
          f.dedupeHash,
          Date.now()
        );
      return r.changes === 1;
    },
    countFindings(scanId) {
      const r = db.prepare('SELECT COUNT(*) AS n FROM findings WHERE scan_id = ?').get(scanId);
      return Number(r.n);
    },
    findingsBySeverity(scanId) {
      return db
        .prepare('SELECT severity, COUNT(*) AS n FROM findings WHERE scan_id = ? GROUP BY severity')
        .all(scanId);
    },
    findingsByOwasp(scanId) {
      return db
        .prepare(
          `SELECT COALESCE(owasp_id, 'UNMAPPED') AS cat, COUNT(*) AS n
           FROM findings WHERE scan_id = ? GROUP BY cat`
        )
        .all(scanId);
    },
    listFindings(scanId, { limit, offset, minSeverity } = {}) {
      const lim = Math.min(limit || 20, 100);
      if (minSeverity != null) {
        return db
          .prepare('SELECT * FROM findings WHERE scan_id = ? ORDER BY id LIMIT ? OFFSET ?')
          .all(scanId, lim, offset || 0);
      }
      return db
        .prepare('SELECT * FROM findings WHERE scan_id = ? ORDER BY id LIMIT ? OFFSET ?')
        .all(scanId, lim, offset || 0);
    },
    topFindings(scanId, limit) {
      const order = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END";
      return db
        .prepare(`SELECT * FROM findings WHERE scan_id = ? ORDER BY ${order}, id LIMIT ?`)
        .all(scanId, Math.min(limit || 10, 50));
    },
    getFindingByDedupe(scanId, hash) {
      return db
        .prepare('SELECT * FROM findings WHERE scan_id = ? AND dedupe_hash = ? ORDER BY id DESC LIMIT 1')
        .get(scanId, hash);
    },
    getFindingById(id) {
      return db.prepare('SELECT * FROM findings WHERE id = ?').get(id);
    },

    // ---- keputusan scope/guard ----
    saveDecision(scanId, d) {
      db.prepare(
        'INSERT INTO scope_decisions (scan_id, ts, decision, host, ip, reason, stage) VALUES (?, ?, ?, ?, ?, ?, ?)'
      ).run(scanId, d.ts || Date.now(), d.decision, d.host || null, d.ip || null, d.reason || '', d.stage || null);
    },
    countDeniedDecisions(scanId) {
      const r = db
        .prepare("SELECT COUNT(*) AS n FROM scope_decisions WHERE scan_id = ? AND decision = 'DENY'")
        .get(scanId);
      return Number(r.n);
    },

    // ---- subdomain / dns / hosts / endpoints ----
    saveSubdomain(scanId, host, source) {
      const r = db
        .prepare('INSERT OR IGNORE INTO subdomains (scan_id, host, source) VALUES (?, ?, ?)')
        .run(scanId, host.slice(0, 253), (source || '').slice(0, 80));
      return r.changes === 1;
    },
    countSubdomains(scanId) {
      return Number(db.prepare('SELECT COUNT(*) AS n FROM subdomains WHERE scan_id = ?').get(scanId).n);
    },
    listSubdomains(scanId, limit) {
      const rows = db
        .prepare('SELECT host, source FROM subdomains WHERE scan_id = ? ORDER BY host LIMIT ?')
        .all(scanId, Math.min(Math.max(Number(limit) || 300, 1), 2000));
      return rows.map((r) => ({ host: r.host, source: r.source }));
    },
    saveDnsRecord(scanId, host, rtype, value) {
      db.prepare(
        'INSERT OR IGNORE INTO dns_records (scan_id, host, rtype, value) VALUES (?, ?, ?, ?)'
      ).run(scanId, host.slice(0, 253), rtype, value.slice(0, 100));
    },
    saveHost(scanId, h) {
      db.prepare(
        `INSERT OR IGNORE INTO hosts (scan_id, url, host, status_code, title, webserver, tech, content_length)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        scanId,
        h.url.slice(0, 1000),
        h.host || null,
        h.statusCode != null ? h.statusCode : null,
        h.title ? String(h.title).slice(0, 300) : null,
        h.webserver ? String(h.webserver).slice(0, 200) : null,
        h.tech ? JSON.stringify(h.tech).slice(0, 500) : null,
        h.contentLength != null ? h.contentLength : null
      );
    },
    countHosts(scanId) {
      return Number(db.prepare('SELECT COUNT(*) AS n FROM hosts WHERE scan_id = ?').get(scanId).n);
    },
    saveEndpoint(scanId, url, method, source) {
      db.prepare(
        'INSERT OR IGNORE INTO endpoints (scan_id, url, method, source) VALUES (?, ?, ?, ?)'
      ).run(scanId, url.slice(0, 1000), (method || 'GET').slice(0, 10), (source || '').slice(0, 40));
    },
    countEndpoints(scanId) {
      return Number(db.prepare('SELECT COUNT(*) AS n FROM endpoints WHERE scan_id = ?').get(scanId).n);
    },

    // ---- owasp coverage ----
    saveCoverage(scanId, rows) {
      db.transaction(() => {
        for (const r of rows) {
          db.prepare(
            `INSERT INTO owasp_coverage (scan_id, category, status, checks_json, findings_count, notes)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(scan_id, category) DO UPDATE SET
               status = excluded.status, checks_json = excluded.checks_json,
               findings_count = excluded.findings_count, notes = excluded.notes`
          ).run(scanId, r.category, r.status, JSON.stringify(r.checks || []), r.findings || 0, r.notes || '');
        }
      });
    },
    getCoverage(scanId) {
      return db.prepare('SELECT * FROM owasp_coverage WHERE scan_id = ? ORDER BY category').all(scanId);
    },

    // ---- error log ----
    saveError(scanId, engine, message) {
      db.prepare('INSERT INTO error_log (scan_id, engine, message, ts) VALUES (?, ?, ?, ?)').run(
        scanId,
        engine || null,
        String(message || '').slice(0, 1000),
        Date.now()
      );
    },

    // ---- statistik ----
    globalStats() {
      const byStatus = {};
      for (const r of store.countScansByStatus()) byStatus[r.status] = Number(r.n);
      const sevRows = db.prepare('SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity').all();
      const bySeverity = {};
      for (const r of sevRows) bySeverity[r.severity] = Number(r.n);
      const usersRow = db.prepare('SELECT COUNT(*) AS n FROM users').get();
      return { scansByStatus: byStatus, findingsBySeverity: bySeverity, users: Number(usersRow.n) };
    },
  };

  return store;
}

module.exports = { openDatabase, createStore };
