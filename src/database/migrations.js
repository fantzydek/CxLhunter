'use strict';

/**
 * Migrasi skema SQLite. Idempotent: hanya menjalankan versi yang belum diterapkan,
 * di dalam transaksi, dan mencatat versi pada tabel meta.
 */

const MIGRATIONS = [
  {
    version: 1,
    name: 'initial-schema',
    sql: `
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id TEXT NOT NULL UNIQUE,
  owner_id INTEGER NOT NULL,
  owner_username TEXT,
  mode TEXT NOT NULL,
  target TEXT NOT NULL,
  scope_root TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'QUEUED',
  lab_mode INTEGER NOT NULL DEFAULT 0,
  options_json TEXT,
  stage_label TEXT,
  progress_chat_id INTEGER,
  progress_message_id INTEGER,
  report_json_path TEXT,
  report_txt_path TEXT,
  report_html_path TEXT,
  error TEXT,
  created_at INTEGER NOT NULL,
  started_at INTEGER,
  finished_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_scans_owner ON scans(owner_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);

CREATE TABLE IF NOT EXISTS engine_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL REFERENCES scans(id),
  engine TEXT NOT NULL,
  status TEXT NOT NULL,
  version TEXT,
  args_json TEXT,
  dropped_flags TEXT,
  exit_code INTEGER,
  timed_out INTEGER NOT NULL DEFAULT 0,
  aborted INTEGER NOT NULL DEFAULT 0,
  stdout_bytes INTEGER NOT NULL DEFAULT 0,
  stderr_bytes INTEGER NOT NULL DEFAULT 0,
  truncated INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER,
  error TEXT,
  stderr_head TEXT,
  started_at INTEGER,
  finished_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_engine_runs_scan ON engine_runs(scan_id);

CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL REFERENCES scans(id),
  engine TEXT NOT NULL,
  external_id TEXT,
  name TEXT,
  severity TEXT NOT NULL DEFAULT 'info',
  owasp_id TEXT,
  target TEXT,
  evidence TEXT,
  reference TEXT,
  tags TEXT,
  classification TEXT NOT NULL DEFAULT 'INDICATOR',
  dedupe_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(scan_id, dedupe_hash)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id, severity);

CREATE TABLE IF NOT EXISTS owasp_coverage (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL REFERENCES scans(id),
  category TEXT NOT NULL,
  status TEXT NOT NULL,
  checks_json TEXT,
  findings_count INTEGER NOT NULL DEFAULT 0,
  notes TEXT,
  UNIQUE(scan_id, category)
);

CREATE TABLE IF NOT EXISTS scope_decisions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER,
  ts INTEGER NOT NULL,
  decision TEXT NOT NULL,
  host TEXT,
  ip TEXT,
  reason TEXT NOT NULL,
  stage TEXT
);
CREATE INDEX IF NOT EXISTS idx_decisions_scan ON scope_decisions(scan_id);

CREATE TABLE IF NOT EXISTS subdomains (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL REFERENCES scans(id),
  host TEXT NOT NULL,
  source TEXT,
  UNIQUE(scan_id, host)
);

CREATE TABLE IF NOT EXISTS dns_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL REFERENCES scans(id),
  host TEXT NOT NULL,
  rtype TEXT NOT NULL,
  value TEXT NOT NULL,
  UNIQUE(scan_id, host, rtype, value)
);

CREATE TABLE IF NOT EXISTS hosts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL REFERENCES scans(id),
  url TEXT NOT NULL,
  host TEXT,
  status_code INTEGER,
  title TEXT,
  webserver TEXT,
  tech TEXT,
  content_length INTEGER,
  UNIQUE(scan_id, url)
);

CREATE TABLE IF NOT EXISTS endpoints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL REFERENCES scans(id),
  url TEXT NOT NULL,
  method TEXT,
  source TEXT,
  UNIQUE(scan_id, url, method)
);

CREATE TABLE IF NOT EXISTS error_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER,
  engine TEXT,
  message TEXT,
  ts INTEGER NOT NULL
);
`,
  },
  {
    version: 2,
    name: 'intelligent-vuln-reports',
    sql: `
CREATE TABLE IF NOT EXISTS vuln_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL REFERENCES scans(id),
  report_uid TEXT NOT NULL UNIQUE,
  vuln_type TEXT NOT NULL,
  template_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity_source TEXT NOT NULL,
  severity_assessed TEXT NOT NULL,
  confidence TEXT NOT NULL,
  validation_status TEXT NOT NULL,
  needs_review INTEGER NOT NULL DEFAULT 0,
  cwe TEXT,
  cve TEXT,
  owasp_id TEXT,
  source_finding_ids TEXT NOT NULL DEFAULT '[]',
  payload_json TEXT NOT NULL,
  review_status TEXT NOT NULL DEFAULT 'UNREVIEWED',
  review_note TEXT,
  reviewed_by INTEGER,
  reviewed_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vrep_scan ON vuln_reports(scan_id);
CREATE INDEX IF NOT EXISTS idx_vrep_status ON vuln_reports(scan_id, validation_status);

CREATE TABLE IF NOT EXISTS vuln_report_versions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  report_id INTEGER NOT NULL REFERENCES vuln_reports(id),
  version INTEGER NOT NULL,
  event TEXT NOT NULL,
  validation_status TEXT,
  payload_json TEXT NOT NULL,
  actor_id INTEGER,
  created_at INTEGER NOT NULL,
  UNIQUE(report_id, version)
);
`,
  },
];

function getSchemaVersion(db) {
  let row = null;
  try {
    row = db.prepare('SELECT value FROM meta WHERE key = ?').get('schema_version');
  } catch (_) {
    return 0;
  }
  return row ? parseInt(row.value, 10) || 0 : 0;
}

/** Jalankan migrasi yang belum diterapkan. Mengembalikan daftar versi yang dijalankan. */
function runMigrations(db, logger) {
  const applied = [];
  const current = getSchemaVersion(db);
  for (const m of MIGRATIONS) {
    if (m.version <= current) continue;
    db.transaction(() => {
      db.exec(m.sql);
      db.prepare(
        'INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
      ).run('schema_version', String(m.version));
    });
    applied.push(m.version);
    if (logger) logger.info(`Migrasi v${m.version} (${m.name}) diterapkan`);
  }
  return applied;
}

module.exports = { MIGRATIONS, runMigrations, getSchemaVersion };
