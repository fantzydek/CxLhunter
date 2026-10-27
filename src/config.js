'use strict';

const path = require('path');

function envList(v, fallback) {
  const out = String(v == null ? '' : v)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (!out.length && fallback !== undefined) return fallback;
  return out;
}

function envBool(v, dflt) {
  if (v === undefined || v === null || String(v).trim() === '') return !!dflt;
  return ['1', 'true', 'yes', 'on'].includes(String(v).trim().toLowerCase());
}

function envInt(v, dflt, min, max) {
  const n = parseInt(v, 10);
  if (!Number.isFinite(n)) return dflt;
  return Math.min(max, Math.max(min, n));
}

function buildConfig(env) {
  const e = env || process.env;
  const rootDir = e.CXL_ROOT || process.cwd();
  const abs = (p, dflt) => {
    const raw = p || dflt;
    return path.isAbsolute(raw) ? raw : path.join(rootDir, raw);
  };

  const cfg = {
    rootDir,
    botToken: String(e.BOT_TOKEN || '').trim(),
    adminIds: envList(e.ADMIN_IDS).map(Number).filter(Number.isFinite),
    allowedUsers: envList(e.ALLOWED_USERS).map(Number).filter(Number.isFinite),

    // Scope
    allowedTargets: envList(e.ALLOWED_TARGETS).map((s) => s.toLowerCase()),
    allowedPorts: envList(e.ALLOWED_PORTS, ['80', '443', '8080', '8443']),
    allowedProtocols: envList(e.ALLOWED_PROTOCOLS, ['https', 'http']).map((p) => p.toLowerCase()),
    labMode: envBool(e.LAB_MODE, false),
    labTargets: envList(e.LAB_ALLOWED_TARGETS).map((s) => s.toLowerCase()),

    // Database
    dbDriver: String(e.DB_DRIVER || 'auto').toLowerCase(),
    dbPath: abs(e.DB_PATH, 'data/cxl.db'),

    // Direktori kerja
    binDir: path.join(rootDir, 'bin'),
    tmpDir: abs(e.CXL_TMP_DIR, 'data/tmp'),
    logsDir: abs(e.CXL_LOGS_DIR, 'data/logs'),
    reportsDir: abs(e.CXL_REPORTS_DIR, 'reports'),

    // Antrean & limit
    maxConcurrentScans: envInt(e.MAX_CONCURRENT_SCANS, 1, 1, 3),
    queueMax: envInt(e.QUEUE_MAX, 5, 1, 50),
    maxScansPerUser: envInt(e.MAX_SCANS_PER_USER, 1, 1, 5),
    maxSubdomains: envInt(e.MAX_SUBDOMAINS, 200, 1, 5000),
    maxResolveTargets: envInt(e.MAX_RESOLVE_TARGETS, 200, 1, 5000),
    maxLiveHosts: envInt(e.MAX_LIVE_HOSTS, 50, 1, 1000),
    maxEndpoints: envInt(e.MAX_ENDPOINTS, 300, 1, 10000),
    maxOutputBytes: envInt(e.MAX_OUTPUT_BYTES, 32 * 1024 * 1024, 1024 * 1024, 256 * 1024 * 1024),

    engineTimeouts: {
      subfinder: envInt(e.ENGINE_TIMEOUT_SUBFINDER_MS, 120000, 10000, 3600000),
      dnsx: envInt(e.ENGINE_TIMEOUT_DNSX_MS, 120000, 10000, 3600000),
      httpx: envInt(e.ENGINE_TIMEOUT_HTTPX_MS, 180000, 10000, 3600000),
      katana: envInt(e.ENGINE_TIMEOUT_KATANA_MS, 300000, 10000, 3600000),
      nuclei: envInt(e.ENGINE_TIMEOUT_NUCLEI_MS, 1200000, 30000, 7200000),
      xray: envInt(e.ENGINE_TIMEOUT_XRAY_MS, 600000, 30000, 7200000),
      headerProbe: envInt(e.ENGINE_TIMEOUT_HEADERPROBE_MS, 180000, 10000, 3600000),
    },

    // Tuning engine
    httpxThreads: envInt(e.HTTPX_THREADS, 10, 1, 50),
    httpxRateLimit: envInt(e.HTTPX_RATE_LIMIT, 50, 1, 1000),
    katanaDepth: envInt(e.KATANA_DEPTH, 3, 1, 10),
    katanaConcurrency: envInt(envInt(e.KATANA_CONCURRENCY, 5, 1, 30), 5, 1, 30),
    katanaRateLimit: envInt(e.KATANA_RATE_LIMIT, 20, 1, 1000),
    nucleiConcurrency: envInt(e.NUCLEI_CONCURRENCY, 10, 1, 100),
    nucleiRateLimit: envInt(e.NUCLEI_RATE_LIMIT, 50, 1, 1000),
    nucleiSeverity: envList(e.NUCLEI_SEVERITY, ['low', 'medium', 'high', 'critical']),
    nucleiExcludeTags: envList(e.NUCLEI_EXCLUDE_TAGS, [
      'intrusive',
      'destructive',
      'bruteforce',
      'dos',
      'fuzz',
      'stealth',
    ]),
    nucleiOob: envBool(e.NUCLEI_ENABLE_OOB, false),
    nucleiUpdateTemplates: envBool(e.NUCLEI_UPDATE_TEMPLATES, false),
    exposedFilesCheck: envBool(e.EXPOSED_FILES_CHECK, true),

    enginePaths: {},
    userAgent: e.USER_AGENT || 'CxLScanner/1.4 (authorized security assessment)',
    logLevel: String(e.LOG_LEVEL || 'info').toLowerCase(),

    // Engine internal (Node murni)
    internalFallback: envBool(e.INTERNAL_FALLBACK, true),
    internalConcurrency: envInt(e.INTERNAL_CONCURRENCY, 4, 1, 16),
    internalMinDelayMs: envInt(e.INTERNAL_MIN_DELAY_MS, 120, 0, 5000),
    maxSecretsJsFiles: envInt(e.MAX_SECRETS_JS_FILES, 30, 1, 100),
    maxVulnScanUrls: envInt(e.MAX_VULN_SCAN_URLS, 25, 1, 200),
  };

  for (const name of ['nuclei', 'subfinder', 'dnsx', 'httpx', 'katana', 'xray']) {
    const key = name.toUpperCase() + '_PATH';
    if (e[key]) cfg.enginePaths[name] = e[key];
  }

  return cfg;
}

function loadConfig() {
  try {
    // eslint-disable-next-line global-require
    require('dotenv').config({ path: path.join(process.cwd(), '.env') });
  } catch (_) {
    // dotenv tidak tersedia; lanjut dengan process.env saja
  }
  return buildConfig(process.env);
}

module.exports = { buildConfig, loadConfig, envList, envBool, envInt };
