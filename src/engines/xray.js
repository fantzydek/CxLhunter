'use strict';

/**
 * Xray (https://github.com/chaitin/xray) - engine TAMBAHAN, bukan dependensi wajib.
 * Realitas di Termux: rilis resmi Xray menyasar glibc (linux_amd64/linux_arm64); biner glibc
 * umumnya TIDAK berjalan natif di Termux (bionic). Adapter ini JUJUR:
 * - bila binary tidak ada     => UNAVAILABLE
 * - bila binary gagal dieksekusi => INCOMPATIBLE
 * - Xray membutuhkan lisensi (community license dari chaitin) untuk webscan; tanpa lisensi,
 *   scan akan gagal dan errornya direkam apa adanya (tidak disimulasikan).
 *
 * Parsing output (sejak v1.2.0): bila flag --json-output didukung dan file terbentuk,
 * dokumen JSON/JSONL resmi Xray diparsing menjadi temuan nyata. Tidak ada output simulasi.
 */

const fs = require('fs');
const { Engine, EngineError } = require('./baseEngine');
const { runProcess } = require('../utils/processRunner');
const { sanitizeText } = require('../utils/validation');
const { mapTagsToOwasp } = require('../owasp/mapping');

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

function normalizeSeverity(v) {
  const s = String(v == null ? '' : v).trim().toLowerCase();
  if (SEVERITIES.includes(s)) return s;
  // varian yang kadang dipakai: "crit", "hige" (typo), "warn", "moderate"
  if (s === 'crit' || s === 'critical-high') return 'critical';
  if (s === 'warn' || s === 'warning' || s === 'moderate' || s === 'med') return 'medium';
  return 'info';
}

function truncate(s, n) {
  const str = String(s == null ? '' : s);
  return str.length > n ? str.slice(0, n) + '...[dipotong]' : str;
}

/** Tokenisasi vuln_id/plugin menjadi kandidat tag untuk pemetaan OWASP. */
function tagsFromVulnId(vulnId, plugin, source) {
  const raw = [String(vulnId || ''), String(plugin || ''), String(source || '')]
    .join(' ')
    .toLowerCase();
  const tokens = raw
    .split(/[^a-z0-9]+/)
    .filter((t) => t.length >= 3 && t.length <= 40);
  return [...new Set(tokens)].slice(0, 20);
}

/** Ambil array kandidat dari objek JSON tingkat atas (varian struktur antar versi xray). */
function extractItemArray(obj) {
  if (Array.isArray(obj)) return { items: obj, kind: 'json-array' };
  if (obj && typeof obj === 'object') {
    for (const key of ['data', 'vulnerabilities', 'results', 'items', 'vulns']) {
      if (Array.isArray(obj[key])) return { items: obj[key], kind: `json-object:${key}` };
    }
    // satu objek temuan tunggal
    if (obj.vuln_id || obj.detail || obj.target || obj.severity) {
      return { items: [obj], kind: 'json-object:single' };
    }
    return { items: [], kind: 'json-object:kosong' };
  }
  return null;
}

function pick(obj, keys) {
  for (const k of keys) {
    if (obj && obj[k] !== undefined && obj[k] !== null) return obj[k];
  }
  return undefined;
}

/**
 * Normalisasi SATU item hasil xray menjadi bentuk temuan standar proyek.
 * Mengembalikan null bila item tidak dapat dinormalisasi (dihitung malformed/terabaikan).
 */
function normalizeXrayItem(it) {
  if (!it || typeof it !== 'object') return null;
  const detail = it.detail && typeof it.detail === 'object' ? it.detail : {};
  const target = it.target && typeof it.target === 'object' ? it.target : {};
  const vulnId = sanitizeText(String(pick(it, ['vuln_id', 'vulnId', 'id']) || ''), 200);
  const plugin = sanitizeText(String(pick(it, ['plugin', 'plugin_name', 'pluginName']) || ''), 120);
  const source = sanitizeText(String(pick(it, ['source']) || ''), 60);
  const targetUrl = sanitizeText(String(target.url || target.host || pick(it, ['url', 'target']) || ''), 500);
  const description = sanitizeText(String(pick(detail, ['description']) || ''), 300);
  const severity = normalizeSeverity(pick(it, ['severity']) || pick(detail, ['severity']));

  if (!vulnId && !description && !targetUrl) return null;

  const name = description || vulnId || plugin || 'temuan xray';
  const tags = tagsFromVulnId(vulnId, plugin, source);

  const evidenceParts = {
    vuln_id: vulnId || undefined,
    plugin: plugin || undefined,
    source: source || undefined,
    payload: detail.payload != null ? truncate(detail.payload, 500) : undefined,
    request: detail.request != null ? truncate(detail.request, 600) : undefined,
    response_header: detail.response_header
      ? truncate(typeof detail.response_header === 'string'
          ? detail.response_header
          : JSON.stringify(detail.response_header), 600)
      : undefined,
    description: description || undefined,
  };
  const evidence = JSON.stringify(evidenceParts).slice(0, 3000);

  return {
    engine: 'xray',
    externalId: vulnId || plugin || 'xray-finding',
    name: name.slice(0, 300),
    severity,
    target: targetUrl,
    evidence,
    reference: sanitizeText(String(pick(detail, ['reference', 'references']) || ''), 400),
    tags: tags.join(','),
    owaspId: mapTagsToOwasp(tags),
    // Deteksi xray berbasis POC/plugin => wajib verifikasi manual seperti temuan nuclei.
    classification: 'TEMPLATE_MATCH',
  };
}

/**
 * Parser murni dokumen output Xray (hasil --json-output).
 * Mendukung: array JSON, objek dengan key array (data/vulnerabilities/results/items/vulns),
 * satu objek temuan tunggal, dan JSONL per baris.
 * Hasil: { items: [temuan...], malformed: n, kind: 'json-array'|'jsonl'|..., notes: [string] }
 */
function parseXrayDocument(text) {
  const raw = String(text == null ? '' : text);
  const notes = [];
  if (!raw.trim()) {
    return { items: [], malformed: 0, kind: 'kosong', notes: ['file output kosong'] };
  }

  // 1) coba parse sebagai JSON utuh
  try {
    const obj = JSON.parse(raw);
    const ex = extractItemArray(obj);
    if (ex) {
      const items = [];
      let malformed = 0;
      for (const it of ex.items) {
        const f = normalizeXrayItem(it);
        if (f) items.push(f);
        else malformed++;
      }
      return { items, malformed, kind: ex.kind, notes };
    }
  } catch (_) {
    /* jatuh ke JSONL */
  }

  // 2) JSONL per baris
  const items = [];
  let malformed = 0;
  let lines = 0;
  for (const line of raw.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    lines++;
    try {
      const obj = JSON.parse(t);
      const ex = extractItemArray(obj);
      if (ex) {
        for (const it of ex.items) {
          const f = normalizeXrayItem(it);
          if (f) items.push(f);
          else malformed++;
        }
      } else {
        malformed++;
      }
    } catch (_) {
      malformed++;
    }
  }
  if (!lines) {
    return { items: [], malformed: 0, kind: 'tidak-dikenali', notes: ['dokumen bukan JSON/JSONL yang dikenali; tidak ada temuan diparsing'] };
  }
  if (!items.length && malformed === lines) {
    // semua baris gagal diparsing: jujur sebut tidak dikenali, jangan diklaim sebagai JSONL valid
    return {
      items: [],
      malformed,
      kind: 'tidak-dikenali',
      notes: ['dokumen bukan JSON/JSONL yang dikenali; tidak ada temuan diparsing'],
    };
  }
  notes.push(`dokumen diparsing sebagai JSONL (${lines} baris)`);
  return { items, malformed, kind: 'jsonl', notes };
}

/** Baca file output xray dari disk (dengan batas ukuran) dan parsing. */
function parseXrayOutputFile(filePath, maxBytes) {
  let stat = null;
  try {
    stat = fs.statSync(filePath);
  } catch (_) {
    return { items: [], malformed: 0, kind: 'file-tidak-ada', notes: ['file output JSON tidak ditemukan; tidak ada temuan diparsing'] };
  }
  let text = '';
  try {
    const size = Math.min(stat.size, maxBytes || 32 * 1024 * 1024);
    const fd = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(size);
    try {
      fs.readSync(fd, buf, 0, size, 0);
    } finally {
      fs.closeSync(fd);
    }
    text = buf.toString('utf8');
  } catch (e) {
    return { items: [], malformed: 0, kind: 'gagal-baca', notes: [`gagal membaca file output: ${e.message}`] };
  }
  const parsed = parseXrayDocument(text);
  if (stat.size > (maxBytes || 32 * 1024 * 1024)) {
    parsed.notes.push('file melebihi batas ukuran; hanya bagian awal yang diparsing');
  }
  return parsed;
}

class XrayEngine extends Engine {
  constructor(config, logger) {
    super(
      'xray',
      {
        binary: 'xray',
        // xray memakai subcommand "version", bukan flag -version
        versionArgs: ['version'],
        helpArgs: ['webscan', '--help'],
        installHint:
          'Unduh rilis resmi dari https://github.com/chaitin/xray/releases (linux_arm64) - CATATAN: umumnya INCOMPATIBLE natif di Termux (glibc vs bionic); pertimbangkan proot-distro atau jalankan di host terpisah.',
        homepage: 'https://github.com/chaitin/xray',
      },
      config,
      logger
    );
  }

  /**
   * Jalankan webscan terhadap SATU url dengan output JSON ke file (bila flag didukung),
   * selain itu HTML. Hasil diparsing dari output resmi Xray (bukan disimulasikan).
   */
  async run(jobCtx, opts) {
    const o = opts || {};
    const url = o.url;
    if (!url) throw new EngineError('xray membutuhkan url', 'BAD_ARGS');

    const wants = [
      { flag: '--url', value: url, required: true },
      { flag: '--json-output', value: o.outputFile, when: !!o.outputFile },
      { flag: '--html-output', value: o.htmlFile, when: !!o.htmlFile },
    ];
    const { used, dropped } = await this.resolveFlags(wants);
    const args = ['webscan', 'run', ...used];
    const jsonUsed = used.some((u) => String(u).startsWith('--json-output'));

    const r = await runProcess({
      cmd: this.resolveBinaryPath(),
      args,
      cwd: jobCtx.workDir,
      timeoutMs: this.config.engineTimeouts.xray,
      maxOutputBytes: this.config.maxOutputBytes,
      signal: jobCtx.signal,
    });
    if (r.aborted) {
      const e = new EngineError('Dibatalkan pengguna', 'ABORTED');
      e.aborted = true;
      throw e;
    }
    const combined = `${r.stdout || ''}\n${r.stderr || ''}`;
    const licenseProblem = /license|licen[cs]e (invalid|expired|not found)|激活/i.test(combined);

    // ---- parsing hasil nyata dari file output JSON ----
    let items = [];
    let parseNotes = [];
    let parsedMalformed = 0;
    let parsedKind = 'tidak-dihasilkan';
    if (jsonUsed && o.outputFile) {
      const parsed = parseXrayOutputFile(o.outputFile, this.config.maxOutputBytes);
      items = parsed.items;
      parsedMalformed = parsed.malformed;
      parsedKind = parsed.kind;
      parseNotes = parsed.notes || [];
    } else if (dropped.some((d) => d.flag === '--json-output')) {
      parseNotes.push('flag --json-output tidak didukung versi xray ini; hasil HTML saja direkam dan TIDAK diparsing otomatis');
    }

    let status = r.ok ? 'COMPLETED' : 'FAILED';
    let error = r.ok ? null : `xray exit=${r.code} ${r.timedOut ? '(timeout)' : ''}`.trim();
    if (licenseProblem) {
      status = 'FAILED';
      error = 'Xray membutuhkan lisensi aktif (community license chaitin). Jalankan aktivasi secara manual lalu ulangi.';
    }
    return {
      status,
      items,
      stats: {
        parsed: items.length,
        malformed: parsedMalformed,
        parseKind: parsedKind,
        notes: parseNotes,
        htmlReport: o.htmlFile && fs.existsSync(o.htmlFile) ? o.htmlFile : null,
      },
      exitCode: r.code,
      timedOut: r.timedOut,
      truncated: r.truncated,
      stderrHead: sanitizeText((r.stderr || '').slice(0, 1500)),
      error,
      droppedFlags: dropped,
      usedArgs: args,
    };
  }
}

module.exports = { XrayEngine, parseXrayDocument, parseXrayOutputFile, normalizeXrayItem, normalizeSeverity };
