'use strict';

/**
 * Nuclei (https://github.com/projectdiscovery/nuclei) - engine utama.
 * - Hanya template non-destruktif: tag intrusive/destructive/bruteforce/dos/fuzz/stealth
 *   DIEKSKUSI secara default (NUCLEI_EXCLUDE_TAGS).
 * - Flag diverifikasi terhadap --help versi terinstal (anti-flag-fiktif).
 * - Output JSONL diparsing defensif; hanya baris matcher-status=true dianggap temuan.
 * - Klasifikasi temuan: TEMPLATE_MATCH (kecocokan template, WAJIB diverifikasi manual
 *   sebelum dilaporkan ke program bug bounty).
 * - Update template HANYA bila NUCLEI_UPDATE_TEMPLATES=true (persetujuan eksplisit di .env).
 */

const { Engine, EngineError } = require('./baseEngine');
const { sanitizeText } = require('../utils/validation');
const { mapTagsToOwasp } = require('../owasp/mapping');

function pick(obj, keys) {
  for (const k of keys) {
    if (obj[k] !== undefined && obj[k] !== null) return obj[k];
  }
  return undefined;
}

/**
 * Parser murni satu baris JSONL Nuclei.
 * Hasil: { finding } | { skipped, reason } | { malformed: true } | null
 */
function parseLine(line) {
  if (!line || !line.trim()) return null;
  let obj;
  try {
    obj = JSON.parse(line);
  } catch (_) {
    return { malformed: true };
  }
  const info = obj.info && typeof obj.info === 'object' ? obj.info : {};
  const matcherStatus = pick(obj, ['matcher-status', 'matcher_status']);
  if (matcherStatus === false || matcherStatus === 'false') {
    return { skipped: true, reason: 'matcher-status=false' };
  }
  const templateId = sanitizeText(pick(obj, ['template-id', 'template_id', 'id']) || '', 200);
  const name = sanitizeText(info.name || templateId || 'tanpa-nama', 300);
  if (!templateId && !name) return null;
  const severityRaw = String(info.severity || 'info').toLowerCase();
  const severity = ['critical', 'high', 'medium', 'low', 'info'].includes(severityRaw) ? severityRaw : 'info';
  const tags = Array.isArray(info.tags) ? info.tags.map((t) => sanitizeText(t, 60)) : [];
  const matchedAt = sanitizeText(pick(obj, ['matched-at', 'matched_at']) || pick(obj, ['host', 'url']) || '', 1000);
  const extracted = Array.isArray(obj['extracted-results'])
    ? obj['extracted-results'].map((x) => sanitizeText(String(x), 300)).slice(0, 10)
    : [];
  const classification = info.classification && typeof info.classification === 'object' ? info.classification : {};
  const cve = classification['cve-id'] || classification.cve || null;
  const cwe = classification['cwe-id'] || classification.cwe || null;
  const refs = Array.isArray(info.reference)
    ? info.reference.map((x) => sanitizeText(String(x), 400)).slice(0, 3)
    : info.reference
      ? [sanitizeText(String(info.reference), 400)]
      : [];
  const curl = sanitizeText(pick(obj, ['curl-command', 'curl_command']) || '', 800);

  return {
    finding: {
      engine: 'nuclei',
      externalId: templateId,
      name,
      severity,
      target: matchedAt,
      evidence: JSON.stringify({
        matcher: true,
        extracted: extracted.length ? extracted : undefined,
        curl: curl || undefined,
        cve: cve || undefined,
        cwe: cwe || undefined,
        type: sanitizeText(pick(obj, ['type']) || '', 40) || undefined,
      }).slice(0, 3000),
      reference: refs.join(' , '),
      tags: tags.join(','),
      owaspId: mapTagsToOwasp(tags),
      classification: 'TEMPLATE_MATCH',
    },
  };
}

class NucleiEngine extends Engine {
  constructor(config, logger) {
    super(
      'nuclei',
      {
        binary: 'nuclei',
        versionArgs: ['-version'],
        installHint: 'bash install.sh --tools-only  (atau: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)',
        homepage: 'https://github.com/projectdiscovery/nuclei',
      },
      config,
      logger
    );
  }

  /** Update template dari sumber resmi - hanya dengan persetujuan konfigurasi. */
  async updateTemplates(jobCtx) {
    if (!this.config.nucleiUpdateTemplates) {
      return { ran: false, reason: 'NUCLEI_UPDATE_TEMPLATES=false (update butuh persetujuan eksplisit)' };
    }
    const { used } = await this.resolveFlags([{ flag: '-update-templates', aliases: ['-ut'], required: false }]);
    if (!used.length) return { ran: false, reason: 'Flag -update-templates tidak didukung versi ini' };
    const r = await this.runLines({ args: used, jobCtx, timeoutMs: 600000, onLine: () => {} });
    return { ran: true, ok: r.ok, exitCode: r.code };
  }

  async run(jobCtx, opts) {
    const o = opts || {};
    const listFile = o.listFile;
    if (!listFile) throw new EngineError('nuclei membutuhkan listFile target', 'BAD_ARGS');

    const upd = await this.updateTemplates(jobCtx);
    if (upd.ran && !upd.ok) {
      this.logger.warn(`Update template gagal (exit=${upd.exitCode}); melanjutkan dengan template lokal`);
    }

    const severity = (o.severity && o.severity.length ? o.severity : this.config.nucleiSeverity).join(',');
    const excludeTags = this.config.nucleiExcludeTags.join(',');
    const wants = [
      { flag: '-l', value: listFile, required: true },
      { flag: '-json', required: true, aliases: ['-j'] },
      { flag: '-severity', value: severity },
      { flag: '-etags', value: excludeTags, aliases: ['-exclude-tags'] },
      { flag: '-tags', value: o.tags && o.tags.length ? o.tags.join(',') : null, when: !!(o.tags && o.tags.length) },
      { flag: '-c', value: this.config.nucleiConcurrency },
      { flag: '-rl', value: this.config.nucleiRateLimit },
      { flag: '-timeout', value: 8 },
      { flag: '-retries', value: 1 },
      { flag: '-ni', when: !this.config.nucleiOob },
      { flag: '-nc', required: false, aliases: ['-no-color'] },
      { flag: '-silent', required: false },
    ];
    const { used, dropped } = await this.resolveFlags(wants);

    const items = [];
    const stats = { lines: 0, parsed: 0, skipped: 0, malformed: 0 };
    const r = await this.runLines({
      args: used,
      jobCtx,
      timeoutMs: this.config.engineTimeouts.nuclei,
      onLine: (line) => {
        stats.lines++;
        const res = parseLine(line);
        if (!res) return;
        if (res.malformed) {
          stats.malformed++;
          return;
        }
        if (res.skipped) {
          stats.skipped++;
          return;
        }
        stats.parsed++;
        items.push(res.finding);
      },
    });
    if (r.aborted) {
      const e = new EngineError('Dibatalkan pengguna', 'ABORTED');
      e.aborted = true;
      throw e;
    }
    return {
      status: r.ok || (r.code !== null && !r.timedOut && !r.spawnError) ? 'COMPLETED' : 'FAILED',
      items,
      stats: { ...stats, templateUpdate: upd },
      exitCode: r.code,
      timedOut: r.timedOut,
      truncated: r.truncated,
      stderrHead: (r.stderr || '').slice(0, 1500),
      error: r.ok ? null : `nuclei exit=${r.code} ${r.timedOut ? '(timeout)' : ''}`.trim(),
      droppedFlags: dropped,
      usedArgs: used,
    };
  }
}

module.exports = { NucleiEngine, parseLine };
