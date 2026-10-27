'use strict';

/**
 * Katana (https://github.com/projectdiscovery/katana)
 * Crawling URL dalam scope yang disetujui. Kedalaman, jumlah URL, rate, dan durasi dibatasi.
 * Tidak mengirim payload eksploitasi dan tidak mengubah data.
 * Kebijakan: flag -scope WAJIB didukung versi terinstal (pencegahan crawling keluar scope);
 * jika tidak, tahap digagalkan dengan aman. Semua URL hasil difilter ulang oleh scope validator.
 */

const { Engine, EngineError } = require('./baseEngine');
const { sanitizeText } = require('../utils/validation');

const URL_RE = /https?:\/\/[^\s"'<>()\\]+/g;

/** Parser murni per baris: JSON mode maupun fallback teks biasa. */
function parseLine(line) {
  if (!line || !line.trim()) return null;
  try {
    const obj = JSON.parse(line);
    const req = obj.request || obj;
    const url = req.url || req.endpoint || obj.url;
    if (!url) return null;
    const resp = obj.response || {};
    return {
      url: String(url),
      method: sanitizeText(req.method || 'GET', 10),
      statusCode: resp.status_code != null ? Number(resp.status_code) : null,
      source: sanitizeText(req.source || obj.source || 'crawl', 40),
    };
  } catch (_) {
    // fallback: baris teks biasa / format " [METHOD] url"
    const m = line.match(URL_RE);
    if (!m) return null;
    const url = m[0];
    const mm = line.match(/\[([A-Z]{3,6})\]/);
    return { url, method: mm ? mm[1] : 'GET', statusCode: null, source: 'crawl-plain' };
  }
}

class KatanaEngine extends Engine {
  constructor(config, logger) {
    super(
      'katana',
      {
        binary: 'katana',
        versionArgs: ['-version'],
        installHint: 'bash install.sh --tools-only  (atau: go install -v github.com/projectdiscovery/katana/cmd/katana@latest)',
        homepage: 'https://github.com/projectdiscovery/katana',
      },
      config,
      logger
    );
  }

  async run(jobCtx, opts) {
    const o = opts || {};
    const listFile = o.listFile;
    const scopeDomain = o.scope; // domain root untuk flag -scope
    if (!listFile || !scopeDomain) throw new EngineError('katana membutuhkan listFile dan scope', 'BAD_ARGS');

    const wants = [
      { flag: '-l', value: listFile, required: true },
      { flag: '-scope', value: scopeDomain, required: true, aliases: ['-sc'] },
      { flag: '-d', value: this.config.katanaDepth },
      { flag: '-c', value: this.config.katanaConcurrency },
      { flag: '-rl', value: this.config.katanaRateLimit },
      { flag: '-timeout', value: 10 },
      { flag: '-silent', required: false },
      { flag: '-no-color', required: false, aliases: ['-nc'] },
      { flag: '-json', required: false, aliases: ['-j'] },
      { flag: '-js-crawl', required: false },
    ];
    const { used, dropped } = await this.resolveFlags(wants);

    const items = [];
    const stats = { lines: 0, parsed: 0, malformed: 0, dupes: 0 };
    const seen = new Set();
    const cap = this.config.maxEndpoints;
    const r = await this.runLines({
      args: used,
      jobCtx,
      timeoutMs: this.config.engineTimeouts.katana,
      onLine: (line) => {
        stats.lines++;
        const it = parseLine(line);
        if (!it) return;
        if (!it.url) {
          stats.malformed++;
          return;
        }
        if (seen.has(it.url)) {
          stats.dupes++;
          return;
        }
        seen.add(it.url);
        stats.parsed++;
        if (items.length < cap) items.push(it);
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
      stats: { ...stats, capped: seen.size > cap },
      exitCode: r.code,
      timedOut: r.timedOut,
      truncated: r.truncated,
      stderrHead: (r.stderr || '').slice(0, 1500),
      error: r.ok ? null : `katana exit=${r.code} ${r.timedOut ? '(timeout)' : ''}`.trim(),
      droppedFlags: dropped,
      usedArgs: used,
    };
  }
}

module.exports = { KatanaEngine, parseLine };
