'use strict';

/**
 * HTTPx (https://github.com/projectdiscovery/httpx)
 * Deteksi host HTTP/HTTPS aktif + metadata layanan.
 * PENTING: identitas binary diverifikasi agar bukan package Python bernama serupa.
 * Redirect TIDAK diikuti (kebijakan scope); lokasi redirect direkam untuk analisis.
 */

const { Engine, EngineError } = require('./baseEngine');
const { sanitizeText } = require('../utils/validation');

function firstOf(obj, keys) {
  for (const k of keys) {
    if (obj[k] !== undefined && obj[k] !== null) return obj[k];
  }
  return undefined;
}

/** Parser murni per baris JSON (menangani varian snake_case/kebab-case antar versi). */
function parseLine(line) {
  if (!line || !line.trim()) return null;
  let obj;
  try {
    obj = JSON.parse(line);
  } catch (_) {
    return { malformed: true };
  }
  const url = firstOf(obj, ['url', 'u']);
  if (!url) return null;
  const status = firstOf(obj, ['status_code', 'status-code', 'status']);
  const out = {
    url: String(url),
    host: sanitizeText(firstOf(obj, ['host', 'input']) || '', 253),
    statusCode: Number.isFinite(Number(status)) ? Number(status) : null,
    title: sanitizeText(firstOf(obj, ['title']) || '', 300),
    webserver: sanitizeText(firstOf(obj, ['webserver', 'server']) || '', 200),
    contentLength: Number(firstOf(obj, ['content_length', 'content-length', 'len'])) || null,
    tech: Array.isArray(obj.tech) ? obj.tech.map((t) => sanitizeText(t, 60)).slice(0, 20) : [],
    ips: Array.isArray(obj.a) ? obj.a.map(String).slice(0, 5) : [],
    location: sanitizeText(firstOf(obj, ['location']) || '', 500),
    time: sanitizeText(firstOf(obj, ['time']) || '', 40),
  };
  return out;
}

/** Verifikasi identitas ProjectDiscovery HTTPx (bukan python httpx/httpx-cli). */
function httpxIdentityCheck(out) {
  const s = String(out || '');
  if (/usage:|traceback|python/i.test(s)) return false;
  return /projectdiscovery|current version|^\s*v?\d+\.\d+/im.test(s);
}

class HttpxEngine extends Engine {
  constructor(config, logger) {
    super(
      'httpx',
      {
        binary: 'httpx',
        versionArgs: ['-version'],
        installHint: 'bash install.sh --tools-only  (atau: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest)',
        homepage: 'https://github.com/projectdiscovery/httpx',
        identityCheck: httpxIdentityCheck,
      },
      config,
      logger
    );
  }

  async run(jobCtx, opts) {
    const listFile = (opts || {}).listFile;
    if (!listFile) throw new EngineError('httpx membutuhkan listFile', 'BAD_ARGS');
    const wants = [
      { flag: '-l', value: listFile, required: true },
      { flag: '-json', required: true, aliases: ['-j'] },
      { flag: '-silent', required: false },
      { flag: '-status-code', required: false, aliases: ['-sc'] },
      { flag: '-title', required: false, aliases: ['-td'] },
      { flag: '-tech-detect', required: false },
      { flag: '-content-length', required: false, aliases: ['-cl'] },
      { flag: '-webserver', required: false, aliases: ['-ws'] },
      { flag: '-no-color', required: false, aliases: ['-nc'] },
      { flag: '-threads', value: this.config.httpxThreads, aliases: ['-t'] },
      { flag: '-rate-limit', value: this.config.httpxRateLimit, aliases: ['-rl'] },
      { flag: '-timeout', value: 8 },
      { flag: '-retries', value: 1 },
    ];
    const { used, dropped } = await this.resolveFlags(wants);
    const items = [];
    const stats = { lines: 0, parsed: 0, malformed: 0 };
    const r = await this.runLines({
      args: used,
      jobCtx,
      timeoutMs: this.config.engineTimeouts.httpx,
      onLine: (line) => {
        stats.lines++;
        const it = parseLine(line);
        if (!it || it.malformed) {
          if (it && it.malformed) stats.malformed++;
          return;
        }
        stats.parsed++;
        items.push(it);
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
      stats,
      exitCode: r.code,
      timedOut: r.timedOut,
      truncated: r.truncated,
      stderrHead: (r.stderr || '').slice(0, 1500),
      error: r.ok ? null : `httpx exit=${r.code} ${r.timedOut ? '(timeout)' : ''}`.trim(),
      droppedFlags: dropped,
      usedArgs: used,
    };
  }
}

module.exports = { HttpxEngine, parseLine, httpxIdentityCheck };
