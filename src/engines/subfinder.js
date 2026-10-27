'use strict';

/**
 * Subfinder (https://github.com/projectdiscovery/subfinder)
 * Enumerasi subdomain PASIF. Tanpa brute-force (flag -b tidak pernah dipakai).
 * Output JSON: {"host":"x.example.com","source":"crtsh"}
 */

const { Engine, EngineError } = require('./baseEngine');
const { sanitizeText } = require('../utils/validation');

/** Parser murni per baris JSON (untuk test & runtime). */
function parseLine(line) {
  if (!line || !line.trim()) return null;
  let obj;
  try {
    obj = JSON.parse(line);
  } catch (_) {
    return { malformed: true };
  }
  const host = obj.host || obj.hostname;
  if (!host || typeof host !== 'string') return null;
  return { host: host.toLowerCase(), source: sanitizeText(obj.source || '', 60) };
}

class SubfinderEngine extends Engine {
  constructor(config, logger) {
    super(
      'subfinder',
      {
        binary: 'subfinder',
        versionArgs: ['-version'],
        installHint: 'bash install.sh --tools-only  (atau: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)',
        homepage: 'https://github.com/projectdiscovery/subfinder',
      },
      config,
      logger
    );
  }

  async run(jobCtx, opts) {
    const options = opts || {};
    const host = options.target;
    const listFile = options.listFile || null;
    const wants = [
      { flag: '-json', required: true, aliases: ['-j'] },
      { flag: '-silent', required: false },
      { flag: '-d', value: host, when: !!host },
      { flag: '-l', value: listFile, when: !!listFile },
    ];
    const { used, dropped } = await this.resolveFlags(wants);
    const items = [];
    const stats = { lines: 0, parsed: 0, malformed: 0, dupes: 0 };
    const seen = new Set();
    const cap = this.config.maxSubdomains;

    const r = await this.runLines({
      args: used,
      jobCtx,
      timeoutMs: this.config.engineTimeouts.subfinder,
      onLine: (line) => {
        stats.lines++;
        const it = parseLine(line);
        if (!it) return;
        if (it.malformed) {
          stats.malformed++;
          return;
        }
        if (seen.has(it.host)) {
          stats.dupes++;
          return;
        }
        seen.add(it.host);
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
      error: r.ok ? null : `subfinder exit=${r.code} ${r.timedOut ? '(timeout)' : ''}`.trim(),
      droppedFlags: dropped,
      usedArgs: used,
    };
  }
}

module.exports = { SubfinderEngine, parseLine };
