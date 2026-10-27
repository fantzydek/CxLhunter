'use strict';

/**
 * DNSx (https://github.com/projectdiscovery/dnsx)
 * Resolusi DNS & validasi hostname. Menyimpan record A/AAAA relevan.
 * Output JSON (dengan -resp): {"host":"x","ttl":300,"resolver":["1.1.1.1"],"a":["1.2.3.4"],"status":true}
 * atau bentuk nested {"host":"x","status":true,"data":{"a":[...],"ttl":300}} - parser menangani keduanya.
 */

const { Engine, EngineError } = require('./baseEngine');

/** Parser murni per baris JSON. */
function parseLine(line) {
  if (!line || !line.trim()) return null;
  let obj;
  try {
    obj = JSON.parse(line);
  } catch (_) {
    return { malformed: true };
  }
  const host = obj.host || obj.hostname;
  if (!host) return null;
  const data = obj.data || obj;
  const a = Array.isArray(data.a) ? data.a : data.a ? [data.a] : [];
  const aaaa = Array.isArray(data.aaaa) ? data.aaaa : data.aaaa ? [data.aaaa] : [];
  const cname = Array.isArray(data.cname) ? data.cname : data.cname ? [data.cname] : [];
  const status = data.status === true || data.status === 'true' || obj.status === true || obj.status === 'true';
  const ttl = data.ttl != null ? Number(data.ttl) : obj.ttl != null ? Number(obj.ttl) : null;
  return {
    host: String(host).toLowerCase(),
    a: a.map(String),
    aaaa: aaaa.map(String),
    cname: cname.map(String),
    status,
    ttl: Number.isFinite(ttl) ? ttl : null,
  };
}

class DnsxEngine extends Engine {
  constructor(config, logger) {
    super(
      'dnsx',
      {
        binary: 'dnsx',
        versionArgs: ['-version'],
        installHint: 'bash install.sh --tools-only  (atau: go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest)',
        homepage: 'https://github.com/projectdiscovery/dnsx',
      },
      config,
      logger
    );
  }

  async run(jobCtx, opts) {
    const listFile = (opts || {}).listFile;
    if (!listFile) throw new EngineError('dnsx membutuhkan listFile', 'BAD_ARGS');
    const wants = [
      { flag: '-l', value: listFile, required: true },
      { flag: '-json', required: true, aliases: ['-j'] },
      { flag: '-resp', required: true },
      { flag: '-a', required: false },
      { flag: '-aaaa', required: false },
      { flag: '-silent', required: false },
    ];
    const { used, dropped } = await this.resolveFlags(wants);
    const items = [];
    const stats = { lines: 0, parsed: 0, malformed: 0 };
    const r = await this.runLines({
      args: used,
      jobCtx,
      timeoutMs: this.config.engineTimeouts.dnsx,
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
      error: r.ok ? null : `dnsx exit=${r.code} ${r.timedOut ? '(timeout)' : ''}`.trim(),
      droppedFlags: dropped,
      usedArgs: used,
    };
  }
}

module.exports = { DnsxEngine, parseLine };
