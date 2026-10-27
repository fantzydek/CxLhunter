'use strict';

/**
 * DnsxInternalEngine - resolusi & validasi DNS internal (pengganti dnsx).
 * Input: file list host (satu per baris). Output: item { host, a[], aaaa[], cname[] }.
 * Hanya query ke resolver DNS; tidak mengirim traffic HTTP ke target.
 */

const fs = require('fs');
const { mapPool } = require('./internal/netClient');
const { resolveHost } = require('./internal/dnsKit');

class DnsxInternalEngine {
  constructor(config, logger) {
    this.name = 'dnsx-internal';
    this.builtIn = true;
    this.config = config;
    this.logger = logger && logger.child ? logger.child('dnsx-internal') : logger;
  }

  async checkInstalled() {
    return { status: 'AVAILABLE', version: `node-${process.version} (internal)`, binaryPath: 'internal', reason: 'OK', error: null };
  }

  async run(jobCtx, opts) {
    const o = opts || {};
    let hosts = [];
    if (o.listFile) {
      hosts = fs.readFileSync(o.listFile, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean);
    } else if (Array.isArray(o.hosts)) {
      hosts = o.hosts.map(String);
    }
    hosts = [...new Set(hosts)].slice(0, this.config.maxResolveTargets || 200);

    const items = [];
    let failed = 0;
    // eslint-disable-next-line no-await-in-loop
    await mapPool(hosts, 10, async (host) => {
      if (jobCtx.signal && jobCtx.signal.aborted) return;
      try {
        const r = await resolveHost(host);
        if (r.error) {
          failed++;
          return;
        }
        items.push(r);
      } catch (_) {
        failed++;
      }
    });

    return {
      status: 'COMPLETED',
      items,
      stats: { resolved: items.length, failed },
      exitCode: 0,
      timedOut: false,
      truncated: false,
      stderrHead: '',
      error: null,
      droppedFlags: [],
      usedArgs: [`hosts=${hosts.length}`],
    };
  }
}

module.exports = { DnsxInternalEngine };
