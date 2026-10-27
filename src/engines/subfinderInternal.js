'use strict';

/**
 * SubfinderInternalEngine - enumerasi subdomain pasif internal (pengganti subfinder).
 * Sumber: Certificate Transparency (crt.sh) + brute wordlist ringan via DNS.
 * 100% pasif terhadap target (hanya query DNS resolver & API publik crt.sh).
 */

const { enumerateSubdomains } = require('./internal/dnsKit');

class SubfinderInternalEngine {
  constructor(config, logger) {
    this.name = 'subfinder-internal';
    this.builtIn = true;
    this.config = config;
    this.logger = logger && logger.child ? logger.child('subfinder-internal') : logger;
  }

  async checkInstalled() {
    return { status: 'AVAILABLE', version: `node-${process.version} (internal)`, binaryPath: 'internal', reason: 'OK', error: null };
  }

  /** opts: { target: 'domain.com', useBrute?: bool } */
  async run(jobCtx, opts) {
    const o = opts || {};
    const target = String(o.target || '').toLowerCase();
    // Target IP literal (lab mode): enumerasi subdomain tidak berlaku - selesai tanpa temuan
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(target) || target.includes(':')) {
      return {
        status: 'COMPLETED',
        items: [],
        stats: { found: 0, note: 'enumerasi subdomain tidak berlaku untuk target IP literal' },
        exitCode: 0,
        timedOut: false,
        truncated: false,
        stderrHead: '',
        error: null,
        droppedFlags: [],
        usedArgs: [`target=${target}`, 'skipped=ip-literal'],
      };
    }
    if (!target || !/^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/.test(target)) {
      return { status: 'FAILED', items: [], stats: {}, exitCode: 1, timedOut: false, truncated: false, stderrHead: 'target tidak valid', error: 'target tidak valid', droppedFlags: [], usedArgs: [] };
    }
    const useBrute = o.useBrute !== false;
    const max = this.config.maxSubdomains || 200;
    const deadline = Date.now() + ((this.config.engineTimeouts && this.config.engineTimeouts.subfinder) || 120000);

    const result = await enumerateSubdomains(target, { useBrute, maxSubdomains: max });

    const items = result.names.map((host) => ({
      host,
      source: result.sources.crtSh ? 'crt.sh' : 'brute-dns',
    }));

    return {
      status: result.names.length || result.sources.crtSh ? 'COMPLETED' : 'FAILED',
      items,
      stats: { found: items.length, brute: result.sources.brute, crtSh: result.sources.crtSh, note: result.error || '' },
      exitCode: 0,
      timedOut: Date.now() > deadline,
      truncated: false,
      stderrHead: result.error || '',
      error: result.names.length ? null : result.error,
      droppedFlags: [],
      usedArgs: [`target=${target}`, `brute=${useBrute}`],
    };
  }
}

module.exports = { SubfinderInternalEngine };
