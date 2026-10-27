'use strict';

/**
 * PortsInternalEngine - pemindai port TCP internal (hanya port web umum).
 * Connect-scan sederhana dengan timeout ketat & konkurensi rendah.
 * Hanya memeriksa port yang DIIZINKAN konfigurasi (allowedPorts) + beberapa
 * port web umum; TIDAK melakukan fingerprint konten berbahaya.
 */

const net = require('net');
const { mapPool } = require('./internal/netClient');
const { extractTitle } = require('./internal/netClient');

const COMMON_WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 7001, 8008, 8081, 9090, 9443, 1337, 4000, 5001, 9000];

function probePort(host, port, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const done = (open) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ port, open });
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));
    socket.connect(port, host);
  });
}

class PortsInternalEngine {
  constructor(config, logger) {
    this.name = 'ports-internal';
    this.builtIn = true;
    this.config = config;
    this.logger = logger && logger.child ? logger.child('ports-internal') : logger;
  }

  async checkInstalled() {
    return { status: 'AVAILABLE', version: `node-${process.version} (internal)`, binaryPath: 'internal', reason: 'OK', error: null };
  }

  /** opts: { host, ips?: [ip], ports?: [n], timeoutMs?: n } */
  async run(jobCtx, opts) {
    const o = opts || {};
    const host = String(o.host || '');
    if (!host) {
      return { status: 'FAILED', items: [], stats: {}, exitCode: 1, timedOut: false, truncated: false, stderrHead: 'host kosong', error: 'host kosong', droppedFlags: [], usedArgs: [] };
    }
    let ports;
    if (o.ports && o.ports.length) {
      ports = o.ports.map(Number);
    } else {
      // UNION port web umum + port yang diizinkan konfigurasi (mis. 7777 di lab)
      ports = [...new Set([...COMMON_WEB_PORTS, ...((this.config.allowedPorts || []).map(Number))])];
    }
    ports = ports.filter((p) => p > 0 && p < 65536);

    const ips = (o.ips && o.ips.length ? o.ips : []).slice(0, 4);
    const targets = ips.length ? ips : [host];

    const openPorts = [];
    let checked = 0;
    for (const t of targets) {
      // eslint-disable-next-line no-await-in-loop
      const results = await mapPool(ports, 8, async (p) => {
        if (jobCtx.signal && jobCtx.signal.aborted) return { port: p, open: false };
        const r = await probePort(t, p, o.timeoutMs || 3000);
        return r;
      });
      checked += results.length;
      for (const r of results) {
        if (r.open) openPorts.push({ host: t === host ? host : `${host} (${t})`, ip: t, port: r.port });
      }
    }

    const items = openPorts.map((p) => ({
      engine: 'ports-internal',
      externalId: `ports:open:${p.port}`,
      name: `Port web terbuka: ${p.port}`,
      severity: [80, 443].includes(p.port) ? 'info' : 'low',
      target: `${p.host}:${p.port}`,
      evidence: JSON.stringify({ host: p.host, ip: p.ip, port: p.port, note: 'Port TCP merespons koneksi' }),
      reference: '',
      tags: 'ports:open',
      owaspId: 'A02',
      classification: 'INDICATOR',
    }));

    return {
      status: 'COMPLETED',
      items,
      stats: { checked, open: openPorts.length, ports: ports.length },
      exitCode: 0,
      timedOut: false,
      truncated: false,
      stderrHead: '',
      error: null,
      droppedFlags: [],
      usedArgs: [`host=${host}`, `ports=${ports.length}`, `ips=${targets.length}`],
    };
  }
}

module.exports = { PortsInternalEngine, COMMON_WEB_PORTS };
