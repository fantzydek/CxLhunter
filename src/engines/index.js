'use strict';

/**
 * Factory engine. Registry tunggal yang dipakai orchestrator, bot, dan self-test.
 * Setiap engine memiliki: name, checkInstalled(), run(jobCtx, opts), installHint, homepage.
 */

const { NucleiEngine } = require('./nuclei');
const { SubfinderEngine } = require('./subfinder');
const { DnsxEngine } = require('./dnsx');
const { HttpxEngine } = require('./httpx');
const { KatanaEngine } = require('./katana');
const { XrayEngine } = require('./xray');
const { HeaderProbeEngine } = require('./headerProbe');
const { SubfinderInternalEngine } = require('./subfinderInternal');
const { DnsxInternalEngine } = require('./dnsxInternal');
const { HttpxInternalEngine } = require('./httpxInternal');
const { KatanaInternalEngine } = require('./katanaInternal');
const { VulnScanInternalEngine } = require('./vulnScanInternal');
const { SecretsInternalEngine } = require('./secretsInternal');
const { PortsInternalEngine } = require('./portsInternal');

function createEngines(config, logger) {
  const list = [
    new NucleiEngine(config, logger),
    new SubfinderEngine(config, logger),
    new DnsxEngine(config, logger),
    new HttpxEngine(config, logger),
    new KatanaEngine(config, logger),
    new XrayEngine(config, logger),
    new HeaderProbeEngine(config, logger),
    // Engine INTERNAL (Node murni, selalu tersedia, pengganti otomatis binary eksternal)
    new SubfinderInternalEngine(config, logger),
    new DnsxInternalEngine(config, logger),
    new HttpxInternalEngine(config, logger),
    new KatanaInternalEngine(config, logger),
    new VulnScanInternalEngine(config, logger),
    new SecretsInternalEngine(config, logger),
    new PortsInternalEngine(config, logger),
  ];
  const map = {};
  for (const e of list) map[e.name] = e;
  return {
    list,
    map,
    get(name) {
      return map[name] || null;
    },
  };
}

module.exports = { createEngines };
