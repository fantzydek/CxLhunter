'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const { NetworkGuard, isPrivateIp, classifyReservedIp } = require('../src/scope/networkGuard');

const silentLogger = { debug() {}, info() {}, warn() {}, error() {} };

function makeGuard(overrides) {
  return new NetworkGuard({
    config: { labMode: false, labTargets: [], allowedTargets: ['example.com'] },
    store: null,
    logger: silentLogger,
    ...overrides,
  });
}

test('isPrivateIp: IPv4 kategori khusus', () => {
  const privates = [
    '0.0.0.1', '10.1.2.3', '100.64.0.1', '127.0.0.1', '169.254.1.1', '172.16.5.4', '172.31.255.255',
    '192.0.2.1', '192.168.1.1', '198.18.0.1', '198.51.100.7', '203.0.113.9', '224.0.0.1', '240.0.0.1',
    '255.255.255.255',
  ];
  for (const ip of privates) assert.ok(isPrivateIp(ip), `${ip} harus private/reserved`);
  const publics = ['8.8.8.8', '172.32.0.1', '1.1.1.1', '100.128.0.1', '9.9.9.9'];
  for (const ip of publics) assert.ok(!isPrivateIp(ip), `${ip} harus publik`);
});

test('isPrivateIp: IPv6 kategori khusus', () => {
  const privates = ['::', '::1', 'fc00::1', 'fd12:3456::1', 'fe80::1', 'ff02::1', '2001:db8::1', '::ffff:10.0.0.1', '::ffff:127.0.0.1', '64:ff9b::808:808'];
  for (const ip of privates) assert.ok(isPrivateIp(ip), `${ip} harus private/reserved`);
  const publics = ['2606:4700::1111', '2001:4860:4860::8888', '2400:cb00::1'];
  for (const ip of publics) assert.ok(!isPrivateIp(ip), `${ip} harus publik`);
  assert.strictEqual(classifyReservedIp('bukan-ip').category, 'invalid');
});

test('guard: IP literal private ditolak, publik diizinkan', () => {
  const g = makeGuard();
  assert.ok(!g.checkIp('10.0.0.1').allowed);
  assert.ok(!g.checkIp('127.0.0.1').allowed);
  assert.ok(!g.checkIp('169.254.169.254').allowed, 'metadata endpoint harus ditolak');
  assert.ok(g.checkIp('93.184.216.34').allowed);
  assert.ok(!g.checkIp('bukan-ip').allowed);
});

test('guard: resolusi private => DENY (domain yang mengarah ke internal)', async () => {
  const g = makeGuard({ resolveFn: async () => ({ ips: ['192.168.1.10'], errors: [] }) });
  const r = await g.checkHost('internal.example.com', { scanId: 1, stage: 'test' });
  assert.ok(!r.allowed);
  assert.ok(/internal|private/i.test(r.reason));
});

test('guard: resolusi campuran (satu private) => DENY', async () => {
  const g = makeGuard({ resolveFn: async () => ({ ips: ['93.184.216.34', '192.168.0.1'], errors: [] }) });
  const r = await g.checkHost('mixed.example.com');
  assert.ok(!r.allowed);
});

test('guard: resolusi publik => ALLOW dan cache', async () => {
  let calls = 0;
  const g = makeGuard({
    resolveFn: async () => {
      calls++;
      return { ips: ['93.184.216.34'], errors: [] };
    },
  });
  const r1 = await g.checkHost('ok.example.com');
  const r2 = await g.checkHost('ok.example.com');
  assert.ok(r1.allowed && r2.allowed);
  assert.strictEqual(calls, 1, 'pemanggilan kedua dilayani cache (resolve hanya sekali)');
});

test('guard: DNS gagal => fail-closed DENY', async () => {
  const g = makeGuard({ resolveFn: async () => ({ ips: [], errors: ['ENOTFOUND'] }) });
  const r = await g.checkHost('nx.example.com');
  assert.ok(!r.allowed);
  assert.ok(/fail-closed|resolusi/i.test(r.reason));

  const g2 = makeGuard({ resolveFn: async () => { throw new Error('resolver mati'); } });
  const r2 = await g2.checkHost('err.example.com');
  assert.ok(!r2.allowed);
});

test('guard: loopback hostname di-resolve ke 127.0.0.1 => DENY', async () => {
  const g = makeGuard({ resolveFn: async () => ({ ips: ['127.0.0.1'], errors: [] }) });
  const r = await g.checkHost('localhost.evil.com');
  assert.ok(!r.allowed);
});

test('guard: lab mode mengizinkan IP lab yang eksplisit', () => {
  const g = new NetworkGuard({
    config: { labMode: true, labTargets: ['192.168.1.0/24'], allowedTargets: [] },
    store: null,
    logger: silentLogger,
  });
  assert.ok(g.checkIp('192.168.1.5').allowed);
  assert.ok(!g.checkIp('192.168.2.5').allowed, 'CIDR lab hanya 192.168.1.0/24');
  assert.ok(!g.checkIp('10.0.0.5').allowed);
});

test('guard: filterHosts menyaring host yang tidak lolos', async () => {
  const g = makeGuard({
    resolveFn: async (host) =>
      host.startsWith('bad') ? { ips: ['10.0.0.1'], errors: [] } : { ips: ['8.8.8.8'], errors: [] },
  });
  const out = await g.filterHosts(['good.example.com', 'bad.example.com'], { stage: 'test' });
  assert.strictEqual(out.length, 1);
  assert.strictEqual(out[0].host, 'good.example.com');
});

test('guard: recheckHost mendeteksi perubahan ke alamat private (rebinding)', async () => {
  let first = true;
  const g = makeGuard({
    resolveFn: async () => {
      if (first) {
        first = false;
        return { ips: ['93.184.216.34'], errors: [] };
      }
      return { ips: ['127.0.0.1'], errors: [] }; // TOCTOU: berganti ke loopback
    },
  });
  await g.checkHost('rebind.example.com', { useCache: false });
  const re = await g.recheckHost('rebind.example.com', { scanId: 1, stage: 'recheck' });
  assert.ok(!re.allowed, 'recheck harus menolak setelah DNS berubah ke alamat internal');
  assert.ok(re.changed);
});
