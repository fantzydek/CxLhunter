'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const {
  normalizeDomain,
  isValidDomain,
  isSubdomainOf,
  parseUrlSafe,
  sha16,
  sanitizeFilename,
  sanitizeText,
  maskSecrets,
  clampInt,
} = require('../src/utils/validation');
const { ScopeValidator } = require('../src/scope/validator');

function makeValidator(extra) {
  return new ScopeValidator({
    allowedTargets: ['example.com'],
    allowedPorts: ['80', '443', '8080', '8443'],
    allowedProtocols: ['https', 'http'],
    labMode: false,
    labTargets: [],
    ...extra,
  });
}

test('normalizeDomain: skema/path/port dibuang, lowercase', () => {
  assert.strictEqual(normalizeDomain('https://Sub.Example.com/path?q=1'), 'sub.example.com');
  assert.strictEqual(normalizeDomain('http://EXAMPLE.com:8080'), 'example.com');
  assert.strictEqual(normalizeDomain('example.com.'), 'example.com');
  assert.strictEqual(normalizeDomain('  api.example.com  '), 'api.example.com');
});

test('normalizeDomain: menolak userinfo, IP, label tidak valid', () => {
  assert.strictEqual(normalizeDomain('https://user:pass@example.com'), null);
  assert.strictEqual(normalizeDomain('192.168.1.1'), null);
  assert.strictEqual(normalizeDomain('bad_domain.com'), null);
  assert.strictEqual(normalizeDomain('localhost'), null);
  assert.strictEqual(normalizeDomain(''), null);
});

test('isSubdomainOf: root dan subdomain cocok, sibling tidak', () => {
  assert.ok(isSubdomainOf('example.com', 'example.com'));
  assert.ok(isSubdomainOf('a.b.example.com', 'example.com'));
  assert.ok(!isSubdomainOf('notexample.com', 'example.com'));
  assert.ok(!isSubdomainOf('example.com.evil.io', 'example.com'));
});

test('parseUrlSafe: protokol, port, userinfo, IP literal', () => {
  assert.ok(parseUrlSafe('https://sub.example.com/a').ok);
  assert.ok(!parseUrlSafe('ftp://sub.example.com').ok);
  assert.ok(!parseUrlSafe('file:///etc/passwd').ok);
  assert.ok(!parseUrlSafe('https://user:pass@sub.example.com').ok, 'userinfo harus ditolak');
  assert.ok(!parseUrlSafe('https://sub.example.com:22').ok, 'port 22 di luar allowlist');
  assert.ok(!parseUrlSafe('https://127.0.0.1').ok, 'IP literal ditolak default');
  const ip = parseUrlSafe('http://192.168.1.10', { allowIpLiteral: true, allowedPorts: ['80'] });
  assert.ok(ip.ok, 'IP literal boleh bila diizinkan (lab)');
});

test('ScopeValidator: target harus dalam root allowlist bila ALLOWED_TARGETS diisi', () => {
  const v = makeValidator();
  assert.deepStrictEqual(v.validateTargetInput('sub.example.com'), { ok: true, host: 'sub.example.com', root: 'example.com' });
  assert.ok(!v.validateTargetInput('example.org').ok);
  assert.ok(!v.validateTargetInput('192.168.1.1').ok);
});

test('ScopeValidator: ALLOWED_TARGETS kosong = mode terbuka (domain publik diterima)', () => {
  const empty = makeValidator({ allowedTargets: [] });
  assert.ok(empty.openMode, 'roots kosong => openMode aktif');
  const r = empty.validateTargetInput('any-public-domain.com');
  assert.ok(r.ok, 'scope kosong => domain publik valid diterima (mode terbuka)');
  assert.strictEqual(r.root, 'any-public-domain.com');
  assert.ok(!empty.validateTargetInput('192.168.1.1').ok, 'IP literal tetap ditolak di mode terbuka');
  assert.strictEqual(empty.hostInScope('anything.example.org'), 'anything.example.org');
  assert.strictEqual(empty.hostInScope('8.8.8.8'), null, 'IP tetap tidak otomatis dalam scope');
  assert.strictEqual(empty.hostInScope('localhost'), null);
});

test('ScopeValidator: validasi redirect keluar scope ditolak', () => {
  const v = makeValidator();
  const inScope = v.validateRedirect('https://sub.example.com/a', '/b');
  assert.ok(inScope.ok);
  const outScope = v.validateRedirect('https://sub.example.com/a', 'https://evil.io/steal');
  assert.ok(!outScope.ok, 'redirect lintas scope harus ditolak');
  const downgrade = v.validateRedirect('https://sub.example.com/a', 'http://other.example.com/');
  assert.ok(downgrade.ok, 'redirect http ke host dalam scope tetap dalam scope (flag turunan dicatat headerProbe)');
});

test('ScopeValidator: hostInScope menolak IP dan host aneh', () => {
  const v = makeValidator();
  assert.strictEqual(v.hostInScope('sub.example.com'), 'example.com');
  assert.strictEqual(v.hostInScope('8.8.8.8'), null);
  assert.strictEqual(v.hostInScope('bad_domain.com'), null);
  assert.strictEqual(v.hostInScope(null), null);
});

test('Lab mode: IP lab diizinkan hanya dalam allowlist', () => {
  const v = makeValidator({ labMode: true, labTargets: ['192.168.1.0/24'] });
  assert.ok(v.validateUrl('http://192.168.1.10/app', { allowIpLiteral: true }).ok);
  assert.ok(!v.validateUrl('http://10.0.0.5/app', { allowIpLiteral: true }).ok, 'IP di luar CIDR lab ditolak');
  const noLab = makeValidator({ labMode: false, labTargets: ['192.168.1.0/24'] });
  assert.ok(!noLab.validateUrl('http://192.168.1.10/app', { allowIpLiteral: true }).ok);
});

test('util: sha16 stabil, clampInt, sanitizeFilename, maskSecrets, sanitizeText', () => {
  assert.strictEqual(sha16('abc'), sha16('abc'));
  assert.notStrictEqual(sha16('abc'), sha16('abd'));
  assert.strictEqual(sha16('abc').length, 16);
  assert.strictEqual(clampInt('9', 1, 5, 3), 5);
  assert.strictEqual(clampInt('x', 1, 5, 3), 3);
  assert.strictEqual(sanitizeFilename('Job Report/2025!!'), 'job-report-2025');
  assert.strictEqual(
    maskSecrets('token 123456789:AAExxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx abcd'),
    'token [REDACTED_TOKEN] abcd'
  );
  assert.ok(maskSecrets('password=hunter2').includes('[REDACTED]'));
  assert.strictEqual(sanitizeText('a\u0000b\u001fc'), 'a b c');
});

test('parseUrlSafe: protokol-relative dan panjang berlebih ditangani', () => {
  assert.ok(!parseUrlSafe('//sub.example.com/path').ok, 'tanpa skema ditolak');
  assert.ok(!parseUrlSafe('a'.repeat(3000)).ok);
});
