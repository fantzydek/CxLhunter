'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const { mapTagsToOwasp, plannedChecksForMode } = require('../src/owasp/mapping');
const { computeCoverage, coverageSummary } = require('../src/owasp/coverage');
const { OWASP_CATEGORIES, VALID_STATUSES } = require('../src/owasp/categories');
const { evaluateResponse } = require('../src/engines/headerProbe');

test('mapTagsToOwasp: aturan prioritas dan fallback UNMAPPED', () => {
  assert.strictEqual(mapTagsToOwasp(['sqli']), 'A05');
  assert.strictEqual(mapTagsToOwasp(['xss', 'tech']), 'A05');
  assert.strictEqual(mapTagsToOwasp(['default-login']), 'A07');
  assert.strictEqual(mapTagsToOwasp(['unauth', 'exposure']), 'A01');
  assert.strictEqual(mapTagsToOwasp(['ssl']), 'A04');
  assert.strictEqual(mapTagsToOwasp(['cve']), 'A03');
  assert.strictEqual(mapTagsToOwasp(['misconfig']), 'A02');
  assert.strictEqual(mapTagsToOwasp(['debug']), 'A10');
  assert.strictEqual(mapTagsToOwasp(['sri']), 'A08');
  assert.strictEqual(mapTagsToOwasp(['kategorisasi-tidak-dikenal']), 'UNMAPPED');
  assert.strictEqual(mapTagsToOwasp('sqli,debug'), 'A05', 'string csv diproses');
  assert.strictEqual(mapTagsToOwasp(['cve2023-injection']), 'A05', 'substring majemuk cocok');
});

test('semua kategori 2025 ada dan status valid', () => {
  const ids = OWASP_CATEGORIES.map((c) => c.id);
  assert.deepStrictEqual(ids, ['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10']);
  for (const c of OWASP_CATEGORIES) {
    assert.ok(c.name && c.desc && c.manualChecklist.length > 0, `${c.id} lengkap`);
  }
  assert.ok(VALID_STATUSES.includes('CHECKED_NO_FINDINGS'));
});

test('plannedChecksForMode: per mode', () => {
  assert.ok(plannedChecksForMode('quick', {}).includes('subdomain_enum'));
  assert.ok(!plannedChecksForMode('quick', {}).includes('nuclei_safe_templates'));
  assert.ok(plannedChecksForMode('full', {}).includes('nuclei_safe_templates'));
  const custom = plannedChecksForMode('custom', { engines: ['nuclei', 'headerProbe'] });
  assert.ok(custom.includes('nuclei_safe_templates') && custom.includes('header_security'));
  assert.ok(!custom.includes('subdomain_enum'));
});

test('computeCoverage: lengkap + temuan => CHECKED_FINDINGS; tanpa temuan => CHECKED_NO_FINDINGS', () => {
  const engineStatuses = {
    subfinder: { status: 'COMPLETED' },
    dnsx: { status: 'COMPLETED' },
    httpx: { status: 'COMPLETED' },
    katana: { status: 'COMPLETED' },
    headerProbe: { status: 'COMPLETED' },
    nuclei: { status: 'COMPLETED' },
  };
  const rows = computeCoverage({ mode: 'full', options: {}, engineStatuses, findingsByCat: { A02: 3 } });
  assert.strictEqual(rows.length, 10);
  const a02 = rows.find((r) => r.category === 'A02');
  assert.strictEqual(a02.status, 'CHECKED_FINDINGS');
  const a05 = rows.find((r) => r.category === 'A05');
  assert.strictEqual(a05.status, 'CHECKED_NO_FINDINGS');
  const a06 = rows.find((r) => r.category === 'A06');
  assert.strictEqual(a06.status, 'MANUAL_REQUIRED', 'A06 selalu manual');
  const a09 = rows.find((r) => r.category === 'A09');
  assert.strictEqual(a09.status, 'MANUAL_REQUIRED', 'A09 selalu manual');
  for (const r of rows) assert.ok(VALID_STATUSES.includes(r.status));
});

test('computeCoverage: engine tidak tersedia => ENGINE_UNAVAILABLE / PARTIAL', () => {
  const rows = computeCoverage({
    mode: 'owasp',
    options: {},
    engineStatuses: { headerProbe: { status: 'COMPLETED' }, nuclei: { status: 'UNAVAILABLE' } },
    findingsByCat: {},
  });
  const a05 = rows.find((r) => r.category === 'A05');
  assert.strictEqual(a05.status, 'ENGINE_UNAVAILABLE', 'A05 hanya lewat nuclei => ENGINE_UNAVAILABLE');
  const a02 = rows.find((r) => r.category === 'A02');
  assert.strictEqual(a02.status, 'PARTIAL', 'A02 punya headerProbe (ok) + nuclei (unavailable) => PARTIAL');
  const a10 = rows.find((r) => r.category === 'A10');
  assert.strictEqual(a10.status, 'PARTIAL');
});

test('computeCoverage: engine gagal (bukan unavailable) => PARTIAL, bukan sukses kosong', () => {
  const rows = computeCoverage({
    mode: 'nuclei',
    options: {},
    engineStatuses: { httpx: { status: 'COMPLETED' }, nuclei: { status: 'FAILED' } },
    findingsByCat: {},
  });
  const a05 = rows.find((r) => r.category === 'A05');
  assert.strictEqual(a05.status, 'PARTIAL');
});

test('computeCoverage: tanpa engine berjalan sama sekali => NOT_TESTED/MANUAL_REQUIRED', () => {
  const rows = computeCoverage({ mode: 'nuclei', options: {}, engineStatuses: {}, findingsByCat: {} });
  const statuses = rows.map((r) => r.status);
  assert.ok(statuses.includes('NOT_TESTED') || statuses.includes('MANUAL_REQUIRED'));
  const sum = coverageSummary(rows);
  assert.ok(Object.keys(sum).every((k) => VALID_STATUSES.includes(k)));
});

test('evaluateResponse (headerProbe): header hilang, cookie, server version, stack trace, redirect', () => {
  const ctx = {
    url: 'https://target.example.com/',
    status: 200,
    headers: {
      'Server': 'nginx/1.18.0',
      'Set-Cookie': ['sessionid=abc123; Path=/', 'pref=1; Secure; HttpOnly; SameSite=Strict'],
    },
    body: 'Traceback (most recent call last): File "app.py"',
    tlsProtocol: 'TLSv1.3',
    tlsError: null,
    redirectChain: [{ url: 'https://target.example.com/a', location: 'http://target.example.com/b', fromHttps: true }],
  };
  const findings = evaluateResponse(ctx);
  const ids = new Set(findings.map((f) => f.checkId));
  assert.ok(ids.has('header:strict-transport-security'), 'HSTS hilang terdeteksi');
  assert.ok(ids.has('header:content-security-policy'), 'CSP hilang terdeteksi');
  assert.ok(ids.has('cookie:flags'), 'cookie tanpa Secure/HttpOnly terdeteksi');
  assert.ok(ids.has('server:version'), 'versi server terungkap');
  assert.ok(ids.has('redirect:downgrade'), 'redirect turun ke HTTP terdeteksi');
  const stack = findings.find((f) => f.checkId.startsWith('page:stacktrace'));
  assert.ok(stack, 'traceback python terdeteksi');
  assert.strictEqual(stack.owasp, 'A10');

  // respons bersih => hanya temuan header default yang wajar, tidak ada stack/cookie
  const clean = evaluateResponse({
    url: 'https://t.example.com/',
    status: 200,
    headers: {
      'strict-transport-security': 'max-age=63072000',
      'content-security-policy': "default-src 'self'",
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'referrer-policy': 'no-referrer',
    },
    body: 'Welcome',
    tlsProtocol: 'TLSv1.3',
  });
  assert.strictEqual(clean.length, 0, 'konfigurasi baik menghasilkan nol temuan');
});

test('evaluateResponse: directory listing dan 5xx', () => {
  const listing = evaluateResponse({
    url: 'https://t.example.com/files/',
    status: 200,
    headers: {},
    body: '<html><title>Index of /files/</title></html>',
  });
  assert.ok(listing.some((f) => f.checkId === 'page:dirlisting' && f.owasp === 'A02'));
  const e500 = evaluateResponse({ url: 'https://t.example.com/x', status: 500, headers: {}, body: 'oops' });
  assert.ok(e500.some((f) => f.checkId === 'page:5xx' && f.owasp === 'A10'));
});
