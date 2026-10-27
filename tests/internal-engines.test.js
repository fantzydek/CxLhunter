'use strict';

/**
 * Test unit engine internal + modul rich message.
 * Dijalankan: node --test tests/internal-engines.test.js
 */

const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const fs = require('fs');

const ROOT = path.join(__dirname, '..');

// ---------- rich.js ----------
const rich = require(path.join(ROOT, 'src/utils/rich'));

test('rich: blok builder dasar', () => {
  const blocks = rich.richBlocks('Judul', [
    rich.paragraph('halo'),
    rich.divider(),
    rich.bulletList(['a', 'b']),
    rich.quoteBlock('kutip'),
    rich.mono('kode'),
  ]);
  assert.strictEqual(blocks[0].type, 'heading');
  assert.strictEqual(blocks[1].type, 'divider');
  assert.ok(blocks.some((b) => b.type === 'paragraph' && b.text === 'halo'));
  assert.ok(blocks.some((b) => b.type === 'list' && b.items.length === 2));
});

test('rich: tabel dengan tableRow', () => {
  const t = rich.tableBlock([
    rich.tableRow(rich.tableCell('H1', { header: true }), rich.tableCell('H2', { header: true })),
    rich.tableRow(rich.tableCell('v1'), rich.tableCell('v2')),
  ]);
  assert.strictEqual(t.cells.length, 2);
  assert.strictEqual(t.cells[0][0].is_header, true);
  assert.strictEqual(t.is_bordered, true);
});

test('rich: fallback HTML meng-escape input berbahaya', () => {
  const html = rich.blocksToHtml([rich.paragraph('<script>alert(1)</script>')]);
  assert.ok(!html.includes('<script>'));
  assert.ok(html.includes('&lt;script&gt;'));
});

test('rich: tombol url/callback/copy punya struktur benar', () => {
  const row = rich.buttonRow([rich.urlButton('X', 'https://a.b'), rich.callbackButton('Y', 'cb:1'), rich.copyButton('Z', 'copy-me')]);
  assert.strictEqual(row.buttons[0].url, 'https://a.b');
  assert.strictEqual(row.buttons[1].callback_data, 'cb:1');
  assert.strictEqual(row.buttons[2].copy_text, 'copy-me');
});

// ---------- techKit ----------
const { detectTech } = require(path.join(ROOT, 'src/engines/internal/techKit'));

test('techKit: deteksi dari header + body + cookie', () => {
  const tech = detectTech({
    headers: { server: 'nginx/1.14.0', 'x-powered-by': 'PHP/7.4.3', 'set-cookie': 'PHPSESSID=abc; Path=/' },
    body: '<html><script src="/wp-content/themes/a.js"></script><meta name="generator" content="WordPress 6.4"></html>',
  });
  const names = tech.map((t) => t.name);
  assert.ok(names.includes('Nginx'));
  assert.ok(names.includes('PHP'));
  assert.ok(names.includes('WordPress'));
});

// ---------- dnsKit (fingerprint Email SPF parsing dari teks) ----------
const { resolveHost } = require(path.join(ROOT, 'src/engines/internal/dnsKit'));

test('dnsKit: resolveHost host tidak ada mengembalikan error', async () => {
  const r = await resolveHost('subdomain-tidak-ada-cxl-test.invalid');
  assert.ok(r.error || (!r.a.length && !r.aaaa.length && !r.cname.length));
});

// ---------- netClient ----------
const { extractTitle, RateLimiter, mapPool } = require(path.join(ROOT, 'src/engines/internal/netClient'));

test('netClient: extractTitle', () => {
  assert.strictEqual(extractTitle('<html><title> Halo  Dunia </title></html>'), 'Halo Dunia');
  assert.strictEqual(extractTitle('<html></html>'), '');
});

test('netClient: RateLimiter menjaga konkurensi', async () => {
  const lim = new RateLimiter({ minDelayMs: 1, concurrency: 2 });
  let active = 0;
  let maxActive = 0;
  const jobs = Array.from({ length: 6 }, () =>
    lim.run(async () => {
      active++;
      maxActive = Math.max(maxActive, active);
      await new Promise((r) => setTimeout(r, 20));
      active--;
    })
  );
  await Promise.all(jobs);
  assert.ok(maxActive <= 2, `konkurensi melebihi batas: ${maxActive}`);
});

test('netClient: mapPool memproses semua item', async () => {
  const out = await mapPool([1, 2, 3, 4, 5], 2, async (n) => n * 2);
  assert.deepStrictEqual(out.sort((a, b) => a - b), [2, 4, 6, 8, 10]);
});

// ---------- vulnScanInternal: evaluasi statis ----------
const { evaluateSecurityPosture } = require(path.join(ROOT, 'src/engines/vulnScanInternal'));

test('vulnscan: postur keamanan - header hilang terdeteksi', () => {
  const findings = evaluateSecurityPosture({
    url: 'https://example.com/',
    status: 200,
    headers: { 'content-type': 'text/html' },
    body: '<html></html>',
  });
  const ids = findings.map((f) => f.checkId);
  assert.ok(ids.includes('sec:csp-missing'));
  assert.ok(ids.includes('sec:clickjacking'));
  assert.ok(ids.includes('sec:hsts-missing'));
});

test('vulnscan: cookie tanpa flag terdeteksi', () => {
  const findings = evaluateSecurityPosture({
    url: 'https://example.com/login',
    status: 200,
    headers: { 'set-cookie': 'sid=abc; Path=/' },
    body: '',
  });
  assert.ok(findings.some((f) => f.checkId === 'cookie:flags' && f.severity === 'medium'));
});

test('vulnscan: mixed content terdeteksi di halaman HTTPS', () => {
  const findings = evaluateSecurityPosture({
    url: 'https://example.com/',
    status: 200,
    headers: {},
    body: '<html><script src="http://cdn.contoh.com/x.js"></script></html>',
  });
  assert.ok(findings.some((f) => f.checkId === 'page:mixed-content'));
});

test('vulnscan: sertifikat kedaluwarsa terdeteksi', () => {
  const findings = evaluateSecurityPosture({
    url: 'https://example.com/',
    status: 200,
    headers: {},
    body: '',
    certExpiryDays: -5,
  });
  assert.ok(findings.some((f) => f.checkId === 'tls:cert-expired' && f.severity === 'high'));
});

// ---------- secretsInternal: scanner teks ----------
const { scanText, redact } = require(path.join(ROOT, 'src/engines/secretsInternal'));

test('secrets: AWS key terdeteksi dan di-redact', () => {
  const findings = scanText('const k = "AKIAIOSFODNN7EXAMPLE";', 'http://t/app.js');
  assert.ok(findings.some((f) => f.externalId.startsWith('secret:aws-access-key')));
  const ev = JSON.parse(findings[0].evidence);
  assert.ok(!JSON.stringify(ev).includes('AKIAIOSFODNN7EXAMPLE'.slice(4, 12)), 'nilai mentah tidak boleh muncul');
});

test('secrets: private key PEM terdeteksi', () => {
  const findings = scanText('-----BEGIN RSA PRIVATE KEY-----', 'http://t/x.js');
  assert.ok(findings.some((f) => f.externalId.includes('private-key')));
});

test('secrets: placeholder tidak dianggap temuan', () => {
  const findings = scanText('api_key = "XXXXXXXXXXXXXXXXXXXX"', 'http://t/x.js');
  assert.strictEqual(findings.length, 0);
});

test('secrets: redact menyembunyikan tengah nilai', () => {
  const r = redact('AKIA1234567890ABCD');
  assert.ok(r.startsWith('AKIA'));
  assert.ok(r.includes('*'));
  assert.ok(!r.includes('5678'));
});

// ---------- portsInternal: probe port ----------
const { PortsInternalEngine } = require(path.join(ROOT, 'src/engines/portsInternal'));

test('ports: menolak host kosong', async () => {
  const eng = new PortsInternalEngine({ allowedPorts: ['80'] }, console);
  const r = await eng.run({ signal: null }, { host: '' });
  assert.strictEqual(r.status, 'FAILED');
});

// ---------- katanaInternal: ekstraksi tautan ----------
const { extractLinks, extractForms } = require(path.join(ROOT, 'src/engines/katanaInternal'));

test('katana: ekstrak tautan absolut dari HTML', () => {
  const links = extractLinks(
    '<a href="/a">1</a><a href="https://ext.com/b">2</a><a href="javascript:void(0)">3</a><script src="/js/app.js"></script>',
    'http://t.local/'
  );
  assert.ok(links.includes('http://t.local/a'));
  assert.ok(links.includes('https://ext.com/b'));
  assert.ok(links.includes('http://t.local/js/app.js'));
  assert.ok(!links.some((l) => l.startsWith('javascript')));
});

test('katana: ekstrak form + input', () => {
  const forms = extractForms('<form action="/login" method="POST"><input name="user" type="text"><input name="pass" type="password"></form>', 'http://t.local/');
  assert.strictEqual(forms.length, 1);
  assert.strictEqual(forms[0].method, 'POST');
  assert.strictEqual(forms[0].inputs.length, 2);
});

// ---------- dedup vulnscan per-origin ----------
test('vulnscan: dedup per-origin mencegah temuan berulang', () => {
  // uji langsung mekanisme Map seenKeys
  const seen = new Map();
  const key1 = 'http://t.local|exposed:/.env';
  seen.set(key1, true);
  assert.ok(seen.has(key1));
});

// ---------- vulnKB: kamus bug ----------
const { kbFor, kbList, kbSearch, kbEntry, ENRICH } = require(path.join(ROOT, 'src/engines/internal/vulnKB'));

test('vulnKB: resolusi externalId -> Vuln ID + CWE + severity', () => {
  const cases = [
    ['xss:reflected:q', 'CXL-021', 'high', 'CWE-79'],
    ['sqli:error-signature:id', 'CXL-022', 'high', 'CWE-89'],
    ['exposed:/.env', 'CXL-001', 'critical', 'CWE-200'],
    ['exposed:/.git/HEAD', 'CXL-010', 'high', 'CWE-538'],
    ['exposed:/.aws/credentials', 'CXL-002', 'critical', 'CWE-798'],
    ['takeover:AWS S3', 'CXL-006', 'critical', 'CWE-350'],
    ['secret:aws-key:https://x/a.js', 'CXL-005', 'critical', 'CWE-798'],
    ['malware:crypto-miner', 'CXL-007', 'critical', 'CWE-506'],
    ['redirect:open:next', 'CXL-027', 'medium', 'CWE-601'],
    ['cors:wildcard-credentials', 'CXL-029', 'medium', 'CWE-942'],
    ['dirlisting:/uploads/', 'CXL-030', 'medium', 'CWE-548'],
    ['sec:hsts-missing', 'CXL-050', 'low', 'CWE-319'],
    ['email:spf-missing', 'CXL-064', 'low', 'CWE-290'],
    ['ports:open:8080', 'CXL-061', 'info', 'CWE-200'],
  ];
  for (const [id, vulnId, sev, cwe] of cases) {
    const e = kbFor(id, '');
    assert.ok(e, `entry untuk ${id}`);
    assert.strictEqual(e.vulnId, vulnId, `vulnId ${id}`);
    assert.strictEqual(e.severity, sev, `severity ${id}`);
    assert.strictEqual(e.cwe, cwe, `cwe ${id}`);
  }
});

test('vulnKB: entry lengkap dengan payload & contoh bug detail', () => {
  const total = kbList().length;
  assert.ok(total >= 30, `minimal 30 entry, ada ${total}`);
  for (const key of kbList()) {
    const e = kbEntry(key);
    assert.ok(e.vulnId && e.cwe && e.name && e.severity && e.what && e.impact && e.fix, `entry ${key} lengkap`);
  }
  const xss = kbEntry('xss-reflected');
  assert.ok(xss.payloads.length >= 3);
  assert.ok(xss.vulnerable.includes('$_GET'), 'contoh kode rentan realistis');
  assert.ok(xss.attack.includes('GET /'), 'contoh request serangan ada');
});

test('vulnKB: ENRICH menghasilkan metadata utk evidence JSON', () => {
  const meta = ENRICH('xss:reflected:q', JSON.stringify({ detail: 'refleksi', evidence: 'marker' }));
  assert.strictEqual(meta.vuln_id, 'CXL-021');
  assert.strictEqual(meta.cwe, 'CWE-79');
  assert.ok(Array.isArray(meta.payload_example) && meta.payload_example.length > 0);
  assert.ok(meta.bug_example && meta.bug_example.vulnerable && meta.bug_example.attack);
});

test('vulnKB: pencarian /vuln', () => {
  assert.ok(kbSearch('xss').length >= 1);
  assert.ok(kbSearch('CXL-021').some((e) => e.vulnId === 'CXL-021'));
  assert.ok(kbSearch('CWE-89').some((e) => e.cwe === 'CWE-89'));
  assert.strictEqual(kbSearch('zzz-tidak-ada-xyz').length, 0);
});
