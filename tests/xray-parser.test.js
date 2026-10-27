'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { parseXrayDocument, parseXrayOutputFile, normalizeXrayItem, normalizeSeverity } = require('../src/engines/xray');

test('parser xray: dokumen JSON array => temuan ternormalisasi + OWASP + evidence', () => {
  const doc = JSON.stringify([
    {
      create_time: '2026-01-01T00:00:00+07:00',
      vuln_id: 'poc-xss-echo-reflected',
      severity: 'high',
      source: 'basic-crawler',
      target: { url: 'https://target.example.com/search?q=<svg>', host: 'target.example.com', port: 443 },
      detail: {
        payload: '<svg onload=alert(1)>',
        description: 'Reflected XSS pada parameter q',
        response_header: { 'Content-Type': 'text/html' },
      },
    },
    {
      vuln_id: 'poc-cors-origin-reflection',
      severity: 'medium',
      target: { url: 'https://target.example.com/api' },
      detail: { payload: 'evil.example' },
    },
    { vuln_id: 'info-fingerprint', severity: 'nilai-aneh' },
  ]);
  const res = parseXrayDocument(doc);
  assert.strictEqual(res.kind, 'json-array');
  assert.strictEqual(res.items.length, 3);
  assert.strictEqual(res.malformed, 0);

  const xss = res.items.find((i) => i.externalId === 'poc-xss-echo-reflected');
  assert.strictEqual(xss.severity, 'high');
  assert.strictEqual(xss.classification, 'TEMPLATE_MATCH');
  assert.strictEqual(xss.engine, 'xray');
  assert.strictEqual(xss.target, 'https://target.example.com/search?q=<svg>');
  assert.strictEqual(xss.owaspId, 'A05', 'token xss => A05 Injection');
  const ev = JSON.parse(xss.evidence);
  assert.strictEqual(ev.payload, '<svg onload=alert(1)>');
  assert.ok(xss.name.includes('Reflected XSS'));

  const cors = res.items.find((i) => i.externalId === 'poc-cors-origin-reflection');
  assert.strictEqual(cors.severity, 'medium');
  assert.strictEqual(cors.owaspId, 'A02', 'token reflection tidak ada aturannya => A02 misconfig/exposure atau UNMAPPED yang dipetakan mapping.js');

  const info = res.items.find((i) => i.externalId === 'info-fingerprint');
  assert.strictEqual(info.severity, 'info', 'severity tidak dikenal => info');
});

test('parser xray: objek pembungkus {data:[...]} dan temuan tunggal', () => {
  const wrapper = JSON.stringify({
    data: [{ vuln_id: 'poc-ssrf-basic', severity: 'critical', target: { url: 'https://t.example/x' } }],
  });
  const res = parseXrayDocument(wrapper);
  assert.strictEqual(res.kind, 'json-object:data');
  assert.strictEqual(res.items.length, 1);
  assert.strictEqual(res.items[0].severity, 'critical');
  assert.strictEqual(res.items[0].owaspId, 'A05', 'token ssrf => A05');

  const single = JSON.stringify({ vuln_id: 'poc-open-redirect', severity: 'low', target: { url: 'https://t.example/r' } });
  const res2 = parseXrayDocument(single);
  assert.strictEqual(res2.kind, 'json-object:single');
  assert.strictEqual(res2.items.length, 1);
  assert.strictEqual(res2.items[0].externalId, 'poc-open-redirect');
});

test('parser xray: JSONL + baris rusak dihitung malformed', () => {
  const lines = [
    JSON.stringify({ vuln_id: 'poc-sqli-error', severity: 'high', target: { url: 'https://t.example/?id=1' } }),
    'ini bukan json {',
    JSON.stringify({ vuln_id: 'poc-xxe-file', severity: 'high', target: { url: 'https://t.example/xml' } }),
  ];
  const res = parseXrayDocument(lines.join('\n'));
  assert.strictEqual(res.kind, 'jsonl');
  assert.strictEqual(res.items.length, 2);
  assert.strictEqual(res.malformed, 1);
  const sqli = res.items.find((i) => i.externalId === 'poc-sqli-error');
  assert.strictEqual(sqli.owaspId, 'A05');
});

test('parser xray: dokumen kosong dan tidak dikenali => jujur tanpa temuan', () => {
  const empty = parseXrayDocument('   \n  ');
  assert.strictEqual(empty.items.length, 0);
  assert.strictEqual(empty.kind, 'kosong');
  assert.ok(empty.notes.length >= 1);

  const unknown = parseXrayDocument('<html><body>not json</body></html>');
  assert.strictEqual(unknown.items.length, 0);
  assert.strictEqual(unknown.kind, 'tidak-dikenali');
  assert.ok(unknown.notes[0].includes('bukan JSON/JSONL'));
});

test('parser xray: item tanpa identitas => null (terabaikan)', () => {
  assert.strictEqual(normalizeXrayItem(null), null);
  assert.strictEqual(normalizeXrayItem({}), null);
  assert.strictEqual(normalizeXrayItem({ detail: { foo: 1 } }), null);
});

test('parser xray: normalizeSeverity varian', () => {
  assert.strictEqual(normalizeSeverity('HIGH'), 'high');
  assert.strictEqual(normalizeSeverity('crit'), 'critical');
  assert.strictEqual(normalizeSeverity('moderate'), 'medium');
  assert.strictEqual(normalizeSeverity(undefined), 'info');
});

test('parser xray: parseXrayOutputFile dari disk (ada / tidak ada)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cxl-xray-'));
  try {
    const missing = parseXrayOutputFile(path.join(dir, 'tidak-ada.json'));
    assert.strictEqual(missing.kind, 'file-tidak-ada');
    assert.strictEqual(missing.items.length, 0);

    const file = path.join(dir, 'out.json');
    fs.writeFileSync(
      file,
      JSON.stringify([{ vuln_id: 'poc-rce-deserialization', severity: 'critical', target: { url: 'https://t.example/api' } }]),
      'utf8'
    );
    const parsed = parseXrayOutputFile(file);
    assert.strictEqual(parsed.items.length, 1);
    assert.strictEqual(parsed.items[0].externalId, 'poc-rce-deserialization');
    assert.strictEqual(parsed.items[0].severity, 'critical');
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (_) {
      /* diamkan */
    }
  }
});
