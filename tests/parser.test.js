'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const nuclei = require('../src/engines/nuclei');
const httpx = require('../src/engines/httpx');
const katana = require('../src/engines/katana');
const subfinder = require('../src/engines/subfinder');
const dnsx = require('../src/engines/dnsx');

const FIX = (name) => fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8');

function readLines(name) {
  return FIX(name)
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
}

test('parser nuclei: temuan, skip matcher-status=false, malformed terhitung', () => {
  const lines = readLines('nuclei-sample.jsonl');
  const findings = [];
  let skipped = 0;
  let malformed = 0;
  for (const l of lines) {
    const r = nuclei.parseLine(l);
    if (!r) continue;
    if (r.malformed) malformed++;
    else if (r.skipped) skipped++;
    else findings.push(r.finding);
  }
  assert.strictEqual(findings.length, 5, '5 temuan valid (termasuk varian underscore)');
  assert.strictEqual(skipped, 1);
  assert.strictEqual(malformed, 1);
  const sqli = findings.find((f) => f.externalId === 'sqli-error-based');
  assert.strictEqual(sqli.severity, 'high');
  assert.strictEqual(sqli.owaspId, 'A05', 'tag sqli => A05 Injection');
  assert.strictEqual(sqli.classification, 'TEMPLATE_MATCH');
  const actuator = findings.find((f) => f.externalId === 'spring-boot-actuator');
  assert.strictEqual(actuator.owaspId, 'A02');
  const defaultLogin = findings.find((f) => f.externalId === 'default-login');
  assert.strictEqual(defaultLogin.owaspId, 'A07', 'tag default-login => A07');
  const underscore = findings.find((f) => f.externalId === 'with-underscore');
  assert.ok(underscore, 'varian matcher_status/matched_at didukung');
});

test('parser nuclei: baris tanpa matcher-status tetap dianggap temuan (versi lama)', () => {
  const r = nuclei.parseLine('{"template-id":"legacy","info":{"name":"Legacy","severity":"low"},"host":"https://x"}');
  assert.ok(r && r.finding);
  assert.strictEqual(r.finding.severity, 'low');
});

test('parser httpx: snake_case dan kebab-case, baris rusak', () => {
  const lines = readLines('httpx-sample.jsonl');
  const items = [];
  let malformed = 0;
  for (const l of lines) {
    const r = httpx.parseLine(l);
    if (!r) continue;
    if (r.malformed) malformed++;
    else items.push(r);
  }
  assert.strictEqual(malformed, 1);
  assert.strictEqual(items.length, 3);
  const first = items[0];
  assert.strictEqual(first.statusCode, 200);
  assert.strictEqual(first.webserver, 'nginx/1.18.0');
  assert.deepStrictEqual(first.tech.slice(0, 1), ['WordPress']);
  const kebab = items.find((i) => i.url.includes('kebab-case'));
  assert.strictEqual(kebab.statusCode, 301, 'field status-code (kebab) tetap terbaca');
  assert.strictEqual(kebab.location, 'https://kebab-case.example.com/login');
});

test('parser katana: JSON mode dan fallback teks', () => {
  const lines = readLines('katana-sample.jsonl');
  const items = [];
  for (const l of lines) {
    const r = katana.parseLine(l);
    if (r) items.push(r);
  }
  assert.strictEqual(items.length, 4, '2 JSON + 2 baris teks (plain dan prefixed)');
  const post = items.find((i) => i.url.includes('/api/users'));
  assert.strictEqual(post.method, 'POST');
  assert.strictEqual(post.statusCode, 403);
  const plain = items.find((i) => i.url.includes('plain-link'));
  assert.strictEqual(plain.method, 'GET');
  const prefixed = items.find((i) => i.url.includes('prefixed'));
  assert.ok(prefixed, 'baris " [GET] url" tetap terekstrak');
});

test('parser subfinder: duplikasi host terlihat, malformed terpisah', () => {
  const lines = readLines('subfinder-sample.jsonl');
  const items = [];
  let malformed = 0;
  for (const l of lines) {
    const r = subfinder.parseLine(l);
    if (!r) continue;
    if (r.malformed) malformed++;
    else items.push(r);
  }
  assert.strictEqual(malformed, 1);
  assert.strictEqual(items.length, 4);
  const dupes = items.filter((i) => i.host === 'api.target.example.com');
  assert.strictEqual(dupes.length, 2, 'duplikat tetap dilaporkan parser; dedup dilakukan di atasnya');
  const staging = items.find((i) => i.host === 'staging.target.example.com');
  assert.ok(staging, 'hostname key varian didukung');
});

test('parser dnsx: bentuk flat dan nested, AAAA, status false', () => {
  const lines = readLines('dnsx-sample.jsonl');
  const items = [];
  let malformed = 0;
  for (const l of lines) {
    const r = dnsx.parseLine(l);
    if (!r) continue;
    if (r.malformed) malformed++;
    else items.push(r);
  }
  assert.strictEqual(malformed, 1);
  assert.strictEqual(items.length, 4);
  const flat = items.find((i) => i.host === 'target.example.com');
  assert.deepStrictEqual(flat.a, ['93.184.216.34']);
  assert.strictEqual(flat.ttl, 300);
  const nested = items.find((i) => i.host === 'api.target.example.com');
  assert.deepStrictEqual(nested.a, ['93.184.216.35'], 'bentuk data:{a:[..]} didukung');
  const v6 = items.find((i) => i.host === 'v6.target.example.com');
  assert.deepStrictEqual(v6.aaaa, ['2606:4700::1111']);
  const nx = items.find((i) => i.host === 'nx.target.example.com');
  assert.strictEqual(nx.status, false);
});

test('httpx identity check: menolak binary python httpx', () => {
  assert.ok(httpx.httpxIdentityCheck('Current Version: v1.6.9'));
  assert.ok(httpx.httpxIdentityCheck('v1.3.2\nprojectdiscovery'));
  assert.ok(!httpx.httpxIdentityCheck('usage: httpx [OPTIONS]'));
  assert.ok(!httpx.httpxIdentityCheck('Traceback (most recent call last):'));
});
