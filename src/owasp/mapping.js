'use strict';

/**
 * Pemetaan sumber temuan -> kategori OWASP Top 10:2025.
 * - Temuan headerProbe sudah membawa owasp sendiri (paling akurat).
 * - Temuan Nuclei dipetakan dari tag template dengan urutan prioritas.
 * - Hasil bisa 'UNMAPPED' (ditampilkan apa adanya, tidak dipaksakan).
 */

const TAG_RULES = [
  {
    cat: 'A05',
    tags: [
      'injection',
      'sqli',
      'sql-injection',
      'xss',
      'reflected-xss',
      'rce',
      'ssti',
      'lfi',
      'rfi',
      'ssrf',
      'command-injection',
      'template-injection',
      'deserialization',
      'xxe',
      'code-injection',
    ],
  },
  { cat: 'A07', tags: ['default-login', 'auth-bypass', 'password', 'login', 'credential'] },
  { cat: 'A01', tags: ['unauth', 'unauthorized', 'access-control', 'idor', 'bypass', 'traversal'] },
  { cat: 'A04', tags: ['ssl', 'tls', 'https', 'crypto', 'jwt', 'certificate'] },
  {
    cat: 'A02',
    tags: [
      'misconfig',
      'exposure',
      'config',
      'panel',
      'dashboard',
      'directory-listing',
      'listing',
      'backup',
      'exposed',
      'actuator',
      'debug-page',
      'cors',
      'csp',
      'hsts',
    ],
  },
  {
    cat: 'A03',
    tags: ['cve', 'outdated', 'tech', 'wordpress', 'joomla', 'drupal', 'exchange', 'sharepoint', 'kit'],
  },
  { cat: 'A10', tags: ['debug', 'stack-trace', 'error', 'verbose', 'trace'] },
  { cat: 'A08', tags: ['integrity', 'supply-chain', 'dependency', 'sri', 'desync'] },
];

/** Map daftar tag (array atau string csv) ke kategori OWASP; 'UNMAPPED' bila tidak ada aturan cocok. */
function mapTagsToOwasp(tags) {
  const list = Array.isArray(tags)
    ? tags.map((t) => String(t).toLowerCase())
    : String(tags || '')
        .split(',')
        .map((t) => t.trim().toLowerCase())
        .filter(Boolean);
  for (const rule of TAG_RULES) {
    for (const t of list) {
      if (rule.tags.includes(t)) return rule.cat;
    }
  }
  // fallback: kecocokan substring untuk tag majemuk seperti "cve2023,sqli"
  for (const rule of TAG_RULES) {
    for (const t of list) {
      for (const kw of rule.tags) {
        if (t.includes(kw)) return rule.cat;
      }
    }
  }
  return 'UNMAPPED';
}

/** Registry pemeriksaan otomatis: id -> { engine, categories, label } */
const AUTO_CHECKS = {
  scope_validation: { engine: null, categories: [], label: 'Validasi scope & network guard' },
  subdomain_enum: { engine: 'subfinder', categories: [], label: 'Enumerasi subdomain pasif' },
  dns_validation: { engine: 'dnsx', categories: [], label: 'Resolusi & validasi DNS' },
  http_inventory: { engine: 'httpx', categories: ['A02', 'A03'], label: 'Inventaris layanan HTTP' },
  header_security: {
    engine: 'headerProbe',
    categories: ['A01', 'A02', 'A03', 'A04', 'A07', 'A10'],
    label: 'Pemeriksaan header & TLS non-destruktif',
  },
  exposed_files: { engine: 'headerProbe', categories: ['A02'], label: 'Deteksi file konfigurasi terekspos' },
  endpoint_crawl: { engine: 'katana', categories: ['A01', 'A02'], label: 'Crawling endpoint dalam scope' },
  nuclei_safe_templates: {
    engine: 'nuclei',
    categories: ['A01', 'A02', 'A03', 'A04', 'A05', 'A07', 'A10'],
    label: 'Nuclei template non-destruktif',
  },
  xray_webscan: {
    engine: 'xray',
    categories: ['A01', 'A02', 'A03', 'A05', 'A07', 'A10'],
    label: 'Xray passive webscan (bila kompatibel)',
  },
};

/** Kategori yang selalu manual (tidak ada auto check). */
const ALWAYS_MANUAL = ['A06', 'A09'];

/**
 * Susun daftar check yang direncanakan untuk sebuah mode.
 * Hasil: array check id.
 */
function plannedChecksForMode(mode, options) {
  const opts = options || {};
  const picked = new Set();
  switch (mode) {
    case 'quick':
      ['scope_validation', 'subdomain_enum', 'dns_validation', 'http_inventory', 'header_security'].forEach((c) =>
        picked.add(c)
      );
      break;
    case 'full':
      [
        'scope_validation',
        'subdomain_enum',
        'dns_validation',
        'http_inventory',
        'endpoint_crawl',
        'header_security',
        'nuclei_safe_templates',
      ].forEach((c) => picked.add(c));
      break;
    case 'owasp':
      [
        'scope_validation',
        'http_inventory',
        'header_security',
        'nuclei_safe_templates',
      ].forEach((c) => picked.add(c));
      break;
    case 'nuclei':
      ['scope_validation', 'http_inventory', 'nuclei_safe_templates'].forEach((c) => picked.add(c));
      break;
    case 'subdomain':
      ['scope_validation', 'subdomain_enum', 'dns_validation', 'http_inventory'].forEach((c) => picked.add(c));
      break;
    case 'xss':
    case 'sqli':
    case 'sans':
    case 'malware':
      [
        'scope_validation',
        'http_inventory',
        'endpoint_crawl',
        'header_security',
        'nuclei_safe_templates',
      ].forEach((c) => picked.add(c));
      break;
    case 'endpoints':
      ['scope_validation', 'http_inventory', 'endpoint_crawl'].forEach((c) => picked.add(c));
      break;
    case 'custom': {
      const engines = opts.engines || [];
      if (engines.includes('subfinder')) picked.add('subdomain_enum');
      if (engines.includes('dnsx')) picked.add('dns_validation');
      if (engines.includes('httpx')) picked.add('http_inventory');
      if (engines.includes('katana')) picked.add('endpoint_crawl');
      if (engines.includes('headerProbe')) {
        picked.add('header_security');
        picked.add('exposed_files');
      }
      if (engines.includes('nuclei')) picked.add('nuclei_safe_templates');
      if (engines.includes('xray')) picked.add('xray_webscan');
      picked.add('scope_validation');
      break;
    }
    default:
      break;
  }
  if (opts.exposedFilesCheck !== false && (mode === 'quick' || mode === 'full' || mode === 'owasp' || mode === 'xss' || mode === 'sqli' || mode === 'sans')) {
    picked.add('exposed_files');
  }
  return Array.from(picked);
}

module.exports = { mapTagsToOwasp, AUTO_CHECKS, ALWAYS_MANUAL, plannedChecksForMode };
