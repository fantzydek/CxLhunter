'use strict';

/**
 * Pemetaan tervalidasi untuk Intelligent Vulnerability Report Generator.
 *
 * ATURAN ANTI-REKAYASA (wajib dipatuhi pemanggil):
 * 1. CWE HANYA ditampilkan pada laporan bila berasal dari sumber yang jelas:
 *    - sumber "engine"  : metadata klasifikasi dari engine (mis. classification.cwe-id Nuclei)
 *    - tabel kurasi di file ini dipakai untuk melengkapi NAMA/pemetaan OWASP dari CWE
 *      yang benar-benar ada pada data temuan - TIDAK pernah menurunkan CWE dari nama template.
 * 2. Pemetaan CWE -> OWASP memakai OWASP Top 10:2021 (Release 1) karena pemetaan
 *    resmi per-CWE yang dipublikasikan OWASP didasarkan pada 2021. Label versi WAJIB
 *    ditampilkan. Kategori 2025 proyek tetap dipakai terpisah dari pipeline scan
 *    (finding.owaspId) dan diberi label sumbernya masing-masing.
 * 3. Tidak ada skor CVSS yang dibuat oleh sistem ini.
 */

/** Registry tipe kerentanan yang memiliki template laporan khusus. */
const VULN_TYPES = {
  sqli: { label: 'SQL Injection', templateId: 'TPL-SQLI' },
  xss: { label: 'Cross-Site Scripting (XSS)', templateId: 'TPL-XSS' },
  'access-control': { label: 'Broken Access Control / IDOR', templateId: 'TPL-ACCESS-CONTROL' },
  ssrf: { label: 'Server-Side Request Forgery (SSRF)', templateId: 'TPL-SSRF' },
  lfi: { label: 'Local File Inclusion / Path Traversal', templateId: 'TPL-LFI' },
  'auth-session': { label: 'Authentication / Session Weakness', templateId: 'TPL-AUTH-SESSION' },
  misconfig: { label: 'Security Misconfiguration', templateId: 'TPL-MISCONFIG' },
  'info-exposure': { label: 'Sensitive Information Exposure', templateId: 'TPL-INFO-EXPOSURE' },
  rce: { label: 'Remote Code Execution (RCE)', templateId: 'TPL-RCE' },
  'open-redirect': { label: 'Open Redirect', templateId: 'TPL-OPEN-REDIRECT' },
  cors: { label: 'CORS Misconfiguration', templateId: 'TPL-CORS' },
  'tls-crypto': { label: 'TLS / Cryptographic Weakness', templateId: 'TPL-TLS-CRYPTO' },
  'known-component': { label: 'Known Vulnerable Component', templateId: 'TPL-KNOWN-COMPONENT' },
  fallback: { label: 'Temuan Belum Terklasifikasi', templateId: 'TPL-FALLBACK' },
};

const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'];

/**
 * Tabel CWE kurasi: id resmi CWE + nama resmi + pemetaan OWASP 2021 resmi +
 * kandidat tipe laporan. Hanya CWE yang relevan dengan tipe template yang ada.
 */
const CWE_REGISTRY = {
  'CWE-20': { name: 'Improper Input Validation', owasp2021: 'A03:2021 - Injection', types: [] },
  'CWE-22': { name: 'Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)', owasp2021: 'A01:2021 - Broken Access Control', types: ['lfi'] },
  'CWE-23': { name: 'Relative Path Traversal', owasp2021: 'A01:2021 - Broken Access Control', types: ['lfi'] },
  'CWE-78': { name: 'Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)', owasp2021: 'A03:2021 - Injection', types: ['rce'] },
  'CWE-79': { name: 'Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)', owasp2021: 'A03:2021 - Injection', types: ['xss'] },
  'CWE-80': { name: 'Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)', owasp2021: 'A03:2021 - Injection', types: ['xss'] },
  'CWE-89': { name: 'Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)', owasp2021: 'A03:2021 - Injection', types: ['sqli'] },
  'CWE-90': { name: 'Improper Neutralization of Special Elements used in an LDAP Query (LDAP Injection)', owasp2021: 'A03:2021 - Injection', types: ['sqli'] },
  'CWE-91': { name: 'XML Injection (aka Blind XPath Injection)', owasp2021: 'A03:2021 - Injection', types: ['sqli'] },
  'CWE-94': { name: 'Improper Control of Generation of Code (Code Injection)', owasp2021: 'A03:2021 - Injection', types: ['rce'] },
  'CWE-95': { name: 'Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection)', owasp2021: 'A03:2021 - Injection', types: ['rce'] },
  'CWE-98': { name: 'Improper Control of Filename for Include/Require Statement in PHP Program (PHP File Inclusion)', owasp2021: 'A03:2021 - Injection', types: ['lfi'] },
  'CWE-200': { name: 'Exposure of Sensitive Information to an Unauthorized Actor', owasp2021: 'A01:2021 - Broken Access Control', types: ['info-exposure'] },
  'CWE-284': { name: 'Improper Access Control', owasp2021: 'A01:2021 - Broken Access Control', types: ['access-control'] },
  'CWE-285': { name: 'Improper Authorization', owasp2021: 'A01:2021 - Broken Access Control', types: ['access-control'] },
  'CWE-295': { name: 'Improper Certificate Validation', owasp2021: 'A02:2021 - Cryptographic Failures', types: ['tls-crypto'] },
  'CWE-319': { name: 'Cleartext Transmission of Sensitive Information', owasp2021: 'A02:2021 - Cryptographic Failures', types: ['tls-crypto'] },
  'CWE-326': { name: 'Inadequate Encryption Strength', owasp2021: 'A02:2021 - Cryptographic Failures', types: ['tls-crypto'] },
  'CWE-327': { name: 'Use of a Broken or Risky Cryptographic Algorithm', owasp2021: 'A02:2021 - Cryptographic Failures', types: ['tls-crypto'] },
  'CWE-328': { name: 'Use of Weak Hash', owasp2021: 'A02:2021 - Cryptographic Failures', types: ['tls-crypto'] },
  'CWE-384': { name: 'Session Fixation', owasp2021: 'A07:2021 - Identification and Authentication Failures', types: ['auth-session'] },
  'CWE-400': { name: 'Uncontrolled Resource Consumption', owasp2021: 'A05:2021 - Security Misconfiguration', types: [] },
  'CWE-522': { name: 'Insufficiently Protected Credentials', owasp2021: 'A07:2021 - Identification and Authentication Failures', types: ['info-exposure'] },
  'CWE-532': { name: 'Insertion of Sensitive Information into Log File', owasp2021: 'A09:2021 - Security Logging and Monitoring Failures', types: ['info-exposure'] },
  'CWE-601': { name: 'URL Redirection to Untrusted Site (Open Redirect)', owasp2021: 'A01:2021 - Broken Access Control', types: ['open-redirect'] },
  'CWE-611': { name: 'Improper Restriction of XML External Entity Reference (XXE)', owasp2021: 'A05:2021 - Security Misconfiguration', types: [] },
  'CWE-613': { name: 'Insufficient Session Expiration', owasp2021: 'A07:2021 - Identification and Authentication Failures', types: ['auth-session'] },
  'CWE-614': { name: "Missing 'Secure' Attribute in Session Cookie", owasp2021: 'A02:2021 - Cryptographic Failures', types: ['auth-session'] },
  'CWE-639': { name: 'Authorization Bypass Through User-Controlled Key (IDOR)', owasp2021: 'A01:2021 - Broken Access Control', types: ['access-control'] },
  'CWE-798': { name: 'Use of Hard-coded Credentials', owasp2021: 'A07:2021 - Identification and Authentication Failures', types: ['info-exposure'] },
  'CWE-862': { name: 'Missing Authorization', owasp2021: 'A01:2021 - Broken Access Control', types: ['access-control'] },
  'CWE-863': { name: 'Incorrect Authorization', owasp2021: 'A01:2021 - Broken Access Control', types: ['access-control'] },
  'CWE-918': { name: 'Server-Side Request Forgery (SSRF)', owasp2021: 'A10:2021 - Server-Side Request Forgery', types: ['ssrf'] },
  'CWE-942': { name: 'Permissive Cross-domain Policy with Untrusted Domains', owasp2021: 'A05:2021 - Security Misconfiguration', types: ['cors'] },
  'CWE-1004': { name: "Sensitive Cookie Without 'HttpOnly' Flag", owasp2021: 'A05:2021 - Security Misconfiguration', types: ['auth-session'] },
  'CWE-1104': { name: 'Use of Unmaintained Third Party Components', owasp2021: 'A06:2021 - Vulnerable and Outdated Components', types: ['known-component'] },
};

const CWE_RE = /^CWE-(\d{1,4})$/i;

/**
 * Validasi & normalisasi string CWE dari sumber engine.
 * Mengembalikan 'CWE-<angka>' kanonik atau null (bukan menurunkan tebakan).
 */
function normalizeCwe(raw) {
  if (raw === null || raw === undefined) return null;
  const first = Array.isArray(raw) ? String(raw[0] || '') : String(raw);
  const m = first.trim().toUpperCase().match(CWE_RE);
  return m ? `CWE-${parseInt(m[1], 10)}` : null;
}

/**
 * Ambil metadata klasifikasi (CWE/CVE) dari evidence JSON temuan.
 * HANYA membaca apa yang benar-benar ditulis engine. Tidak ada penurunan.
 */
function extractClassificationFromEvidence(evidence) {
  const out = { cwe: null, cve: null, source: null };
  if (!evidence || typeof evidence !== 'string') return out;
  let obj = null;
  try {
    obj = JSON.parse(evidence);
  } catch (_) {
    return out;
  }
  if (!obj || typeof obj !== 'object') return out;
  const cwe = normalizeCwe(obj.cwe);
  if (cwe) {
    out.cwe = cwe;
    out.source = 'engine';
  }
  if (obj.cve && /^CVE-\d{4}-\d{4,7}$/i.test(String(obj.cve).trim())) {
    out.cve = String(obj.cve).trim().toUpperCase();
  }
  return out;
}

/**
 * Resolusi metadata pemetaan untuk laporan.
 * Sumber CWE: hanya metadata engine. Tabel kurasi hanya melengkapi nama/OWASP.
 * Field yang tidak berdasar = null (tidak dipaksakan).
 */
function resolveMappingMetadata(finding) {
  const fromEngine = extractClassificationFromEvidence(finding.evidence);
  const meta = {
    cwe: null,
    cweName: null,
    cweSource: null,
    owaspFromCwe: null,
    owaspFromCweSource: null,
    cve: fromEngine.cve || null,
  };
  if (fromEngine.cwe) {
    meta.cwe = fromEngine.cwe;
    meta.cweSource = 'metadata klasifikasi engine';
    const reg = CWE_REGISTRY[fromEngine.cwe];
    if (reg) {
      meta.cweName = reg.name;
      meta.owaspFromCwe = reg.owasp2021;
      meta.owaspFromCweSource = 'OWASP Top 10:2021 (pemetaan resmi per-CWE)';
    }
  }
  return meta;
}

/** Kandidat tipe laporan dari CWE (bila CWE valid dan terdaftar). */
function typesFromCwe(cwe) {
  if (!cwe) return [];
  const reg = CWE_REGISTRY[cwe];
  return reg ? reg.types.slice() : [];
}

function severityRank(s) {
  const i = SEVERITY_ORDER.indexOf(String(s || '').toLowerCase());
  return i === -1 ? SEVERITY_ORDER.length : i;
}

function minSeverity(a, b) {
  return severityRank(a) <= severityRank(b) ? a : b;
}

module.exports = {
  VULN_TYPES,
  CWE_REGISTRY,
  CWE_RE,
  normalizeCwe,
  extractClassificationFromEvidence,
  resolveMappingMetadata,
  typesFromCwe,
  severityRank,
  minSeverity,
};
