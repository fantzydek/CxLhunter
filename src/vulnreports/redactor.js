'use strict';

/**
 * Sensor bukti untuk laporan cerdas. Bukti dari engine TIDAK PERNAH diteruskan
 * mentah ke laporan: token, secret, header kredensial, cookie sesi, JWT, kunci
 * privat, dan parameter sensitif pada URL disensor SEBELUM disimpan/ditampilkan.
 *
 * Prinsip: sensor over-inclusive (aman untuk gagal menutup) tetapi tetap menjaga
 * struktur bukti agar tetap berguna untuk verifikasi manual (panjang & posisi dijaga).
 */

const SECRET_KV_RE = /(token|secret|password|passwd|pwd|authorization|proxy-authorization|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret)(\s*[:=]\s*)("[^"\s]*"|'[^'\s]*'|[^\s'",;&]+)/gi;
// Nilai header kredensial: berhenti sebelum pasangan key= berikutnya, tanda kutip,
// pemisah, atau akhir baris - agar tidak ikut "melahap" key-value setelahnya.
const AUTH_HEADER_RE = /\b(authorization|cookie|set-cookie|proxy-authorization|x-api-key)\s*:\s*([^"'\n\r]*?)(?=\s+\w[\w-]*\s*[:=]|["';,\n\r]|$)/gi;
const BEARER_RE = /\b(bearer|basic)\s+[\w._~+/=-]{6,}/gi;
const JWT_RE = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b/g;
const AWS_KEY_RE = /\bAKIA[0-9A-Z]{16}\b/g;
const PRIVATE_KEY_RE = /-----BEGIN[ A-Z]{0,20}PRIVATE KEY-----[\s\S]*?-----END[ A-Z]{0,20}PRIVATE KEY-----/g;
const URL_SECRET_PARAM_RE = /([?&](?:password|passwd|pwd|token|api[_-]?key|access[_-]?token|auth|session|sid|sig|signature|secret)=)[^&\s"']+/gi;
const CREDIT_CARD_RE = /\b(?:\d[ -]*?){13,16}\b/g;

const RULES = [
  { name: 'private-key', re: PRIVATE_KEY_RE, repl: '[REDACTED_PRIVATE_KEY]' },
  { name: 'jwt', re: JWT_RE, repl: '[REDACTED_JWT]' },
  { name: 'aws-key', re: AWS_KEY_RE, repl: '[REDACTED_AWS_KEY]' },
  { name: 'auth-header', re: AUTH_HEADER_RE, repl: (_m, h) => `${h}: [REDACTED_HEADER_VALUE]` },
  { name: 'bearer', re: BEARER_RE, repl: '[REDACTED_CREDENTIAL]' },
  { name: 'secret-kv', re: SECRET_KV_RE, repl: (_m, k, sep) => `${k}${sep}[REDACTED]` },
  { name: 'url-secret-param', re: URL_SECRET_PARAM_RE, repl: (_m, p) => `${p}[REDACTED]` },
  { name: 'credit-card', re: CREDIT_CARD_RE, repl: '[REDACTED_NUMBER]' },
];

/**
 * Sensor satu potong teks bukti.
 * Hasil: { text, redactions: string[] } - redactions berisi nama aturan yang kena.
 */
function redactText(input) {
  let text = String(input == null ? '' : input);
  const redactions = [];
  for (const rule of RULES) {
    rule.re.lastIndex = 0;
    if (rule.re.test(text)) {
      rule.re.lastIndex = 0;
      text = text.replace(rule.re, rule.repl);
      redactions.push(rule.name);
    }
  }
  return { text, redactions };
}

/**
 * Sensor bukti terstruktur milik generator:
 * - string                -> disensor langsung
 * - array of strings      -> tiap elemen disensor
 * - object (evidence JSON)-> setiap nilai string di semua kedalaman disensor
 * Batasi ukuran keluaran agar laporan tetap ringkas.
 */
function redactEvidence(evidence, maxLen) {
  const limit = maxLen || 1200;
  const applied = new Set();
  function walk(v, depth) {
    if (v === null || v === undefined) return v;
    if (typeof v === 'string') {
      const r = redactText(v);
      r.redactions.forEach((n) => applied.add(n));
      return r.text.slice(0, limit);
    }
    if (typeof v === 'number' || typeof v === 'boolean') return v;
    if (depth > 4) return '[TRUNCATED]';
    if (Array.isArray(v)) {
      return v.slice(0, 12).map((x) => walk(x, depth + 1));
    }
    if (typeof v === 'object') {
      const out = {};
      let n = 0;
      for (const k of Object.keys(v)) {
        if (++n > 24) {
          out['[TRUNCATED]'] = true;
          break;
        }
        out[k] = walk(v[k], depth + 1);
      }
      return out;
    }
    return String(v).slice(0, limit);
  }

  if (evidence === null || evidence === undefined || evidence === '') {
    return { redacted: null, redactions: [], isEmpty: true };
  }

  // Coba parse sebagai JSON agar strukturnya terjaga
  if (typeof evidence === 'string') {
    try {
      const parsed = JSON.parse(evidence);
      const redactedObj = walk(parsed, 0);
      return { redacted: redactedObj, redactions: Array.from(applied), isEmpty: false };
    } catch (_) {
      /* bukan JSON - jatuh ke jalur teks */
    }
    const r = redactText(evidence);
    return { redacted: r.text.slice(0, limit), redactions: r.redactions, isEmpty: r.text.trim().length === 0 };
  }

  const r2 = walk(evidence, 0);
  return { redacted: r2, redactions: Array.from(applied), isEmpty: false };
}

/** Apakah bukti dianggap "konkret" (ada isi setelah sensor) untuk penilaian status. */
function hasConcreteEvidence(evidence) {
  const r = redactEvidence(evidence, 200);
  if (r.isEmpty) return false;
  if (typeof r.redacted === 'string') return r.redacted.trim().length > 4;
  if (r.redacted && typeof r.redacted === 'object') {
    return Object.keys(r.redacted).length > 0;
  }
  return false;
}

module.exports = { redactText, redactEvidence, hasConcreteEvidence };
