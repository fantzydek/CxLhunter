'use strict';

/**
 * Klasifikasi otomatis temuan -> tipe laporan.
 *
 * Multi-sinyal (BUKAN hanya nama template):
 *   1. engine-check  : checkId internal engine (headerProbe) - paling andal utk pemeriksaan internal
 *   2. engine-cwe    : CWE dari metadata klasifikasi engine (mis. classification.cwe-id Nuclei)
 *   3. template-id   : pola token pada ID template
 *   4. tags          : tag template
 *   5. name          : kata kunci nama temuan (sinyal lemah)
 *   6. evidence      : penanda kuat pada isi bukti (mis. error SQL, header CORS)
 *
 * Setiap sinyal diberi bobot. Hasil akhir:
 *   { type, typeLabel, confidence: HIGH|MEDIUM|LOW, needsReview, signals[], ambiguity }
 * Bila sinyal berkonflik atau lemah -> needsReview = true (ditandai NEEDS_REVIEW).
 * Bila tidak ada sinyal cukup -> tipe 'fallback' + NEEDS_REVIEW. Tidak ada pemaksaan.
 */

const { VULN_TYPES, typesFromCwe, extractClassificationFromEvidence } = require('./mappings');

/** --- Aturan pola untuk template-id (bobot 2.5) dan nama (bobot 1) --- */
const PATTERN_RULES = [
  { type: 'sqli', re: /(^|[^a-z])(sqli|sql[-_ ]?injection|blind[-_ ]?sql|error[-_ ]?based|union[-_ ]?select|sqlmap)([^a-z]|$)/i },
  { type: 'xss', re: /(^|[^a-z])(xss|cross[-_ ]?site[-_ ]?script|reflected[-_ ]?xss|stored[-_ ]?xss|dom[-_ ]?xss|script[-_ ]?insert)([^a-z]|$)/i },
  { type: 'access-control', re: /(^|[^a-z])(idor|access[-_ ]?control|unauthori[sz]ed|unauth|priv[-_ ]?esc|broken[-_ ]?access|access[-_ ]?bypass)([^a-z]|$)/i },
  { type: 'ssrf', re: /(^|[^a-z])(ssrf|server[-_ ]?side[-_ ]?request[-_ ]?forg)([^a-z]|$)/i },
  { type: 'lfi', re: /(^|[^a-z])(lfi|rfi|path[-_ ]?traversal|directory[-_ ]?traversal|file[-_ ]?inclusion|\.\.\/|dotdot)([^a-z]|$)/i },
  { type: 'rce', re: /(^|[^a-z])(rce|remote[-_ ]?code[-_ ]?exec|code[-_ ]?injection|command[-_ ]?injection|cmd[-_ ]?injection|ssti|template[-_ ]?injection|eval[-_ ]?injection|insecure[-_ ]?deserial)([^a-z]|$)/i },
  { type: 'open-redirect', re: /(^|[^a-z])(open[-_ ]?redirect|redirect(?![^.]*tls))([^a-z]|$)/i },
  { type: 'cors', re: /(^|[^a-z])(cors|cross[-_ ]?origin|access[-_ ]?control[-_ ]?allow[-_ ]?origin)([^a-z]|$)/i },
  { type: 'tls-crypto', re: /(^|[^a-z])(tls|ssl(?![a-z])|weak[-_ ]?cipher|heartbleed|certificate|tls[-_ ]?version|old[-_ ]?cipher)([^a-z]|$)/i },
  { type: 'known-component', re: /(^|[^a-z])(cve[-_ ]?\d{4}|exploit|vulnerable[-_ ]?(app|component|version|software)|wordpress|joomla|drupal|exchange|sharepoint|struts|tomcat|jenkins|confluence|gitlab)([^a-z]|$)/i },
  { type: 'auth-session', re: /(^|[^a-z])(default[-_ ]?login|weak[-_ ]?password|auth[-_ ]?bypass|brute[-_ ]?force|jwt|session[-_ ]?(fixation|expiration|timeout)|cookie(?![^a-z]))([^a-z]|$)/i },
  { type: 'info-exposure', re: /(^|[^a-z])(info?[-_ ]?exposure|information[-_ ]?disclosure|exposed[-_ ]?(file|env|git|backup|key|secret)|stack[-_ ]?trace|sensitive[-_ ]?(data|file|info)|source[-_ ]?code[-_ ]?disclosure)([^a-z]|$)/i },
  { type: 'misconfig', re: /(^|[^a-z])(misconfig|directory[-_ ]?listing|listing|panel|dashboard|actuator|phpinfo|debug[-_ ]?page|server[-_ ]?status|admin[-_ ]?page|default[-_ ]?page)([^a-z]|$)/i },
];

/** Peta checkId internal headerProbe -> tipe (sinyal paling andal untuk engine internal). */
const CHECK_ID_MAP = [
  { prefix: 'header:', type: 'misconfig' },
  { exact: 'cookie:flags', type: 'auth-session' },
  { exact: 'server:version', type: 'info-exposure' },
  { exact: 'server:poweredby', type: 'info-exposure' },
  { prefix: 'tls:', type: 'tls-crypto' },
  { exact: 'redirect:downgrade', type: 'tls-crypto' },
  { exact: 'redirect:scope', type: 'open-redirect' },
  { prefix: 'page:stacktrace', type: 'info-exposure' },
  { exact: 'page:dirlisting', type: 'misconfig' },
  { exact: 'page:5xx', type: 'info-exposure' },
  { prefix: 'exposed:', type: 'info-exposure' },
];

/** Penanda kuat pada isi bukti (bobot 2). Hanya pola yang tidak ambigu. */
const EVIDENCE_MARKERS = [
  { type: 'sqli', re: /You have an error in your SQL syntax|SQLSyntaxError|MySQLSyntaxError|Warning:\s*(mysql|mysqli|pg_)\w*\(|ORA-\d{5}|SQLSTATE\[\w+\]/i, detail: 'pola error SQL pada bukti' },
  { type: 'cors', re: /Access-Control-Allow-Origin/i, detail: 'header CORS muncul pada bukti' },
  { type: 'tls-crypto', re: /TLSv1\.[01]\b|protocol:\s*TLSv1\.[01]\b/i, detail: 'versi TLS lama pada bukti' },
  { type: 'open-redirect', re: /\blocation:\s*https?:\/\//i, detail: 'header Location pada bukti redirect' },
];

function pushSignal(signals, kind, detail, weight) {
  signals.push({ kind, detail: String(detail).slice(0, 200), weight });
}

/** Kumpulkan sinyal dari semua sumber untuk satu temuan ternormalisasi. */
function collectSignals(finding) {
  const signals = [];
  const externalId = String(finding.externalId || '');
  const name = String(finding.name || '');
  const tags = Array.isArray(finding.tags)
    ? finding.tags
    : String(finding.tags || '')
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean);
  const evidenceText = String(finding.evidence || '').slice(0, 4000);

  // 1. checkId internal engine
  const checkId = externalId || '';
  for (const rule of CHECK_ID_MAP) {
    if ((rule.exact && checkId === rule.exact) || (rule.prefix && checkId.startsWith(rule.prefix))) {
      pushSignal(signals, 'engine-check', `checkId internal "${checkId}" dipetakan langsung oleh engine internal`, 3);
      break;
    }
  }

  // 2. CWE dari metadata engine
  const cls = extractClassificationFromEvidence(finding.evidence);
  if (cls.cwe) {
    const types = typesFromCwe(cls.cwe);
    if (types.length === 1) {
      pushSignal(signals, 'engine-cwe', `CWE ${cls.cwe} (metadata engine) terdefinisi tunggal untuk tipe ini`, 3);
    } else if (types.length > 1) {
      for (const t of types) signals.push({ kind: 'engine-cwe', detail: `CWE ${cls.cwe} (metadata engine) memetakan ke beberapa tipe (ambigu)`, weight: 1.5, forType: t });
      // tandai ambiguitas eksplisit
      signals.push({ kind: 'engine-cwe-ambiguous', detail: `CWE ${cls.cwe} memetakan ke ${types.length} tipe kandidat`, weight: 0, forType: types[0] });
    } else {
      signals.push({ kind: 'engine-cwe-neutral', detail: `CWE ${cls.cwe} valid tetapi tidak dipetakan ke tipe template mana pun`, weight: 0 });
    }
  }

  // 3. pola template-id
  if (externalId) {
    for (const rule of PATTERN_RULES) {
      if (rule.re.test(externalId)) {
        pushSignal(signals, 'template-id', `ID template "${externalId.slice(0, 80)}" cocok pola tipe ${rule.type}`, 2.5);
      }
    }
  }

  // 4. tags
  for (const tag of tags.slice(0, 12)) {
    for (const rule of PATTERN_RULES) {
      if (rule.re.test(tag)) {
        pushSignal(signals, 'tags', `tag "${tag}" cocok pola tipe ${rule.type}`, 1.5);
      }
    }
  }

  // 5. nama temuan (lemah)
  if (name) {
    for (const rule of PATTERN_RULES) {
      if (rule.re.test(name)) {
        pushSignal(signals, 'name', `nama temuan "${name.slice(0, 80)}" cocok pola tipe ${rule.type}`, 1);
      }
    }
  }

  // 6. penanda bukti
  if (evidenceText) {
    for (const marker of EVIDENCE_MARKERS) {
      if (marker.re.test(evidenceText)) {
        pushSignal(signals, 'evidence', marker.detail, 2);
      }
    }
  }

  return signals;
}

/**
 * Klasifikasikan satu temuan ternormalisasi.
 * Temuan: { engine, externalId, name, severity, target, evidence, tags, classification }
 */
function classifyFinding(finding) {
  const signals = collectSignals(finding || {});

  // agregasi skor per tipe (sinyal with forType diarahkan; sisanya dihitung dari detail pola)
  const scores = {};
  for (const s of signals) {
    if (s.weight <= 0) continue;
    let targetType = null;
    if (s.forType) {
      targetType = s.forType;
    } else {
      // tentukan tipe dari aturan yang menghasilkan sinyal
      if (s.kind === 'engine-check') {
        const checkId = String(finding.externalId || '');
        for (const rule of CHECK_ID_MAP) {
          if ((rule.exact && checkId === rule.exact) || (rule.prefix && checkId.startsWith(rule.prefix))) {
            targetType = rule.type;
            break;
          }
        }
      } else if (s.kind === 'template-id' || s.kind === 'tags' || s.kind === 'name') {
        // cocokkan ulang aturan untuk mengetahui tipenya
        const hay = s.kind === 'template-id' ? String(finding.externalId || '') : s.kind === 'tags' ? String(finding.tags || '') : String(finding.name || '');
        // detail sinyal menyimpan tipe pada akhir kalimat pola; ekstrak dari detail
        const m = /tipe ([a-z-]+)$/.exec(s.detail);
        if (m && VULN_TYPES[m[1]]) targetType = m[1];
        else if (hay) {
          for (const rule of PATTERN_RULES) {
            if (rule.re.test(hay)) {
              targetType = rule.type;
              break;
            }
          }
        }
      } else if (s.kind === 'evidence') {
        for (const marker of EVIDENCE_MARKERS) {
          if (s.detail === marker.detail) {
            targetType = marker.type;
            break;
          }
        }
      } else if (s.kind === 'engine-cwe') {
        const types = typesFromCwe(extractClassificationFromEvidence(finding.evidence).cwe);
        if (types.length === 1) targetType = types[0];
      }
    }
    if (targetType && VULN_TYPES[targetType]) {
      scores[targetType] = (scores[targetType] || 0) + s.weight;
    }
  }

  const ranked = Object.keys(scores)
    .map((t) => ({ type: t, score: scores[t] }))
    .sort((a, b) => b.score - a.score);

  const top = ranked[0] || null;
  const second = ranked[1] || null;
  const ambiguity = !!(top && second && second.score >= top.score * 0.8);

  let type = 'fallback';
  let confidence = 'LOW';
  if (top && top.score >= 2 && !ambiguity) {
    type = top.type;
    confidence = top.score >= 4 ? 'HIGH' : 'MEDIUM';
  } else if (top && top.score >= 4 && ambiguity) {
    // skor tinggi tapi ambigu: pilih teratas namun tandai review
    type = top.type;
    confidence = 'LOW';
  }

  const needsReview = type === 'fallback' || confidence === 'LOW' || ambiguity;

  return {
    type,
    typeLabel: VULN_TYPES[type].label,
    confidence,
    needsReview,
    ambiguity,
    signals,
    scores: ranked,
  };
}

module.exports = { classifyFinding, collectSignals, PATTERN_RULES, CHECK_ID_MAP, EVIDENCE_MARKERS };
