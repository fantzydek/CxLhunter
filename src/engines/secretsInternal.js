'use strict';

/**
 * SecretsInternalEngine - deteksi secrets/API keys yang bocor di halaman & file JS.
 * Murni pasif: mengambil file JS yang dirujuk halaman (GET, terbatas), lalu scan
 * dengan regex signature umum. Semua temuan di-REDACT (hanya preview aman).
 *
 * Cakupan: AWS, Google, Azure, GitHub, GitLab, Slack, Stripe, Twilio, Mailgun,
 * SendGrid, JWT, private key, Firebase, MongoDB/Postgres URI, PayPal, Square,
 * Twitter, Facebook, Telegram bot token, Heroku, Shopify, npm token, generic api key.
 */

const { requestPinned, RateLimiter, mapPool, sleep } = require('./internal/netClient');

const SIGNATURES = [
  { id: 'aws-access-key', name: 'AWS Access Key ID', severity: 'critical', re: /\b(AKIA[0-9A-Z]{16})\b/g, owasp: 'A07' },
  { id: 'aws-secret', name: 'AWS Secret Key (konteks)', severity: 'critical', re: /aws(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]/gi, owasp: 'A07' },
  { id: 'google-api', name: 'Google API Key', severity: 'high', re: /\b(AIza[0-9A-Za-z\-_]{35})\b/g, owasp: 'A07' },
  { id: 'google-oauth', name: 'Google OAuth Client Secret', severity: 'high', re: /\b([0-9A-Za-z\-_]{24})\.apps\.googleusercontent\.com\b/g, owasp: 'A07' },
  { id: 'gcp-service-account', name: 'GCP Service Account (private key JSON)', severity: 'critical', re: /"type"\s*:\s*"service_account"/g, owasp: 'A07' },
  { id: 'azure-key', name: 'Azure Storage Account Key', severity: 'critical', re: /AccountKey=[A-Za-z0-9+/]{60,}={0,2}/g, owasp: 'A07' },
  { id: 'github-token', name: 'GitHub Token', severity: 'critical', re: /\b(ghp_[0-9A-Za-z]{36}|gho_[0-9A-Za-z]{36}|ghu_[0-9A-Za-z]{36}|ghs_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{22}[0-9A-Za-z]{59})\b/g, owasp: 'A07' },
  { id: 'gitlab-token', name: 'GitLab Token', severity: 'high', re: /\b(glpat-[0-9A-Za-z\-_]{20,})\b/g, owasp: 'A07' },
  { id: 'slack-token', name: 'Slack Token', severity: 'high', re: /\b(xox[baprs]-[0-9A-Za-z\-]{10,48})\b/g, owasp: 'A07' },
  { id: 'slack-webhook', name: 'Slack Webhook URL', severity: 'medium', re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_\-]{6,}\/[A-Za-z0-9_\-]{6,}/g, owasp: 'A07' },
  { id: 'stripe-live', name: 'Stripe Live Secret Key', severity: 'critical', re: /\b(sk_live_[0-9A-Za-z]{16,32})\b/g, owasp: 'A07' },
  { id: 'stripe-pk', name: 'Stripe Publishable Key (info)', severity: 'info', re: /\b(pk_live_[0-9A-Za-z]{16,32})\b/g, owasp: 'A07' },
  { id: 'twilio', name: 'Twilio API Key', severity: 'high', re: /\b(SK[0-9a-fA-F]{32})\b/g, owasp: 'A07' },
  { id: 'mailgun', name: 'Mailgun API Key', severity: 'high', re: /\b(key-[0-9A-Za-z]{32})\b/g, owasp: 'A07' },
  { id: 'sendgrid', name: 'SendGrid API Key', severity: 'high', re: /\b(SG\.[0-9A-Za-z\-_]{16,40}\.[0-9A-Za-z\-_]{16,40})\b/g, owasp: 'A07' },
  { id: 'jwt', name: 'JWT Token (hardcoded)', severity: 'medium', re: /\b(eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b/g, owasp: 'A07' },
  { id: 'private-key', name: 'Private Key (PEM)', severity: 'critical', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----/g, owasp: 'A02' },
  { id: 'firebase-url', name: 'Firebase Realtime DB URL', severity: 'high', re: /\b([a-z0-9\-]{3,30}\.firebaseio\.com|firebasestorage\.googleapis\.com)\b/gi, owasp: 'A02' },
  { id: 'mongo-uri', name: 'MongoDB Connection URI', severity: 'critical', re: /mongodb(?:\+srv)?:\/\/[^\s'"<>]{8,120}/g, owasp: 'A07' },
  { id: 'postgres-uri', name: 'Postgres/MySQL Connection URI', severity: 'critical', re: /(?:postgres(?:ql)?|mysql):\/\/[^\s'"<>]*:[^\s'"<>@]{3,}@[\w.\-]+/g, owasp: 'A07' },
  { id: 'paypal', name: 'PayPal Braintree Access Token', severity: 'critical', re: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g, owasp: 'A07' },
  { id: 'square', name: 'Square Access Token', severity: 'critical', re: /\b(sq0atp-[0-9A-Za-z\-_]{20,43})\b/g, owasp: 'A07' },
  { id: 'telegram-bot', name: 'Telegram Bot Token', severity: 'high', re: /\b([0-9]{8,10}:[A-Za-z0-9_\-]{35})\b/g, owasp: 'A07' },
  { id: 'heroku-api', name: 'Heroku API Key', severity: 'high', re: /\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b/g, owasp: 'A07', requireContext: /heroku/i },
  { id: 'npm-token', name: 'npm Token', severity: 'critical', re: /\b(npm_[0-9A-Za-z]{36})\b/g, owasp: 'A07' },
  { id: 'generic-apikey', name: 'API key (varian umum)', severity: 'medium', re: /(?:api[_-]?key|apikey|secret|token|auth)[\s'"`=:(]{1,12}['"]([A-Za-z0-9_\-./+]{20,80})['"]/gi, owasp: 'A07' },
];

function redact(value) {
  const s = String(value || '');
  if (s.length <= 8) return '*'.repeat(s.length);
  return `${s.slice(0, 4)}${'*'.repeat(Math.min(12, s.length - 8))}${s.slice(-4)}`;
}

function scanText(text, sourceUrl) {
  const findings = [];
  const body = String(text || '');
  for (const sig of SIGNATURES) {
    let m;
    const re = new RegExp(sig.re.source, sig.re.flags);
    let count = 0;
    const samples = [];
    while ((m = re.exec(body)) !== null && count < 3) {
      const ctxStart = Math.max(0, (m.index || 0) - 40);
      const context = body.slice(ctxStart, (m.index || 0) + m[0].length + 40).replace(/\s+/g, ' ');
      if (sig.requireContext && !sig.requireContext.test(context + body.slice(0, 500))) continue;
      // hindari false positive umum
      const val = m[1] || m[0];
      if (/^(xxx|test|sample|example|placeholder|change|your|todo|fixme|nil|null|undefined|jwt_secret|xxx)/i.test(val)) continue;
      // REDAKSI: nilai mentah TIDAK boleh muncul di konteks yang disimpan
      const safeContext = String(val) ? context.split(val).join(redact(val)) : context;
      samples.push({ preview: redact(val), context: safeContext.slice(0, 160) });
      count++;
    }
    if (count) {
      findings.push({
        engine: 'secrets-internal',
        externalId: `secret:${sig.id}:${sourceUrl}`.slice(0, 200),
        name: `${sig.name} terdeteksi (${count}x)`,
        severity: sig.severity,
        target: sourceUrl,
        evidence: JSON.stringify({ samples }).slice(0, 2000),
        reference: '',
        tags: `secret:${sig.id}`,
        owaspId: sig.owasp,
        classification: 'INDICATOR',
      });
    }
  }
  return findings;
}

class SecretsInternalEngine {
  constructor(config, logger) {
    this.name = 'secrets-internal';
    this.builtIn = true;
    this.config = config;
    this.logger = logger && logger.child ? logger.child('secrets-internal') : logger;
  }

  async checkInstalled() {
    return { status: 'AVAILABLE', version: `node-${process.version} (internal)`, binaryPath: 'internal', reason: 'OK', error: null };
  }

  /** opts: { urls: [url halaman], ipMap?: Map, maxJsFiles?: n } */
  async run(jobCtx, opts) {
    const o = opts || {};
    const pages = (o.urls || []).slice(0, 15);
    const items = [];
    const stats = { pagesFetched: 0, jsFilesChecked: 0, inlineScanned: 0 };
    const limiter = new RateLimiter({ minDelayMs: 100, concurrency: 4 });
    const ipMap = o.ipMap instanceof Map ? o.ipMap : new Map();
    const maxJs = Math.min(o.maxJsFiles || this.config.maxSecretsJsFiles || 30, 80);

    const get = (url) =>
      limiter.run(() =>
        requestPinned({
          url,
          ip: ipMap.get(new URL(url).hostname) || null,
          method: 'GET',
          timeoutMs: 10000,
          maxBodyBytes: 400 * 1024,
          maxRedirects: 2,
          userAgent: this.config.userAgent,
        })
      );

    const jsQueue = new Set();

    for (const page of pages) {
      if (jobCtx.signal && jobCtx.signal.aborted) {
        const e = new Error('Dibatalkan pengguna');
        e.name = 'AbortError';
        throw e;
      }
      let u;
      try {
        u = new URL(page);
      } catch (_) {
        // eslint-disable-next-line no-continue
        continue;
      }
      // eslint-disable-next-line no-await-in-loop
      const r = await get(page);
      stats.pagesFetched++;
      if (!r.ok || !r.body) continue;
      const body = String(r.body);
      // inline script
      const inline = body.match(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]{0,60000}?)<\/script>/gi) || [];
      for (const s of inline) {
        // eslint-disable-next-line no-await-in-loop
        const found = scanText(s, `${page}#inline-script`);
        stats.inlineScanned++;
        items.push(...found);
      }
      // kumpulkan file JS
      const srcs = body.match(/<script[^>]+src=["']([^"']+)["']/gi) || [];
      for (const tag of srcs) {
        const m = /src=["']([^"']+)["']/i.exec(tag);
        if (!m) continue;
        try {
          const abs = new URL(m[1], page).toString();
          if (/\.js(\?|$)/i.test(abs) || u.hostname === new URL(abs).hostname) jsQueue.add(abs);
        } catch (_) { /* abaikan */ }
      }
      // eslint-disable-next-line no-await-in-loop
      await sleep(50);
    }

    // scan file JS
    const jsList = [...jsQueue].slice(0, maxJs);
    // eslint-disable-next-line no-await-in-loop
    await mapPool(jsList, 4, async (jsUrl) => {
      if (jobCtx.signal && jobCtx.signal.aborted) return;
      // eslint-disable-next-line no-await-in-loop
      const r = await get(jsUrl);
      stats.jsFilesChecked++;
      if (r.ok && r.body) {
        const found = scanText(r.body, jsUrl);
        items.push(...found);
      }
    });

    return {
      status: 'COMPLETED',
      items,
      stats: { ...stats, jsQueueSize: jsQueue.length },
      exitCode: 0,
      timedOut: false,
      truncated: false,
      stderrHead: '',
      error: null,
      droppedFlags: [],
      usedArgs: [`pages=${pages.length}`, `js=${jsList.length}`],
    };
  }
}

module.exports = { SecretsInternalEngine, scanText, SIGNATURES, redact };
