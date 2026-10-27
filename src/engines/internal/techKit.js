'use strict';

/**
 * techKit - fingerprinting teknologi dari header respons + isi HTML.
 * Pasif (hanya membaca respons yang sudah diambil). Mengembalikan daftar
 * { name, version?, category, source: 'header'|'body'|'cookie' }.
 */

const HEADER_MATCHERS = [
  { name: 'Nginx', re: /^nginx/i, header: 'server', category: 'webserver' },
  { name: 'Apache', re: /^apache/i, header: 'server', category: 'webserver' },
  { name: 'LiteSpeed', re: /^litespeed/i, header: 'server', category: 'webserver' },
  { name: 'IIS', re: /^microsoft-iis/i, header: 'server', category: 'webserver' },
  { name: 'Caddy', re: /^caddy/i, header: 'server', category: 'webserver' },
  { name: 'Envoy', re: /^envoy/i, header: 'server', category: 'webserver' },
  { name: 'Cloudflare', re: /cloudflare/i, header: 'server', category: 'cdn' },
  { name: 'PHP', re: /^php\/?([\d.]+)?/i, header: 'x-powered-by', category: 'language' },
  { name: 'ASP.NET', re: /asp\.net/i, header: 'x-powered-by', category: 'framework' },
  { name: 'Express', re: /express/i, header: 'x-powered-by', category: 'framework' },
  { name: 'Next.js', re: /next\.js/i, header: 'x-powered-by', category: 'framework' },
];

const BODY_MATCHERS = [
  { name: 'WordPress', re: /wp-content|wp-includes/i, category: 'cms' },
  { name: 'Joomla', re: /joomla|\/media\/jui\//i, category: 'cms' },
  { name: 'Drupal', re: /drupal|sites\/default\/files/i, category: 'cms' },
  { name: 'Shopify', re: /cdn\.shopify\.com|shopify\.theme/i, category: 'ecommerce' },
  { name: 'WooCommerce', re: /woocommerce/i, category: 'ecommerce' },
  { name: 'PrestaShop', re: /prestashop/i, category: 'ecommerce' },
  { name: 'React', re: /__NEXT_DATA__|data-reactroot|react(-dom)?[.@-]/i, category: 'js-framework' },
  { name: 'Vue.js', re: /data-v-[0-9a-f]{8}|vue(\.runtime)?(\.min)?\.js/i, category: 'js-framework' },
  { name: 'Angular', re: /ng-version|angular(\.min)?\.js/i, category: 'js-framework' },
  { name: 'Next.js', re: /__NEXT_DATA__|\/_next\//i, category: 'framework' },
  { name: 'Nuxt', re: /__NUXT__|\/_nuxt\//i, category: 'framework' },
  { name: 'Laravel', re: /laravel_session|csrf-token.*laravel/i, category: 'framework' },
  { name: 'Django', re: /csrfmiddlewaretoken|__admin_media_prefix__/i, category: 'framework' },
  { name: 'jQuery', re: /jquery[.\-/]?([\d.]+)?(\.min)?\.js/i, category: 'js-lib' },
  { name: 'Bootstrap', re: /bootstrap(\.min)?\.(js|css)/i, category: 'css-framework' },
  { name: 'Tailwind CSS', re: /tailwind/i, category: 'css-framework' },
  { name: 'Google Analytics', re: /google-analytics\.com|gtag\/js|googletagmanager/i, category: 'analytics' },
  { name: 'Google Tag Manager', re: /googletagmanager\.com\/gtm\.js/i, category: 'analytics' },
  { name: 'Cloudflare', re: /cdn-cgi\//i, category: 'cdn' },
  { name: 'Cloudflare Email Obfuscation', re: /cdn-cgi\/l\/email-protection/i, category: 'misc' },
  { name: 'reCAPTCHA', re: /recaptcha/i, category: 'security' },
  { name: 'Font Awesome', re: /font-?awesome/i, category: 'ui' },
  { name: 'Svelte', re: /svelte-[0-9a-z]{6}/i, category: 'js-framework' },
];

const COOKIE_MATCHERS = [
  { name: 'PHP', re: /^PHPSESSID$/i, category: 'language' },
  { name: 'Java', re: /^JSESSIONID$/i, category: 'language' },
  { name: 'ASP.NET', re: /^ASP\.NET_SessionId|\.ASPXAUTH$/i, category: 'framework' },
  { name: 'Laravel', re: /^(laravel_session|XSRF-TOKEN)$/i, category: 'framework' },
  { name: 'Express', re: /^connect\.sid$/i, category: 'framework' },
  { name: 'Django', re: /^(sessionid|csrftoken)$/i, category: 'framework' },
  { name: 'Cloudflare', re: /^__cf(a|b)m?$/i, category: 'cdn' },
  { name: 'WordPress', re: /^(wordpress_(logged_in|sec)|wp-settings)/i, category: 'cms' },
];

function uniqTech(list) {
  const seen = new Map();
  for (const t of list) {
    const key = `${t.name}`.toLowerCase();
    const prev = seen.get(key);
    if (!prev) seen.set(key, t);
    else if (!prev.version && t.version) seen.set(key, t);
  }
  return [...seen.values()];
}

/**
 * deteksi teknologi dari satu respons.
 * ctx: { status, headers, body }
 */
function detectTech(ctx) {
  const out = [];
  const headers = ctx.headers || {};
  const lkey = {};
  for (const k of Object.keys(headers)) lkey[k.toLowerCase()] = headers[k];
  const body = String(ctx.body || '');

  for (const m of HEADER_MATCHERS) {
    const v = String(lkey[m.header] || '');
    const mt = m.re.exec(v);
    if (mt) out.push({ name: m.name, version: mt[1] || null, category: m.category, source: `header:${m.header}` });
  }
  for (const m of BODY_MATCHERS) {
    if (m.re.test(body)) out.push({ name: m.name, version: null, category: m.category, source: 'body' });
  }
  const setCookies = [].concat(lkey['set-cookie'] || []);
  for (const c of setCookies) {
    const cname = String(c).split('=')[0];
    for (const m of COOKIE_MATCHERS) {
      if (m.re.test(cname)) out.push({ name: m.name, version: null, category: m.category, source: 'cookie' });
    }
  }
  const gen = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']{1,120})["']/i.exec(body);
  if (gen) out.push({ name: gen[1].trim().slice(0, 60), version: null, category: 'generator', source: 'meta-generator' });

  return uniqTech(out);
}

/** Kategori tampil singkat untuk ringkasan. */
function summarizeTech(techList) {
  const byCat = {};
  for (const t of techList || []) {
    if (!byCat[t.category]) byCat[t.category] = [];
    byCat[t.category].push(t.version ? `${t.name} ${t.version}` : t.name);
  }
  return byCat;
}

module.exports = { detectTech, summarizeTech, HEADER_MATCHERS, BODY_MATCHERS, COOKIE_MATCHERS };
