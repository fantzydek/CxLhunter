'use strict';

/**
 * dnsKit - DNS & subdomain enumeration internal (Node murni).
 * - Subdomain pasif via Certificate Transparency (crt.sh) - sumber publik resmi.
 * - Brute force opsional dengan wordlist kecil umum (rate rendah).
 * - Resolusi A/AAAA/CNAME/MX/NS/TXT via node:dns (pengganti dnsx).
 * Semua pasif; TIDAK mengirim traffic ke target selain query DNS resolver.
 */

const dns = require('dns').promises;

/** Wordlist subdomain umum (kecil, aman untuk resolver publik). */
const COMMON_SUBS = [
  'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
  'dns', 'dns1', 'dns2', 'mx', 'mx1', 'mx2', 'ntp', 'imap', 'cpanel', 'whm',
  'webdisk', 'autodiscover', 'autoconfig', 'm', 'mobile', 'blog', 'shop',
  'forum', 'portal', 'admin', 'administrator', 'api', 'app', 'dev', 'develop',
  'staging', 'stage', 'test', 'testing', 'qa', 'uat', 'demo', 'beta', 'alpha',
  'sandbox', 'git', 'gitlab', 'jenkins', 'ci', 'cd', 'jira', 'confluence',
  'wiki', 'docs', 'doc', 'status', 'monitor', 'monitoring', 'grafana', 'kibana',
  'elastic', 'db', 'database', 'mysql', 'postgres', 'redis', 'mongo', 'sql',
  'backup', 'backups', 'old', 'new', 'test2', 'vpn', 'remote', 'rdp', 'ssh',
  'sso', 'auth', 'login', 'account', 'accounts', 'cdn', 'static', 'assets',
  'img', 'images', 'media', 'video', 'download', 'downloads', 'files', 'file',
  'support', 'help', 'helpdesk', 'ticket', 'crm', 'erp', 'hr', 'intranet',
  'internal', 'corp', 'office', 'exchange', 'outlook', 'lync', 'skype',
  'cloud', 'aws', 'azure', 'gcp', 's3', 'storage', 'bucket', 'backup-2023',
  'ns', 'ns3', 'ns4', 'relay', 'gateway', 'gw', 'router', 'proxy', 'cache',
  'lb', 'loadbalancer', 'firewall', 'fw', 'ids', 'ips', 'siem', 'soc',
];

/** Ambil daftar subdomain dari Certificate Transparency log via crt.sh. */
async function queryCrtSh(domain, { timeoutMs = 25000 } = {}) {
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers: { 'User-Agent': 'CxLScanner/1.4 (internal)' } });
    if (!res.ok) return { ok: false, error: `crt.sh HTTP ${res.status}`, names: [] };
    const data = await res.json();
    const names = new Set();
    for (const row of data || []) {
      const cn = String(row.common_name || '').toLowerCase();
      const nameVal = String(row.name_value || '').toLowerCase();
      for (const n of [...cn.split('\n'), ...nameVal.split('\n')]) {
        const v = n.trim().replace(/^\*\./, '');
        if (v && v.endsWith(`.${domain}`)) names.add(v);
      }
    }
    return { ok: true, names: [...names], error: null };
  } catch (err) {
    return { ok: false, error: String(err.message || err), names: [] };
  } finally {
    clearTimeout(timer);
  }
}

/** Bruteforce subdomain ringan via DNS (wordlist umum, konkurensi rendah). */
async function bruteSubdomains(domain, { words = COMMON_SUBS, concurrency = 12 } = {}) {
  const found = [];
  let idx = 0;
  const workers = Array.from({ length: Math.min(concurrency, words.length) }, async () => {
    while (idx < words.length) {
      const w = words[idx++];
      const host = `${w}.${domain}`;
      try {
        // eslint-disable-next-line no-await-in-loop
        const a = await dns.resolve4(host);
        if (a && a.length) found.push(host);
      } catch (_) {
        /* NXDOMAIN - abaikan */
      }
    }
  });
  await Promise.all(workers);
  return found;
}

/** Resolusi lengkap satu host: A, AAAA, CNAME. */
async function resolveHost(host) {
  const out = { host, a: [], aaaa: [], cname: [], error: null };
  const jobs = [
    dns.resolve4(host).then((r) => { out.a = r || []; }).catch(() => {}),
    dns.resolve6(host).then((r) => { out.aaaa = r || []; }).catch(() => {}),
    dns.resolveCname(host).then((r) => { out.cname = r || []; }).catch(() => {}),
  ];
  await Promise.all(jobs);
  if (!out.a.length && !out.aaaa.length && !out.cname.length) out.error = 'gagal resolusi';
  return out;
}

/** DNS records lengkap untuk /dnsinfo: A, AAAA, MX, NS, TXT, CNAME, SOA, CAA. */
async function fullDnsInfo(host) {
  const res = { host, records: {}, warnings: [] };
  const grab = (key, fn) =>
    fn()
      .then((r) => { res.records[key] = r; })
      .catch(() => { res.records[key] = []; });
  await Promise.all([
    grab('A', () => dns.resolve4(host)),
    grab('AAAA', () => dns.resolve6(host)),
    grab('MX', () => dns.resolveMx(host)),
    grab('NS', () => dns.resolveNs(host)),
    grab('TXT', () => dns.resolveTxt(host)),
    grab('CNAME', () => dns.resolveCname(host)),
    grab('SOA', () => dns.resolveSoa(host)),
    grab('CAA', () => dns.resolveCaa(host)),
  ]);
  // Email security: SPF & DMARC
  const txts = (res.records.TXT || []).map((arr) => (Array.isArray(arr) ? arr.join('') : String(arr)));
  res.records.TXT = txts;
  const spf = txts.filter((t) => /^v=spf1/i.test(t));
  res.emailSecurity = {
    spf: spf.length ? spf : null,
    dmarc: null,
    spfMissing: !spf.length,
    dmarcMissing: true,
  };
  try {
    const dmarcTxt = await dns.resolveTxt(`_dmarc.${host}`);
    const flat = (dmarcTxt || []).map((arr) => (Array.isArray(arr) ? arr.join('') : String(arr)));
    const dm = flat.filter((t) => /^v=DMARC1/i.test(t));
    res.emailSecurity.dmarc = dm.length ? dm : null;
    res.emailSecurity.dmarcMissing = !dm.length;
  } catch (_) {
    res.emailSecurity.dmarcMissing = true;
  }
  // MTA-STS (opsional)
  try {
    const mts = await dns.resolveTxt(`_mta-sts.${host}`);
    const flat = (mts || []).map((arr) => (Array.isArray(arr) ? arr.join('') : String(arr)));
    res.emailSecurity.mtaSts = flat.filter((t) => /^v=STSv1/i.test(t)).join(' ') || null;
  } catch (_) {
    res.emailSecurity.mtaSts = null;
  }
  return res;
}

/**
 * Enumerasi menyeluruh: crt.sh + brute ringan + resolusi.
 * return: { names: [host], resolved: [{host, a, aaaa, cname, error}], sources: {crtSh, brute}, error }
 */
async function enumerateSubdomains(domain, { useBrute = true, maxSubdomains = 200 } = {}) {
  const result = { names: [], resolved: [], sources: { crtSh: false, brute: false }, error: null };
  const all = new Set([domain]);
  const crt = await queryCrtSh(domain);
  if (crt.ok) {
    result.sources.crtSh = true;
    for (const n of crt.names) all.add(n);
  } else {
    result.error = `crt.sh: ${crt.error}`;
  }
  if (useBrute) {
    try {
      const brute = await bruteSubdomains(domain);
      result.sources.brute = true;
      for (const n of brute) all.add(n);
    } catch (_) {
      /* diamkan */
    }
  }
  all.delete(domain);
  result.names = [...all].slice(0, maxSubdomains);
  return result;
}

module.exports = {
  COMMON_SUBS,
  queryCrtSh,
  bruteSubdomains,
  resolveHost,
  fullDnsInfo,
  enumerateSubdomains,
};
