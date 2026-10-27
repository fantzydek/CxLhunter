'use strict';

/**
 * Bot Telegram (Telegraf) - CxL Bug Bounty Scanner v1.5.
 * Semua output memakai RICH MESSAGE (API sendRichMessage dengan blok terstruktur,
 * gaya base.zip): heading, divider, paragraph, list, table, buttons, thinking.
 * Bila server Bot API tidak mendukung sendRichMessage, fallback otomatis ke HTML.
 *
 * Keamanan tetap dipertahankan: konfirmasi target sebelum scan, guard IP internal/privat,
 * akses berbasis Telegram user ID, tanpa tombol mati/progress palsu.
 */

const fs = require('fs');
const path = require('path');
const { Telegraf, Markup } = require('telegraf');
const { splitMessage, severityBadge, stageIcon, fmtDateTime, fmtDuration, scanStatusLabel, engineStatusLabel } = require('./utils/format');
const rich = require('./utils/rich');
const { isAdminId, isUserAllowed, resolveRole } = require('./utils/auth');
const { sanitizeText, randomId } = require('./utils/validation');
const { summarizeForTelegram, VALIDATION_STATUSES } = require('./vulnreports/generator');
const { createVulnReportStore } = require('./vulnreports/store');
const { renderVReportText, writeVReportFile } = require('./vulnreports/exporters');
const { requestPinned, requestFollow, extractTitle } = require('./engines/internal/netClient');
const { detectTech, summarizeTech } = require('./engines/internal/techKit');
const { fullDnsInfo } = require('./engines/internal/dnsKit');
const { evaluateSecurityPosture, EXPOSED_PATHS } = require('./engines/vulnScanInternal');
const { PortsInternalEngine, COMMON_WEB_PORTS } = require('./engines/portsInternal');
const { kbFor, kbSearch, kbEntry, kbList } = require('./engines/internal/vulnKB');

const MODE_LABEL = {
  quick: 'Quick Scan',
  full: 'Full Scan',
  deep: 'Deep Vulnerability Scan',
  deepvuln: 'Deep Vuln Scan',
  owasp: 'OWASP Top 10 Scan',
  sans: 'SANS Top 25 Scan',
  xss: 'XSS Scan',
  sqli: 'SQL Injection Scan',
  malware: 'Malware Scan',
  subdomain: 'Subdomain Enumeration',
  nuclei: 'Vuln Scan (nuclei/vulnscan)',
  endpoints: 'Endpoint Scan',
  secrets: 'Secrets & API Key Scan',
  recon: 'Recon + Port Scan',
  custom: 'Custom Scan',
};

/** Tombol pilihan jenis scan untuk /scan - urutan & label sesuai permintaan. */
const SCAN_PICKER = [
  { mode: 'full', label: '🔍 Full Scan', desc: 'Recon + crawl + vuln scan menyeluruh' },
  { mode: 'xss', label: '🕸 XSS Scan', desc: 'Reflected XSS, CSP, encoding parameter' },
  { mode: 'sqli', label: '💉 SQL Injection', desc: 'Error-based SQLi signature pada parameter' },
  { mode: 'owasp', label: '🏛 OWASP Top 10', desc: 'Coverage OWASP Top 10:2025' },
  { mode: 'sans', label: '⚠️ SANS Top 25', desc: 'CWE Top 25: XSS, SQLi, SSRF, traversal' },
  { mode: 'malware', label: '🦠 Malware Scan', desc: 'Defacement, webshell, miner, spam, scam' },
  { mode: 'quick', label: '⚡ Quick Scan', desc: 'Ringan: subdomain, DNS, host, header' },
  { mode: 'subdomain', label: '🌐 Subdomain', desc: 'Enumerasi subdomain saja (subfinder)' },
];

const HELP_TEXT = `PANDUAN CXL BUG BOUNTY SCANNER

PERINTAH SCAN
/scan domain.com - MENU PILIH JENIS SCAN (tombol: full, XSS, SQLi, OWASP, SANS, malware, dll)
/fullscan domain.com - Full Scan (quick + crawl + vuln scan)
/subdomain domain.com - Enumerasi subdomain (subfinder + dnsx + cek host hidup)
/deepscan domain.com - Deep Scan (crawl + vuln mendalam + secrets)
/xss domain.com - Fokus deteksi XSS
/sqli domain.com - Fokus deteksi SQL injection
/owasp domain.com - Penilaian coverage OWASP Top 10:2025
/sans domain.com - Penilaian SANS/CWE Top 25
/malware domain.com - Deteksi malware/defacement/webshell/spam
/nuclei domain.com - Vuln scan saja (pilih severity)
/endpoints domain.com - Pengumpulan endpoint dalam scope
/secrets domain.com - Deteksi API key/secret bocor di JS
/recon domain.com - Recon: DNS + subdomain + port web

INFO KERENTANAN (KB BUG)
/vuln - daftar kamus bug lengkap (Vuln ID + severity)
/vuln xss - cari bug: penjelasan + contoh payload + kode rentan + cara fix
Tombol "Detail Bug" pada temuan/live scan = halaman bug detail lengkap.
Saat scan berjalan, bug baru langsung ditampilkan: severity + Vuln ID + payload.

TOOLS INSTAN (hasil langsung)
/headers domain.com - Analisis header keamanan
/cors domain.com - Uji konfigurasi CORS
/paths domain.com - File sensitif terekspos (.env, .git, backup)
/tech domain.com - Fingerprint teknologi
/ports domain.com - Scan port web umum
/dnsinfo domain.com - Record DNS + SPF/DMARC
/ipinfo domain.com - Info IP/ASN via RDAP

PERINTAH PEKERJAAN
/status - status pekerjaan berjalan/antre
/stop [jobId] - batalkan pekerjaan milik Anda
/results - ringkasan hasil scan terakhir
/history - riwayat scan
/report ID - laporan lengkap (TXT/JSON/HTML)
/menu - menu utama dengan tombol

LAPORAN KERENTANAN CERDAS
/vreports [jobId] - laporan per-jenis kerentanan
/vreport <uid> - pratinjau + tombol aksi
/vreport status <uid> <STATUS> - ubah status validasi
/vreport note <uid> <teks> - tambah catatan review
Status: DETECTED | NEEDS_MANUAL_VERIFICATION | CONFIRMED | FALSE_POSITIVE | NOT_REPRODUCED

PERINTAH SISTEM
/tools - status engine terpasang
/checktools - verifikasi executable + versi
/installtools - installer terkontrol (admin)
/scope - scope yang dikonfigurasi
/stats - statistik lokal

KEBIJAKAN
- ALLOWED_TARGETS kosong = mode terbuka (domain publik apa pun); diisi = terkunci ke domain itu.
- Hanya uji domain yang Anda MILIKI atau punya IZIN RESMI (aturan program bug bounty).
- Semua pemeriksaan non-destruktif; template destruktif/brute-force dikecualikan.
- Engine internal otomatis dipakai bila binary eksternal tidak terpasang.
- Temuan = indikasi; wajib verifikasi manual sebelum dilaporkan.`;

const SEV_EMOJI = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' };
function sevEmoji(s) {
  return SEV_EMOJI[String(s || 'info').toLowerCase()] || '⚪';
}

function createBot({ config, store, queue, guard, validator, engines, logger, registry, worker }) {
  if (!config.botToken) {
    throw new Error('BOT_TOKEN kosong. Isi .env lalu jalankan ulang.');
  }
  const bot = new Telegraf(config.botToken, { handlerTimeout: 120000 });
  const pending = new Map(); // nonce -> { ownerId, mode, host, root, ts, options }
  const progressEdits = new Map(); // jobId -> { chatId, messageId, lastEdit }
  const installing = new Map(); // userId -> true
  const vrStore = createVulnReportStore(store.db);

  // ---------- util kirim (rich + fallback) ----------
  async function replyRich(ctx, title, body, markup) {
    return rich.replyRich(ctx, title, body, markup);
  }

  async function replyText(ctx, text, extra) {
    const parts = splitMessage(text);
    let last;
    for (let i = 0; i < parts.length; i++) {
      const ex = i === parts.length - 1 ? extra : undefined;
      // eslint-disable-next-line no-await-in-loop
      last = await ctx.reply(parts[i], ex);
    }
    return last;
  }

  function requireTargetArg(ctx) {
    const parts = String(ctx.message && ctx.message.text ? ctx.message.text : '').trim().split(/\s+/);
    const arg = parts[1] || '';
    if (!arg) {
      replyRich(
        ctx,
        'Format salah',
        rich.paragraph(`Gunakan: /${(parts[0] || 'scan').replace('/', '')} domain.com`),
      );
      return null;
    }
    const v = validator.validateTargetInput(arg);
    if (!v.ok) {
      const hint = validator.openMode
        ? 'Gunakan format domain, mis: example.com (IP privat/internal selalu ditolak)'
        : 'Pastikan target berada dalam ALLOWED_TARGETS di .env (atau kosongkan untuk mode terbuka)';
      replyRich(ctx, 'Ditolak', [rich.paragraph(v.reason), rich.quoteBlock(hint)]);
      return null;
    }
    return v; // {ok, host, root, openMode?}
  }

  // ---------- KB bug: baris live, tombol detail, halaman detail ----------
  /** Satu baris temuan live: severity + Vuln ID + CWE + nama + target + payload. */
  function recentFindingLine(f) {
    const id = f.vulnId || f.external_id || f.externalId || '-';
    const cwe = f.cwe ? ` | ${f.cwe}` : '';
    const tgt = f.target ? ` - ${String(f.target).slice(0, 70)}` : '';
    const pay = f.payload ? `\n   payload: ${String(f.payload).slice(0, 120)}` : '';
    return `${sevEmoji(f.severity)} [${id}${cwe}] ${f.name || '-'}${tgt}${pay}`;
  }

  /** Tombol "Detail Bug" per temuan (maks 6, 2 per baris). */
  function findingButtons(scanId, recent) {
    const rows = [];
    const items = (recent || []).filter((f) => f && f.hash).slice(0, 6);
    for (let i = 0; i < items.length; i += 2) {
      const row = items.slice(i, i + 2).map((f) =>
        Markup.button.callback(
          `🔎 ${String(f.vulnId || f.name || 'Bug').slice(0, 26)}`,
          `vb:${scanId}:${f.hash}`
        )
      );
      rows.push(row);
    }
    return rows;
  }

  /** Ubah baris DB findings menjadi bentuk seperti temuan live (untuk tombol). */
  function rowToFindingLike(row) {
    let vulnId = '';
    let cwe = '';
    let payload = '';
    try {
      const ev = JSON.parse(row.evidence || '{}') || {};
      vulnId = ev.vuln_id || '';
      cwe = ev.cwe || '';
      payload = (ev.payload_example && ev.payload_example[0]) || '';
    } catch (_) {
      /* evidence polos */
    }
    return { hash: row.dedupe_hash, vulnId, cwe, name: row.name, severity: row.severity, target: row.target, payload };
  }

  /** Vuln ID untuk label baris temuan: dari evidence JSON, fallback external_id. */
  function vulnIdOfRow(row) {
    try {
      const ev = JSON.parse(row.evidence || '{}') || {};
      if (ev.vuln_id) return ev.vuln_id;
    } catch (_) {
      /* abaikan */
    }
    return row.external_id || '-';
  }

  /**
   * Halaman Detail Bug lengkap: penjelasan bug, dampak, contoh payload,
   * contoh kode rentan, request serangan, respons rentan, cara perbaikan.
   * finding: baris DB findings (bisa null bila hanya lookup KB).
   */
  function renderBugDetailBlocks(finding, opts) {
    const o = opts || {};
    const externalId = finding ? finding.external_id : o.externalId;
    const evidence = finding ? finding.evidence : o.evidence;
    const kb = kbFor(externalId, evidence) || null;
    let meta = { vuln_id: '', cwe: '', payload_example: [], bug_example: null };
    try {
      const ev = JSON.parse(evidence || '{}') || {};
      if (ev.vuln_id) meta.vuln_id = ev.vuln_id;
      if (ev.cwe) meta.cwe = ev.cwe;
      if (Array.isArray(ev.payload_example)) meta.payload_example = ev.payload_example;
      if (ev.bug_example) meta.bug_example = ev.bug_example;
    } catch (_) {
      /* evidence bukan JSON */
    }
    if (kb) {
      meta.vuln_id = meta.vuln_id || kb.vulnId;
      meta.cwe = meta.cwe || kb.cwe;
      if (!meta.payload_example.length) meta.payload_example = kb.payloads || [];
      if (!meta.bug_example) meta.bug_example = kb.vulnerable ? { vulnerable: kb.vulnerable, attack: kb.attack, response: kb.response } : null;
    }
    const sev = (finding ? finding.severity : o.severity) || (kb ? kb.severity : 'info');
    const name = (finding ? finding.name : o.name) || (kb ? kb.name : externalId || 'Tidak dikenal');
    const cat = kb ? kb.category : '';
    const owasp = kb ? kb.owasp : (finding ? finding.owasp_id : '') || '';
    const blocks = [
      rich.paragraph(`${sevEmoji(sev)} ${String(sev).toUpperCase()}  |  Vuln ID: ${meta.vuln_id || '-'}  |  ${meta.cwe || kbCweFallback(externalId)}`),
    ];
    const rows = [
      [rich.tableCell('Item', { header: true }), rich.tableCell('Detail', { header: true })],
      [rich.tableCell('Bug'), rich.tableCell(String(name).slice(0, 60))],
    ];
    if (cat) rows.push([rich.tableCell('Kategori'), rich.tableCell(cat)]);
    if (owasp) rows.push([rich.tableCell('OWASP'), rich.tableCell(owasp)]);
    if (finding) rows.push([rich.tableCell('Target'), rich.tableCell(String(finding.target || '-').slice(0, 60))]);
    if (finding) rows.push([rich.tableCell('Engine'), rich.tableCell(String(finding.engine || '-'))]);
    blocks.push(rich.tableBlock(rows));

    if (kb) {
      blocks.push(rich.divider());
      blocks.push(rich.paragraph('📖 Apa ini bug-nya?'));
      blocks.push(rich.paragraph(kb.what));
      blocks.push(rich.paragraph('💥 Dampak:'));
      blocks.push(rich.paragraph(kb.impact));
    }
    if (meta.payload_example.length) {
      blocks.push(rich.divider(), rich.paragraph('🧪 Contoh payload:'));
      blocks.push(rich.codeBlock(meta.payload_example.slice(0, 4).join('\n'), 'http'));
    }
    if (meta.bug_example) {
      const be = meta.bug_example;
      if (be.vulnerable) {
        blocks.push(rich.paragraph('🐛 Contoh kode rentan:'));
        blocks.push(rich.codeBlock(be.vulnerable, 'php'));
      }
      if (be.attack) {
        blocks.push(rich.paragraph('⚔️ Request serangan:'));
        blocks.push(rich.codeBlock(be.attack, 'http'));
      }
      if (be.response) {
        blocks.push(rich.paragraph('📡 Respons rentan:'));
        blocks.push(rich.codeBlock(be.response, 'http'));
      }
    }
    if (kb) {
      blocks.push(rich.divider(), rich.paragraph('🛠 Cara perbaiki:'));
      blocks.push(rich.quoteBlock(kb.fix));
    }
    // bukti asli di target ini (bila ada)
    try {
      const ev = JSON.parse(evidence || '{}') || {};
      const evLine = [ev.detail, ev.evidence].filter(Boolean).join('\n');
      if (evLine) {
        blocks.push(rich.paragraph('🔍 Bukti di target ini:'));
        blocks.push(rich.codeBlock(evLine.slice(0, 700), 'text'));
      }
    } catch (_) {
      if (evidence && !String(evidence).startsWith('{')) {
        blocks.push(rich.paragraph('🔍 Bukti di target ini:'));
        blocks.push(rich.codeBlock(String(evidence).slice(0, 700), 'text'));
      }
    }
    return blocks;
  }

  function kbCweFallback(externalId) {
    const kb = kbFor(externalId, '');
    return (kb && kb.cwe) || '';
  }

  function confirmationKeyboard(nonce) {
    return Markup.inlineKeyboard([
      [Markup.button.callback('Mulai scan', `go:${nonce}`), Markup.button.callback('Batal', `cx:${nonce}`)],
    ]);
  }

  async function offerScan(ctx, mode, targetInfo, options) {
    const canQ = queue.canEnqueue(ctx.from.id);
    if (!canQ.ok) {
      replyRich(ctx, 'Antrean penuh', rich.paragraph(canQ.reason));
      return;
    }
    const nonce = randomId('n').slice(0, 16);
    pending.set(nonce, {
      ownerId: ctx.from.id,
      username: ctx.from.username || null,
      mode,
      host: targetInfo.host,
      root: targetInfo.root,
      ts: Date.now(),
      options: options || {},
    });
    const isIntense = ['full', 'deep', 'nuclei', 'deepvuln', 'xss', 'sqli', 'sans'].includes(mode);
    const rows = [
      rich.tableRow(
        rich.tableCell('Target', { header: true }),
        rich.tableCell('Mode', { header: true }),
        rich.tableCell('Root scope', { header: true })
      ),
      rich.tableRow(rich.tableCell(targetInfo.host), rich.tableCell(MODE_LABEL[mode] || mode), rich.tableCell(targetInfo.root)),
    ];
    const MODE_DESC = {
      full: 'Recon lengkap + crawling + pemindaian kerentanan.',
      xss: 'Fokus XSS: refleksi parameter, CSP, encoding + nuclei tag xss.',
      sqli: 'Fokus SQL injection: signature error DB pada parameter + nuclei tag sqli.',
      owasp: 'Pemetaan coverage OWASP Top 10:2025.',
      sans: 'SANS/CWE Top 25: XSS, SQLi, SSRF, traversal, redirect, dsb.',
      malware: 'Deteksi malware: defacement, webshell, crypto miner, spam, scam.',
      quick: 'Ringan: subdomain, DNS, host HTTP, header keamanan.',
      subdomain: 'Enumerasi subdomain (subfinder) + resolusi DNS + cek host hidup.',
    };
    const body = [
      rich.tableBlock(rows),
      rich.paragraph(MODE_DESC[mode] || (options && options.severity ? `Batas severity: ${options.severity.join(', ')}` : 'Pastikan Anda memiliki izin resmi untuk menguji target ini.')),
      isIntense ? rich.quoteBlock('Mode ini lebih intensif (lebih banyak request) tetapi tetap non-destruktif.') : null,
      !validator.configured ? rich.quoteBlock('Mode terbuka aktif (ALLOWED_TARGETS kosong). Hanya uji target yang Anda punya izin resminya.') : null,
    ].filter(Boolean);
    await replyRich(ctx, `Konfirmasi ${MODE_LABEL[mode] || mode}`, body, confirmationKeyboard(nonce));
  }

  function makeProgressHandler(job) {
    return (snap) => {
      const st = progressEdits.get(job.jobId);
      if (!st) return;
      st.lastSnap = snap; // simpan snapshot terakhir untuk tombol "Cek Status"
      const now = Date.now();
      if (!snap.finished && now - st.lastEdit < 2500) return; // throttle edit
      st.lastEdit = now;
      const counts = snap.counts || {};
      const blocks = [
        rich.paragraph(`Target: ${snap.target}`),
        rich.divider(),
        rich.bulletList(snap.stages.map((s) => `${stageIcon(s.status)} ${s.label}`)),
        rich.divider(),
        rich.paragraph(`Subdomain: ${counts.subdomains || 0} | Host: ${counts.hosts || 0} | Endpoint: ${counts.endpoints || 0} | Temuan: ${counts.findings || 0}`),
      ];
      // LIVE: bug yang baru ditemukan beserta Vuln ID, severity, dan contoh payload
      const recent = Array.isArray(snap.recent) ? snap.recent : [];
      if (recent.length) {
        blocks.push(rich.divider(), rich.paragraph('🐞 Bug ditemukan (live):'));
        blocks.push(rich.bulletList(recent.map((f) => recentFindingLine(f))));
      }
      if (snap.finished) {
        blocks.push(rich.paragraph(`Status akhir: ${scanStatusLabel(snap.finished)}`));
      }
      let markup;
      const detailRows = findingButtons(job.scanId, recent);
      if (snap.finished) {
        const rows = [[Markup.button.callback('Hasil', 'menu:lastresults'), Markup.button.callback('Laporan', 'menu:lastreport')]];
        // Tombol lihat subdomain untuk mode subdomain / ada subdomain terekam
        if (job.scanId && (job.mode === 'subdomain' || (counts.subdomains || 0) > 0)) {
          rows.push([Markup.button.callback(`🌐 Lihat Subdomain (${counts.subdomains || 0})`, `subs:${job.scanId}:0`)]);
        }
        for (const r of detailRows) rows.push(r);
        markup = Markup.inlineKeyboard(rows);
      } else {
        const base = jobControlKeyboard(job.jobId);
        const rows = (base.reply_markup && base.reply_markup.inline_keyboard) ? base.reply_markup.inline_keyboard.slice() : [];
        for (const r of detailRows) rows.push(r);
        markup = Markup.inlineKeyboard(rows);
      }
      bot.telegram
        .callApi('editMessageText', {
          chat_id: st.chatId,
          message_id: st.messageId,
          rich_message: { blocks },
          reply_markup: markup.reply_markup,
        })
        .catch(async (err) => {
          const msg = String((err && err.message) || err);
          if (/404|not found|unknown method|method not found/i.test(msg)) {
            const lines = snap.stages.map((s) => `${stageIcon(s.status)} ${s.label}`).join('\n');
            const head = `<b>${MODE_LABEL[snap.mode] || snap.mode}</b> - <code>${snap.target}</code>`;
            const tail = snap.finished ? `\n\n<b>Status akhir: ${scanStatusLabel(snap.finished)}</b>` : '';
            bot.telegram
              .editMessageText(st.chatId, st.messageId, null, `${head}\n\n${lines}\n\nSubdomain: ${counts.subdomains || 0} | Host: ${counts.hosts || 0} | Temuan: ${counts.findings || 0}${tail}`, { parse_mode: 'HTML' })
              .catch(() => {});
          }
        });
      // ringkasan laporan kerentanan cerdas - sekali saja saat scan selesai
      if (snap.finished && !st.vrepSent) {
        st.vrepSent = true;
        if (job.scanId) {
          setImmediate(() => sendVulnReportSummary(st.chatId, job.scanId));
        }
      }
    };
  }

  // ---------- middleware ----------
  bot.use(async (ctx, next) => {
    try {
      const from = ctx.from;
      if (!from) return;
      if (!isUserAllowed(config, from.id)) {
        logger.warn(`Akses ditolak untuk user ${from.id}`);
        if (ctx.message) await ctx.reply('Akses ditolak. ID Anda tidak terdaftar pada bot ini.');
        return;
      }
      ctx.role = resolveRole(config, from.id);
      store.upsertUser({ id: from.id, username: from.username || null, isAdmin: ctx.role === 'admin' });
      return next();
    } catch (err) {
      logger.error('Middleware error:', err);
    }
  });

  // ---------- perintah dasar ----------
  bot.start(async (ctx) => {
    await rich.showThinking(ctx, 'Menyiapkan dashboard...', 800);
    const name = ctx.from.first_name || 'there';
    const blocks = [
      rich.paragraph(`Selamat datang, ${name}! Orkestrator security assessment untuk target yang ANDA miliki atau izinkan.`),
      rich.divider(),
      rich.bulletList([
        '/scan domain.com - quick scan',
        '/deepscan domain.com - deep vuln + secrets',
        '/headers domain.com - analisis header instan',
        '/menu - semua perintah',
      ]),
      rich.divider(),
      rich.paragraph(`Engine internal aktif: ${engines.list.filter((e) => e.builtIn).length} modul (tanpa binary eksternal).`),
    ];
    return rich
      .replyRich(ctx, 'CxL Bug Bounty Scanner', blocks, Markup.inlineKeyboard([
        [Markup.button.callback('Menu Utama', 'menu:main'), Markup.button.callback('Mulai Scan', 'menu:scanmenu')],
        [Markup.button.callback('Status Engine', 'menu:tools'), Markup.button.callback('Scope', 'menu:scope')],
        [Markup.button.callback('Riwayat', 'menu:history'), Markup.button.callback('Panduan', 'menu:help')],
      ]));
  });

  // ---------- MENU UTAMA ----------
  bot.command('menu', (ctx) => showMainMenu(ctx));
  bot.action('menu:main', (ctx) => {
    ctx.answerCbQuery().catch(() => {});
    showMainMenu(ctx);
  });

  function showMainMenu(ctx) {
    const blocks = [
      rich.paragraph('Pilih kategori - semua aksi fungsional, tanpa tombol mati.'),
      rich.divider(),
      rich.bulletList([
        'Scan - jalankan scan dalam scope',
        'Tools Instan - hasil langsung tanpa antre',
        'Pekerjaan - status/hasil/riwayat/laporan',
        'Kamus Bug - Vuln ID + severity + contoh payload',
        'Sistem - engine, scope, statistik',
      ]),
    ];
    return rich.replyRich(
      ctx,
      'Menu Utama',
      blocks,
      Markup.inlineKeyboard([
        [Markup.button.callback('Scan', 'menu:scanmenu'), Markup.button.callback('Tools Instan', 'menu:instant')],
        [Markup.button.callback('Pekerjaan', 'menu:jobs'), Markup.button.callback('Kamus Bug', 'menu:vulnlist')],
        [Markup.button.callback('Panduan', 'menu:help'), Markup.button.callback('Refresh', 'menu:main')],
      ])
    );
  }

  bot.action('menu:scanmenu', (ctx) => {
    ctx.answerCbQuery().catch(() => {});
    replyRich(
      ctx,
      'Menu Scan',
      [
        rich.paragraph('Cara tercepat: /scan domain.com → pilih jenis scan via TOMBOL (Full, XSS, SQLi, OWASP, SANS, Malware, dll).'),
        rich.divider(),
        rich.bulletList([
          '/scan - pilih jenis scan via tombol',
          '/fullscan - crawl + vuln scan',
          '/subdomain - enumerasi subdomain (subfinder)',
          '/xss - fokus XSS | /sqli - fokus SQL injection',
          '/owasp - coverage OWASP Top 10:2025',
          '/sans - SANS/CWE Top 25',
          '/malware - deteksi malware/defacement',
          '/deepscan - deep vuln + secrets',
          '/endpoints - kumpulkan endpoint | /secrets - API key bocor',
          '/recon - DNS + subdomain + port',
        ]),
      ],
      Markup.inlineKeyboard([
        [Markup.button.callback('Full Scan', 'menu:full'), Markup.button.callback('XSS Scan', 'menu:xssscan')],
        [Markup.button.callback('SQL Injection', 'menu:sqliscan'), Markup.button.callback('Malware', 'menu:malwarescan')],
        [Markup.button.callback('Recon', 'menu:recon'), Markup.button.callback('Secrets', 'menu:secretsscan')],
        [Markup.button.callback('Kembali', 'menu:main')],
      ])
    );
  });

  bot.action('menu:instant', (ctx) => {
    ctx.answerCbQuery().catch(() => {});
    replyRich(
      ctx,
      'Tools Instan',
      [
        rich.paragraph('Hasil langsung di chat (tanpa antrean). Semua tetap tervalidasi scope.'),
        rich.divider(),
        rich.bulletList([
          '/headers domain.com - header keamanan + skor',
          '/cors domain.com - uji CORS misconfig',
          '/paths domain.com - file sensitif terekspos',
          '/tech domain.com - teknologi terdeteksi',
          '/ports domain.com - port web terbuka',
          '/dnsinfo domain.com - DNS + SPF/DMARC',
          '/ipinfo domain.com - IP/ASN/RDAP',
        ]),
      ],
      Markup.inlineKeyboard([[Markup.button.callback('Kembali', 'menu:main')]])
    );
  });

  bot.action('menu:jobs', (ctx) => {
    ctx.answerCbQuery().catch(() => {});
    replyRich(
      ctx,
      'Pekerjaan & Laporan',
      [
        rich.paragraph('Kelola scan dan hasil:'),
        rich.divider(),
        rich.bulletList([
          '/status - pekerjaan berjalan/antre',
          '/stop - batalkan milik Anda',
          '/results - hasil scan terakhir',
          '/history - riwayat scan',
          '/report jobId - ekspor TXT/JSON/HTML',
          '/vreports - laporan kerentanan cerdas',
        ]),
      ],
      Markup.inlineKeyboard([[Markup.button.callback('Hasil terakhir', 'menu:lastresults'), Markup.button.callback('Riwayat', 'menu:history')], [Markup.button.callback('Kembali', 'menu:main')]])
    );
  });

  bot.action('menu:system', (ctx) => {
    ctx.answerCbQuery().catch(() => {});
    replyRich(
      ctx,
      'Sistem',
      rich.bulletList(['/tools - status engine', '/checktools - verifikasi live', '/installtools - installer (admin)', '/scope - konfigurasi scope', '/stats - statistik lokal']),
      Markup.inlineKeyboard([[Markup.button.callback('Status Engine', 'menu:tools'), Markup.button.callback('Scope', 'menu:scope')], [Markup.button.callback('Statistik', 'menu:stats'), Markup.button.callback('Kembali', 'menu:main')]])
    );
  });

  // shortcut callback untuk mulai scan
  bot.action(/menu:(deep|full|recon|secretsscan|xssscan|sqliscan|malwarescan)/, async (ctx) => {
    try {
      await ctx.answerCbQuery();
      const kind = ctx.match[1];
      const modeMap = { xssscan: 'xss', sqliscan: 'sqli', malwarescan: 'malware', secretsscan: 'secrets' };
      const mode = modeMap[kind] || kind;
      pending.set(`pick-${ctx.from.id}`, { ownerId: ctx.from.id, mode, ts: Date.now(), picking: true });
      await replyRich(
        ctx,
        `Masukkan target untuk ${MODE_LABEL[mode] || mode}`,
        rich.paragraph(`Kirim perintah: /${kind === 'secretsscan' ? 'secrets' : kind === 'xssscan' ? 'xss' : kind === 'sqliscan' ? 'sqli' : kind === 'malwarescan' ? 'malware' : kind} domain.com`)
      );
    } catch (err) {
      logger.error('menu scan shortcut error:', err);
    }
  });

  bot.command('help', (ctx) => {
    const parts = HELP_TEXT.split('\n');
    replyRich(ctx, 'Panduan CxL Scanner', [rich.codeBlock(parts.join('\n'))]);
  });

  bot.action('menu:help', (ctx) => {
    ctx.answerCbQuery().catch(() => {});
    const parts = HELP_TEXT.split('\n');
    replyRich(ctx, 'Panduan CxL Scanner', [rich.codeBlock(parts.join('\n'))]);
  });

  bot.command('scope', (ctx) => {
    const roots = validator.roots;
    const blocks = [
      rich.tableBlock([
        [rich.tableCell('Item', { header: true }), rich.tableCell('Nilai', { header: true })],
        [rich.tableCell('Root domain'), rich.tableCell(roots.length ? roots.join(', ') : '(KOSONG - MODE TERBUKA: domain publik apa pun)')],
        [rich.tableCell('Port'), rich.tableCell(validator.ports.join(', '))],
        [rich.tableCell('Protokol'), rich.tableCell(validator.protocols.join(', '))],
        [rich.tableCell('Lab mode'), rich.tableCell(config.labMode ? `AKTIF (${config.labTargets.join(', ') || '-'})` : 'mati')],
        [rich.tableCell('Fallback internal'), rich.tableCell(config.internalFallback === false ? 'mati' : 'aktif (scan tetap jalan tanpa binary eksternal)')],
      ]),
      rich.quoteBlock('Isi ALLOWED_TARGETS di .env untuk mengunci scanner ke domain Anda. Kosong = mode terbuka.'),
    ];
    replyRich(ctx, 'Konfigurasi Scope', blocks);
  });

  bot.action('menu:scope', (ctx) => {
    ctx.answerCbQuery().catch(() => {});
    const roots = validator.roots;
    replyRich(ctx, 'Konfigurasi Scope', [
      rich.paragraph(`Root domain: ${roots.length ? roots.join(', ') : '(kosong - MODE TERBUKA: domain publik apa pun)'}`),
      rich.paragraph(`Port: ${validator.ports.join(', ')} | Protokol: ${validator.protocols.join(', ')}`),
    ]);
  });

  // ---------- perintah scan ----------
  // /scan domain.com -> MENU PILIH JENIS SCAN (tombol): full, XSS, SQLi, OWASP, SANS, malware, quick, subdomain
  bot.command('scan', (ctx) => {
    const t = requireTargetArg(ctx);
    if (!t) return;
    const nonce = randomId('p').slice(0, 16);
    pending.set(nonce, { ownerId: ctx.from.id, host: t.host, root: t.root, ts: Date.now(), picking: true });
    const buttons = SCAN_PICKER.map((p) => [Markup.button.callback(p.label, `sm:${p.mode}:${nonce}`)]);
    buttons.push([Markup.button.callback('Batal', `cx:${nonce}`)]);
    replyRich(
      ctx,
      'Pilih Jenis Scan',
      [
        rich.paragraph(`Target: ${t.host}`),
        rich.paragraph('Pilih jenis pemindaian dari tombol di bawah:'),
        rich.bulletList(SCAN_PICKER.map((p) => `${p.label} - ${p.desc}`)),
      ],
      Markup.inlineKeyboard(buttons)
    );
  });

  bot.action(/sm:(\w+):(n?[a-z0-9]+)/, async (ctx) => {
    try {
      await ctx.answerCbQuery();
      const [, mode, nonce] = ctx.match;
      const p = pending.get(nonce);
      if (!p || p.ownerId !== ctx.from.id || !p.picking) {
        await replyRich(ctx, 'Kedaluwarsa', rich.paragraph('Pilihan tidak valid / kedaluwarsa. Kirim ulang /scan domain.com.'));
        return;
      }
      pending.delete(nonce);
      if (!MODE_LABEL[mode]) {
        replyRich(ctx, 'Mode tidak dikenal', rich.paragraph(`Mode "${sanitizeText(mode, 30)}" tidak tersedia.`));
        return;
      }
      await offerScan(ctx, mode, { host: p.host, root: p.root });
    } catch (err) {
      logger.error('action sm error:', err);
    }
  });

  bot.command('fullscan', (ctx) => {
    const t = requireTargetArg(ctx);
    if (t) offerScan(ctx, 'full', t);
  });

  bot.command('subdomain', (ctx) => {
    // Format: /subdomain domain.com | /subdomain -subfinder domain.com | /subdomain domain.com -subfinder
    const parts = String(ctx.message.text || '').trim().split(/\s+/).slice(1);
    const flagIdx = parts.findIndex((a) => /^-{1,2}subfinder$/i.test(a));
    if (flagIdx >= 0) parts.splice(flagIdx, 1); // -subfinder adalah engine default; diterima & diabaikan
    const arg = parts[0] || '';
    if (!arg) {
      replyRich(ctx, 'Format salah', rich.paragraph('Gunakan: /subdomain domain.com (opsional: -subfinder)'));
      return;
    }
    const v = validator.validateTargetInput(arg);
    if (!v.ok) {
      replyRich(ctx, 'Ditolak', rich.paragraph(v.reason));
      return;
    }
    offerScan(ctx, 'subdomain', v);
  });

  bot.command('xss', (ctx) => {
    const t = requireTargetArg(ctx);
    if (t) offerScan(ctx, 'xss', t);
  });

  bot.command('sqli', (ctx) => {
    const t = requireTargetArg(ctx);
    if (t) offerScan(ctx, 'sqli', t);
  });

  bot.command('sans', (ctx) => {
    const t = requireTargetArg(ctx);
    if (t) offerScan(ctx, 'sans', t);
  });

  bot.command('malware', (ctx) => {
    const t = requireTargetArg(ctx);
    if (t) offerScan(ctx, 'malware', t);
  });

  bot.command('deepscan', (ctx) => {
    const t = requireTargetArg(ctx);
    if (t) offerScan(ctx, 'deep', t, { deepVuln: true });
  });

  bot.command('owasp', (ctx) => {
    const t = requireTargetArg(ctx);
    if (t) offerScan(ctx, 'owasp', t);
  });

  bot.command('endpoints', (ctx) => {
    const t = requireTargetArg(ctx);
    if (t) offerScan(ctx, 'endpoints', t);
  });

  bot.command('secrets', (ctx) => {
    const t = requireTargetArg(ctx);
    if (t) offerScan(ctx, 'secrets', t);
  });

  bot.command('recon', (ctx) => {
    const t = requireTargetArg(ctx);
    if (t) offerScan(ctx, 'recon', t);
  });

  bot.command('nuclei', (ctx) => {
    const t = requireTargetArg(ctx);
    if (!t) return;
    const nonce = randomId('s').slice(0, 16);
    pending.set(nonce, { ownerId: ctx.from.id, username: ctx.from.username || null, mode: 'nuclei-pick', host: t.host, root: t.root, ts: Date.now(), options: {} });
    replyRich(
      ctx,
      'Pilih batas severity',
      rich.paragraph(`Target: ${t.host}\nSemua pilihan tetap non-destruktif.`),
      Markup.inlineKeyboard([
        [Markup.button.callback('info+', `sev:info:${nonce}`), Markup.button.callback('low+', `sev:low:${nonce}`)],
        [Markup.button.callback('medium+', `sev:medium:${nonce}`), Markup.button.callback('high+', `sev:high:${nonce}`)],
        [Markup.button.callback('critical saja', `sev:critical:${nonce}`), Markup.button.callback('Batal', `cx:${nonce}`)],
      ])
    );
  });

  // ---------- callback handlers ----------
  bot.action(/sev:(\w+):(n[a-z0-9]+)/, async (ctx) => {
    try {
      const [, sev, nonce] = ctx.match;
      const p = pending.get(nonce);
      if (!p || p.ownerId !== ctx.from.id) {
        await ctx.answerCbQuery('Konfirmasi tidak valid / bukan milik Anda');
        return;
      }
      const order = ['info', 'low', 'medium', 'high', 'critical'];
      const idx = order.indexOf(sev);
      const severities = sev === 'critical' ? ['critical'] : order.slice(idx);
      await ctx.answerCbQuery();
      await offerScan(ctx, 'nuclei', { host: p.host, root: p.root }, { severity: severities });
    } catch (err) {
      logger.error('action sev error:', err);
    }
  });

  bot.action(/go:(n[a-z0-9]+)/, async (ctx) => {
    try {
      const nonce = ctx.match[1];
      const p = pending.get(nonce);
      if (!p || p.ownerId !== ctx.from.id) {
        await ctx.answerCbQuery('Konfirmasi tidak valid / kedaluwarsa');
        return;
      }
      pending.delete(nonce);
      await ctx.answerCbQuery('Memasukkan ke antrean');
      // validasi ulang target saat eksekusi (anti TOCTOU UI)
      const revalidate = validator.validateTargetInput(p.host);
      if (!revalidate.ok) {
        replyRich(ctx, 'Ditolak', rich.paragraph(revalidate.reason));
        return;
      }
      if (p.mode !== 'nuclei-pick') {
        const canQ = queue.canEnqueue(ctx.from.id);
        if (!canQ.ok) {
          replyRich(ctx, 'Antrean penuh', rich.paragraph(canQ.reason));
          return;
        }
      }
      const jobId = randomId('job').replace(/[^a-z0-9-]/g, '');
      const job = {
        jobId,
        ownerId: ctx.from.id,
        ownerUsername: p.username,
        mode: p.mode === 'nuclei-pick' ? 'nuclei' : p.mode,
        target: revalidate.host,
        scopeRoot: revalidate.root,
        options: p.options || {},
      };
      job.onProgress = makeProgressHandler(job);
      queue.enqueue(job);
      worker.kick();
      const msg = await replyRich(
        ctx,
        `Job masuk antrean`,
        [
          rich.paragraph(`Job ID: ${jobId}`),
          rich.paragraph(`Mode: ${MODE_LABEL[job.mode] || job.mode}`),
          rich.paragraph(`Target: ${job.target}`),
          rich.paragraph('Progres diperbarui otomatis di pesan ini.'),
        ],
        jobControlKeyboard(jobId)
      );
      if (msg) progressEdits.set(jobId, { chatId: msg.chat ? msg.chat.id : ctx.chat.id, messageId: msg.message_id, lastEdit: 0, lastSnap: null });
    } catch (err) {
      logger.error('action go error:', err);
    }
  });

  bot.action(/cx:(n[a-z0-9]+)/, async (ctx) => {
    const nonce = ctx.match[1];
    const p = pending.get(nonce);
    if (p && p.ownerId === ctx.from.id) pending.delete(nonce);
    await ctx.answerCbQuery('Dibatalkan');
    try {
      await rich.editRich(ctx, [rich.heading('Dibatalkan'), rich.paragraph('Konfirmasi dibatalkan. Tidak ada scan dijalankan.')]);
    } catch (_) {
      /* diamkan */
    }
  });

  /** Keyboard kontrol job: stop scan, cek status, hasil, laporan. */
  function jobControlKeyboard(jobId) {
    return Markup.inlineKeyboard([
      [Markup.button.callback('⏹ Stop Scan', `stop:${jobId}`), Markup.button.callback('📋 Cek Status', `jst:${jobId}`)],
      [Markup.button.callback('📄 Hasil', 'menu:lastresults'), Markup.button.callback('🗂 Laporan', 'menu:lastreport')],
    ]);
  }

  /** Render status live sebuah job (dari snapshot progress atau DB). */
  function renderJobStatus(jobId, snap, scanRow) {
    const blocks = [rich.paragraph(`Job ID: ${jobId}`)];
    if (snap) {
      blocks.push(rich.paragraph(`Mode: ${MODE_LABEL[snap.mode] || snap.mode} | Target: ${snap.target}`));
      blocks.push(rich.divider());
      blocks.push(rich.bulletList(snap.stages.map((s) => `${stageIcon(s.status)} ${s.label}`)));
      blocks.push(rich.divider());
      const counts = snap.counts || {};
      blocks.push(rich.paragraph(`Subdomain: ${counts.subdomains || 0} | Host: ${counts.hosts || 0} | Endpoint: ${counts.endpoints || 0} | Temuan: ${counts.findings || 0}`));
      if (snap.finished) blocks.push(rich.paragraph(`Status akhir: ${scanStatusLabel(snap.finished)}`));
      else blocks.push(rich.quoteBlock('Scan sedang berjalan. Gunakan tombol Stop untuk membatalkan.'));
    } else if (scanRow) {
      blocks.push(rich.tableBlock([
        [rich.tableCell('Item', { header: true }), rich.tableCell('Nilai', { header: true })],
        [rich.tableCell('Mode'), rich.tableCell(MODE_LABEL[scanRow.mode] || scanRow.mode)],
        [rich.tableCell('Target'), rich.tableCell(scanRow.target)],
        [rich.tableCell('Status'), rich.tableCell(scanStatusLabel(scanRow.status))],
        [rich.tableCell('Tahap'), rich.tableCell(scanRow.stage_label || '-')],
        [rich.tableCell('Temuan'), rich.tableCell(String(store.countFindings(scanRow.id)))],
        [rich.tableCell('Subdomain'), rich.tableCell(String(store.countSubdomains(scanRow.id)))],
      ]));
      if (scanRow.error) blocks.push(rich.paragraph(`Error: ${sanitizeText(scanRow.error, 200)}`));
    } else {
      blocks.push(rich.paragraph('Job tidak ditemukan. Cek /status atau /history.'));
    }
    return blocks;
  }

  bot.action(/jst:([a-z0-9-]+)/, async (ctx) => {
    try {
      const jobId = ctx.match[1];
      await ctx.answerCbQuery('Mengambil status');
      const scanRow = store.getScanByJobId(jobId);
      if (!scanRow || (scanRow.owner_id !== ctx.from.id && ctx.role !== 'admin')) {
        await ctx.answerCbQuery('Job tidak ditemukan / bukan milik Anda');
        return;
      }
      const st = progressEdits.get(jobId);
      const snap = st && st.lastSnap ? st.lastSnap : null;
      const keyboard = snap && !snap.finished ? jobControlKeyboard(jobId) : undefined;
      await replyRich(ctx, `Status Job - ${MODE_LABEL[snap ? snap.mode : scanRow.mode] || 'Scan'}`, renderJobStatus(jobId, snap, scanRow), keyboard);
    } catch (err) {
      logger.error('action jst error:', err);
    }
  });

  /** Lihat daftar subdomain hasil enumerasi (tombol pada scan subdomain). */
  bot.action(/subs:(\d+):?(\d+)?/, async (ctx) => {
    try {
      const scanId = Number(ctx.match[1]);
      const page = Number(ctx.match[2] || 0);
      const scan = store.getScan(scanId);
      if (!scan || (scan.owner_id !== ctx.from.id && ctx.role !== 'admin')) {
        await ctx.answerCbQuery('Scan tidak ditemukan / bukan milik Anda');
        return;
      }
      await ctx.answerCbQuery('Memuat subdomain');
      const perPage = 30;
      const all = store.listSubdomains ? store.listSubdomains(scanId, 2000) : [];
      const total = all.length;
      if (!total) {
        replyRich(ctx, 'Subdomain', rich.paragraph('Tidak ada subdomain terekam untuk scan ini.'));
        return;
      }
      const slice = all.slice(page * perPage, (page + 1) * perPage);
      const blocks = [
        rich.paragraph(`Target: ${scan.target} | Total: ${total} subdomain`),
        rich.divider(),
        rich.bulletList(slice.map((s) => `${s.host}${s.source ? ` (${s.source})` : ''}`)),
        rich.divider(),
        rich.paragraph(`Halaman ${page + 1}/${Math.ceil(total / perPage)}`),
      ];
      const nav = [];
      if (page > 0) nav.push(Markup.button.callback('Sebelumnya', `subs:${scanId}:${page - 1}`));
      if ((page + 1) * perPage < total) nav.push(Markup.button.callback('Berikutnya', `subs:${scanId}:${page + 1}`));
      const rows = nav.length ? [nav] : [];
      rows.push([Markup.button.callback('Hasil lengkap', 'menu:lastresults'), Markup.button.callback('Laporan', 'menu:lastreport')]);
      replyRich(ctx, `Subdomain ${scan.target}`, blocks, Markup.inlineKeyboard(rows));
    } catch (err) {
      logger.error('action subs error:', err);
    }
  });

  bot.action(/stop:([a-z0-9-]+)/, async (ctx) => {
    try {
      const jobId = ctx.match[1];
      const res = queue.cancel(jobId, ctx.from.id, ctx.role === 'admin');
      await ctx.answerCbQuery(res.reason.slice(0, 190));
    } catch (err) {
      logger.error('action stop error:', err);
    }
  });

  // ---------- DETAIL BUG (KB): tombol dari live scan / hasil + perintah /vuln ----------
  bot.action(/vb:(\d+):([a-f0-9]{16})/, async (ctx) => {
    try {
      const scanId = Number(ctx.match[1]);
      const hash = ctx.match[2];
      const scan = store.getScan(scanId);
      if (!scan || (scan.owner_id !== ctx.from.id && ctx.role !== 'admin')) {
        await ctx.answerCbQuery('Scan tidak ditemukan / bukan milik Anda');
        return;
      }
      const finding = store.getFindingByDedupe(scanId, hash);
      if (!finding) {
        await ctx.answerCbQuery('Temuan tidak ditemukan');
        return;
      }
      await ctx.answerCbQuery('Detail bug');
      const blocks = renderBugDetailBlocks(finding);
      const kb = kbFor(finding.external_id, finding.evidence);
      const rows = [];
      if (kb && kb.reference) rows.push([Markup.button.url('📖 Referensi', kb.reference)]);
      rows.push([Markup.button.callback('⬅️ Kembali ke Hasil', 'menu:lastresults')]);
      replyRich(ctx, `Detail Bug ${ (kb && kb.vulnId) || '' }`.trim(), blocks, Markup.inlineKeyboard(rows));
    } catch (err) {
      logger.error('action vb error:', err);
    }
  });

  // Detail bug langsung dari KB (tanpa scan), dipakai tombol daftar /vuln
  bot.action(/kb:([a-z0-9-]+)/, async (ctx) => {
    try {
      const key = ctx.match[1];
      const kb = kbEntry(key);
      if (!kb) {
        await ctx.answerCbQuery('Bug tidak ditemukan di KB');
        return;
      }
      await ctx.answerCbQuery('Detail bug');
      const blocks = renderBugDetailBlocks(null, { externalId: keyToExternalId(key), severity: kb.severity, name: kb.name });
      const rows = [];
      if (kb.reference) rows.push([Markup.button.url('📖 Referensi', kb.reference)]);
      rows.push([Markup.button.callback('⬅️ Daftar Bug', 'menu:vulnlist')]);
      replyRich(ctx, `Detail Bug ${kb.vulnId}`, blocks, Markup.inlineKeyboard(rows));
    } catch (err) {
      logger.error('action kb error:', err);
    }
  });

  // Pemetaan key KB -> externalId representatif agar kbFor resolusi balik akurat
  function keyToExternalId(key) {
    const MAP = {
      'env-exposed': 'exposed:/.env',
      'aws-creds-exposed': 'exposed:/.aws/credentials',
      'db-dump-exposed': 'exposed:/db.sql',
      'backup-exposed': 'exposed:/backup.zip',
      'secret-leak': 'secret:api-key:example',
      'subdomain-takeover': 'takeover:AWS S3',
      'malware-detected': 'malware:webshell',
      'git-exposed': 'exposed:/.git/HEAD',
      'svn-exposed': 'exposed:/.svn/entries',
      'phpinfo-exposed': 'exposed:/phpinfo.php',
      'actuator-exposed': 'exposed:/actuator/env',
      'xss-reflected': 'xss:reflected:q',
      'sql-injection': 'sqli:error-signature:q',
      'path-traversal': 'traversal:param:q',
      'tls-expired': 'tls:cert-expired',
      'cors-reflected': 'cors:reflected-origin',
      'xss-encoded': 'xss:reflected-encoded:q',
      'open-redirect': 'redirect:open:q',
      'redirect-downgrade': 'redirect:downgrade',
      'cors-wildcard-creds': 'cors:wildcard-credentials',
      'dirlisting': 'page:dirlisting',
      'stack-trace': 'info:stacktrace:sql',
      'cookie-flags': 'cookie:flags',
      'mixed-content': 'page:mixed-content',
      'http-methods': 'http:dangerous-methods',
      'cors-wildcard-auth': 'cors:wildcard-auth-headers',
      'phpmyadmin-exposed': 'exposed:/phpmyadmin',
      'wp-user-enum': 'exposed:/wp-json/wp/v2/users',
      'actuator-or-config': 'exposed:/.htaccess',
      'server-status': 'exposed:/server-status',
      'graphql-open': 'exposed:/graphql',
      'swagger-exposed': 'exposed:/swagger.json',
      'crossdomain-permissive': 'exposed:/crossdomain.xml',
      'tls-version': 'tls:weak-version',
      'tls-cert': 'tls:cert',
      'hsts-missing': 'sec:hsts-missing',
      'csp-missing': 'sec:csp-missing',
      'csp-unsafe': 'sec:csp-unsafe-inline',
      'clickjacking': 'sec:clickjacking',
      'xcto-missing': 'sec:xcto-missing',
      'referrer-missing': 'sec:referrer-missing',
      'permissions-missing': 'sec:permissions-missing',
      'server-version': 'info:server-version',
      'email-internal': 'info:emails',
      'private-ip': 'info:private-ip',
      'error-5xx': 'page:5xx',
      'ports-open': 'ports:open:8080',
      'header-weak': 'header:X-Frame-Options',
      'robots-intel': 'recon:robots-paths',
      'spf-missing': 'email:spf-missing',
      'dmarc-missing': 'email:dmarc-missing',
      'recon-info': 'recon:robots-paths',
    };
    return MAP[key] || key;
  }

  // Daftar semua bug di KB (tombol + severity + Vuln ID)
  function renderKbListBlocks() {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const all = kbList()
      .map((k) => ({ key: k, e: kbEntry(k) }))
      .filter((x) => x.e)
      .sort((a, b) => (order[a.e.severity] ?? 9) - (order[b.e.severity] ?? 9) || a.e.vulnId.localeCompare(b.e.vulnId));
    const bySev = {};
    for (const { key, e } of all) {
      (bySev[e.severity] = bySev[e.severity] || []).push({ key, e });
    }
    const blocks = [
      rich.paragraph(`Kamus bug internal: ${all.length} jenis kerentanan dengan Vuln ID, CWE, contoh payload, dan contoh bug detail.`),
      rich.quoteBlock('Klik tombol di bawah untuk melihat detail tiap bug. Cari cepat: /vuln xss atau /vuln CXL-021.'),
    ];
    const rows = [];
    for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
      const group = bySev[sev] || [];
      if (!group.length) continue;
      blocks.push(rich.paragraph(`${sevEmoji(sev)} ${sev.toUpperCase()} (${group.length})`));
      blocks.push(
        rich.bulletList(
          group.map(({ e }) => `[${e.vulnId}] ${e.name} (${e.cwe})`)
        )
      );
      for (let i = 0; i < group.length; i += 2) {
        rows.push(group.slice(i, i + 2).map(({ key, e }) => Markup.button.callback(`🔎 ${e.vulnId}`, `kb:${key}`)));
      }
    }
    return { blocks, rows };
  }

  bot.command('vuln', (ctx) => {
    const parts = String(ctx.message && ctx.message.text ? ctx.message.text : '').trim().split(/\s+/);
    const q = parts.slice(1).join(' ');
    if (!q) {
      const { blocks, rows } = renderKbListBlocks();
      replyRich(ctx, 'Kamus Kerentanan (KB Bug)', blocks, Markup.inlineKeyboard(rows));
      return;
    }
    const lower = q.toLowerCase();
    // 1) cari Vuln ID persis (CXL-xxx)
    const byVulnId = kbList().map((k) => kbEntry(k)).find((e) => e && e.vulnId.toLowerCase() === lower);
    if (byVulnId) {
      replyVulnDetail(ctx, byVulnId);
      return;
    }
    // 2) cari CWE persis
    const byCwe = kbList().map((k) => kbEntry(k)).find((e) => e && e.cwe.toLowerCase() === lower);
    if (byCwe) {
      replyVulnDetail(ctx, byCwe);
      return;
    }
    // 3) pencarian bebas
    const hits = kbSearch(q);
    if (!hits.length) {
      replyRich(ctx, 'Bug tidak ditemukan', rich.paragraph(`Tidak ada bug yang cocok dengan "${q}". Coba: /vuln xss, /vuln sql, /vuln CXL-001, /vuln CWE-79`));
      return;
    }
    if (hits.length === 1) {
      replyVulnDetail(ctx, hits[0]);
      return;
    }
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    hits.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
    const blocks = [
      rich.paragraph(`${hits.length} bug cocok dengan "${q}":`),
      rich.bulletList(hits.map((e) => `${sevEmoji(e.severity)} [${e.vulnId}] ${e.name} (${e.cwe})`)),
      rich.quoteBlock('Klik tombol untuk melihat detail lengkap bug-nya.'),
    ];
    const keyByVulnId = {};
    for (const k of kbList()) keyByVulnId[kbEntry(k).vulnId] = k;
    const rows = [];
    for (let i = 0; i < hits.length; i += 2) {
      rows.push(
        hits.slice(i, i + 2).map((e) => Markup.button.callback(`🔎 ${e.vulnId}`, `kb:${keyByVulnId[e.vulnId]}`))
      );
    }
    replyRich(ctx, `Hasil Pencarian Bug: ${q}`, blocks, Markup.inlineKeyboard(rows));
  });

  function replyVulnDetail(ctx, kb) {
    const keyByVulnId = {};
    for (const k of kbList()) keyByVulnId[kbEntry(k).vulnId] = k;
    const blocks = renderBugDetailBlocks(null, {
      externalId: keyToExternalId(keyByVulnId[kb.vulnId]),
      severity: kb.severity,
      name: kb.name,
    });
    const rows = [];
    if (kb.reference) rows.push([Markup.button.url('📖 Referensi', kb.reference)]);
    rows.push([Markup.button.callback('⬅️ Daftar Bug', 'menu:vulnlist')]);
    replyRich(ctx, `Detail Bug ${kb.vulnId}`, blocks, Markup.inlineKeyboard(rows));
  }

  bot.action('menu:vulnlist', (ctx) => {
    ctx.answerCbQuery().catch(() => {});
    const { blocks, rows } = renderKbListBlocks();
    replyRich(ctx, 'Kamus Kerentanan (KB Bug)', blocks, Markup.inlineKeyboard(rows));
  });


  // ---------- TOOLS INSTAN (hasil langsung, tanpa antrean) ----------
  // Validasi scope + guard jaringan tetap berlaku sebelum satu request pun dikirim.
  async function guardTarget(ctx, host) {
    if (!validator.hostInScope(host)) {
      const why = validator.openMode
        ? `${host} bukan domain yang valid (IP privat/internal selalu ditolak).`
        : `${host} tidak berada dalam ALLOWED_TARGETS. Cek /scope.`;
      replyRich(ctx, 'Di luar scope', rich.paragraph(why));
      return null;
    }
    const g = await guard.checkHost(host, { scanId: null, stage: 'instant-tool' });
    if (!g.allowed) {
      replyRich(ctx, 'Ditolak guard jaringan', rich.paragraph(g.reason || 'target tidak diizinkan'));
      return null;
    }
    return g; // { allowed, ips }
  }

  function instantUserAgent() {
    return config.userAgent;
  }

  bot.command('headers', async (ctx) => {
    const t = requireTargetArg(ctx);
    if (!t) return;
    const g = await guardTarget(ctx, t.host);
    if (!g) return;
    const ip = (g.ips && g.ips[0]) || null;
    await rich.showThinking(ctx, 'Memeriksa header keamanan...', 500);
    try {
      const url = `https://${t.host}`;
      const r = await requestFollow({ url, ip, method: 'GET', timeoutMs: 10000, maxBodyBytes: 128 * 1024, maxRedirects: 3, userAgent: instantUserAgent() });
      if (!r.ok || !r.status) {
        const r2 = await requestFollow({ url: `http://${t.host}`, ip, method: 'GET', timeoutMs: 10000, maxBodyBytes: 128 * 1024, maxRedirects: 3, userAgent: instantUserAgent() });
        if (!r2.ok || !r2.status) {
          replyRich(ctx, 'Tidak terjangkau', rich.paragraph(`Tidak bisa menghubungi ${t.host}`));
          return;
        }
        r.ok = r2.ok; r.status = r2.status; r.headers = r2.headers; r.body = r2.body; r.tlsProto = r2.tlsProto; r.finalUrl = r2.finalUrl;
      }
      const h = {};
      for (const k of Object.keys(r.headers || {})) h[k.toLowerCase()] = r.headers[k];
      const findings = evaluateSecurityPosture({ url: r.finalUrl || url, status: r.status, headers: r.headers, body: String(r.body || ''), tlsProto: r.tlsProto });
      const headerRows = [
        rich.tableCell('Header', { header: true }),
        rich.tableCell('Status', { header: true }),
        rich.tableCell('Nilai', { header: true }),
      ];
      for (const name of ['strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy', 'server', 'x-powered-by']) {
        const v = h[name] ? String(h[name]).slice(0, 60) : '(tidak ada)';
        headerRows.push(rich.tableRow(rich.tableCell(name), rich.tableCell(h[name] ? 'ada' : 'MISSING'), rich.tableCell(v)));
      }
      const bad = findings.filter((f) => f.severity === 'high' || f.severity === 'medium');
      const warn = findings.filter((f) => f.severity === 'low');
      const info = findings.filter((f) => f.severity === 'info');
      const score = Math.max(0, 100 - bad.length * 15 - warn.length * 5);
      const blocks = [
        rich.tableBlock(headerRows),
        rich.divider(),
        rich.paragraph(`Skor header: ${score}/100 | Status: ${r.status} | TLS: ${r.tlsProto || '-'} | Server: ${String(h.server || '-').slice(0, 40)}`),
        rich.paragraph(`Masalah: ${bad.length} medium/high, ${warn.length} low, ${info.length} info`),
      ];
      if (bad.length) blocks.push(rich.divider(), rich.bulletList(bad.slice(0, 8).map((f) => `[${f.severity.toUpperCase()}] ${f.name}`)));
      if (warn.length) blocks.push(rich.bulletList(warn.slice(0, 6).map((f) => `[${f.severity.toUpperCase()}] ${f.name}`)));
      blocks.push(rich.quoteBlock('Skor indikatif - hasil otomatis perlu verifikasi manual.'));
      replyRich(ctx, `Analisis Header - ${t.host}`, blocks);
    } catch (err) {
      logger.error('/headers error:', err);
      replyRich(ctx, 'Error', rich.paragraph(sanitizeText(err.message, 200)));
    }
  });

  bot.command('cors', async (ctx) => {
    const t = requireTargetArg(ctx);
    if (!t) return;
    const g = await guardTarget(ctx, t.host);
    if (!g) return;
    const ip = (g.ips && g.ips[0]) || null;
    await rich.showThinking(ctx, 'Menguji konfigurasi CORS...', 500);
    try {
      const probes = [
        { label: 'origin acak', origin: 'https://cxl-cors-probe.example.net' },
        { label: 'origin null', origin: 'null' },
        { label: 'subdomain-like', origin: `https://${t.host}.evil.example.net` },
      ];
      const rows = [rich.tableCell('Pengujian', { header: true }), rich.tableCell('ACAO', { header: true }), rich.tableCell('Credentials', { header: true }), rich.tableCell('Hasil', { header: true })];
      const issues = [];
      for (const p of probes) {
        const r = await requestPinned({ url: `https://${t.host}/`, ip, method: 'GET', timeoutMs: 10000, maxBodyBytes: 8 * 1024, userAgent: instantUserAgent(), headers: { Origin: p.origin } });
        const h = {};
        for (const k of Object.keys(r.headers || {})) h[k.toLowerCase()] = r.headers[k];
        const acao = String(h['access-control-allow-origin'] || '(absen)');
        const acac = String(h['access-control-allow-credentials'] || '(absen)');
        let result = 'aman';
        if (acao === p.origin && p.label !== 'origin acak') {
          result = 'REFLEKSI BERBAHAYA';
          issues.push(`Origin ${p.label} direfleksikan${acac === 'true' ? ' + credentials=true' : ''}`);
        } else if (acao === p.origin) {
          result = 'REFLEKSI';
          issues.push('Origin arbitrer direfleksikan');
        } else if (acao === '*' && acac === 'true') {
          result = 'WILDCARD+CREDS';
          issues.push('Wildcard dengan credentials');
        }
        rows.push(rich.tableRow(rich.tableCell(p.label), rich.tableCell(acao.slice(0, 40)), rich.tableCell(acac.slice(0, 12)), rich.tableCell(result)));
      }
      const blocks = [rich.tableBlock(rows)];
      blocks.push(rich.divider(), issues.length ? rich.paragraph(`Ditemukan ${issues.length} masalah:`) : rich.paragraph('Tidak ada konfigurasi CORS berbahaya yang terdeteksi pada uji ini.'));
      if (issues.length) blocks.push(rich.bulletList(issues.slice(0, 5)));
      blocks.push(rich.quoteBlock('Uji dilakukan pada halaman root saja. Endpoint API lain bisa berbeda - cek manual.'));
      replyRich(ctx, `Uji CORS - ${t.host}`, blocks);
    } catch (err) {
      logger.error('/cors error:', err);
      replyRich(ctx, 'Error', rich.paragraph(sanitizeText(err.message, 200)));
    }
  });

  bot.command('paths', async (ctx) => {
    const t = requireTargetArg(ctx);
    if (!t) return;
    const g = await guardTarget(ctx, t.host);
    if (!g) return;
    const ip = (g.ips && g.ips[0]) || null;
    await rich.showThinking(ctx, 'Memeriksa file sensitif terekspos...', 800);
    try {
      const base = `https://${t.host}`;
      const found = [];
      const checked = { n: 0 };
      const critical = EXPOSED_PATHS.filter((e) => e.severity === 'critical' || e.severity === 'high');
      const others = EXPOSED_PATHS.filter((e) => e.severity !== 'critical' && e.severity !== 'high');
      for (const ex of [...critical, ...others]) {
        const probeUrl = new URL(ex.path, base).toString();
        const r = await requestPinned({ url: probeUrl, ip, method: 'GET', timeoutMs: 8000, maxBodyBytes: 4 * 1024, maxRedirects: 0, userAgent: instantUserAgent() });
        checked.n++;
        if (!r.ok || !r.status) continue;
        const ctype = String((r.headers && r.headers['content-type']) || '');
        let hit = false;
        if (ex.sigType === 'body' && ex.sig && ex.sig.test(String(r.body || ''))) hit = true;
        else if (ex.sigType === 'nonhtml200' && r.status === 200 && !/text\/html/i.test(ctype)) hit = true;
        else if (ex.sigType === 'status200' && r.status === 200) hit = true;
        else if (ex.sigType === 'magic' && r.status === 200 && !/text\/html/i.test(ctype)) hit = true;
        if (hit) found.push({ path: ex.path, name: ex.name, severity: ex.severity, status: r.status });
      }
      const blocks = [
        rich.paragraph(`${checked.n} path diperiksa pada ${base}`),
        rich.divider(),
      ];
      if (found.length) {
        blocks.push(rich.tableBlock([
          rich.tableCell('Path', { header: true }),
          rich.tableCell('Severity', { header: true }),
          rich.tableCell('Keterangan', { header: true }),
        ].concat(found.map((f) => rich.tableRow(rich.tableCell(f.path), rich.tableCell(f.severity.toUpperCase()), rich.tableCell(f.name.slice(0, 44)))))));
        blocks.push(rich.quoteBlock('Isi file TIDAK diunduh/disimpan (kebijakan privasi). Segera amankan jika benar-benar terekspos.'));
      } else {
        blocks.push(rich.paragraph('Tidak ada file sensitif yang terdeteksi terekspos pada daftar pemeriksaan.'));
      }
      replyRich(ctx, `Pemindaian Path - ${t.host}`, blocks);
    } catch (err) {
      logger.error('/paths error:', err);
      replyRich(ctx, 'Error', rich.paragraph(sanitizeText(err.message, 200)));
    }
  });

  bot.command('tech', async (ctx) => {
    const t = requireTargetArg(ctx);
    if (!t) return;
    const g = await guardTarget(ctx, t.host);
    if (!g) return;
    const ip = (g.ips && g.ips[0]) || null;
    await rich.showThinking(ctx, 'Mengidentifikasi teknologi...', 500);
    try {
      let r = await requestFollow({ url: `https://${t.host}`, ip, method: 'GET', timeoutMs: 10000, maxBodyBytes: 200 * 1024, maxRedirects: 3, userAgent: instantUserAgent() });
      if ((!r.ok || !r.status) ) {
        r = await requestFollow({ url: `http://${t.host}`, ip, method: 'GET', timeoutMs: 10000, maxBodyBytes: 200 * 1024, maxRedirects: 3, userAgent: instantUserAgent() });
      }
      if (!r.ok || !r.status) {
        replyRich(ctx, 'Tidak terjangkau', rich.paragraph(`Tidak bisa menghubungi ${t.host}`));
        return;
      }
      const tech = detectTech({ headers: r.headers, body: r.body });
      const byCat = summarizeTech(tech);
      const title = extractTitle(r.body);
      const blocks = [
        rich.paragraph(`Status: ${r.status} | Title: ${title || '(tanpa title)'}`),
        rich.paragraph(`Server: ${String((r.headers && r.headers.server) || '-').slice(0, 60)}`),
        rich.divider(),
      ];
      const cats = Object.keys(byCat);
      if (!cats.length) {
        blocks.push(rich.paragraph('Tidak ada teknologi yang teridentifikasi secara pasti.'));
      } else {
        for (const c of cats) {
          blocks.push(rich.paragraph(`${c}:`), rich.bulletList(byCat[c].slice(0, 6)));
        }
      }
      blocks.push(rich.quoteBlock('Deteksi pasif dari header/body. Versi terdeteksi != kerentanan; cocokkan dengan advisori.'));
      replyRich(ctx, `Teknologi - ${t.host}`, blocks);
    } catch (err) {
      logger.error('/tech error:', err);
      replyRich(ctx, 'Error', rich.paragraph(sanitizeText(err.message, 200)));
    }
  });

  bot.command('ports', async (ctx) => {
    const t = requireTargetArg(ctx);
    if (!t) return;
    const g = await guardTarget(ctx, t.host);
    if (!g) return;
    await rich.showThinking(ctx, 'Memindai port web umum...', 800);
    try {
      const eng = new PortsInternalEngine(config, logger);
      const fakeCtx = { signal: null, scanId: null, store: null };
      const res = await eng.run(fakeCtx, { host: t.host, ips: g.ips || [] });
      const open = res.items || [];
      const rows = [rich.tableCell('Host', { header: true }), rich.tableCell('Port', { header: true }), rich.tableCell('Status', { header: true })];
      for (const p of open) rows.push(rich.tableRow(rich.tableCell(t.host), rich.tableCell(String(p.port)), rich.tableCell('TERBUKA')));
      const blocks = [
        rich.paragraph(`${res.stats.checked} port web umum diperiksa: ${COMMON_WEB_PORTS.join(', ')}`),
        rich.divider(),
      ];
      if (open.length) {
        blocks.push(rich.tableBlock(rows));
        blocks.push(rich.paragraph(`${open.length} port terbuka. Port non-standar sering jadi pintu masuk - inventarisasi dan lindungi.`));
      } else {
        blocks.push(rich.paragraph('Tidak ada port web umum yang terbuka pada pemeriksaan ini.'));
      }
      replyRich(ctx, `Pemindaian Port - ${t.host}`, blocks);
    } catch (err) {
      logger.error('/ports error:', err);
      replyRich(ctx, 'Error', rich.paragraph(sanitizeText(err.message, 200)));
    }
  });

  bot.command('dnsinfo', async (ctx) => {
    const t = requireTargetArg(ctx);
    if (!t) return;
    if (!validator.hostInScope(t.host)) {
      const why = validator.openMode
        ? `${t.host} bukan domain yang valid (IP privat/internal selalu ditolak).`
        : `${t.host} tidak berada dalam ALLOWED_TARGETS. Cek /scope.`;
      replyRich(ctx, 'Di luar scope', rich.paragraph(why));
      return;
    }
    await rich.showThinking(ctx, 'Mengumpulkan record DNS...', 600);
    try {
      const info = await fullDnsInfo(t.host);
      const rec = info.records || {};
      const fmt = (arr, joiner = ', ') => (arr && arr.length ? arr.map((x) => (typeof x === 'object' ? JSON.stringify(x) : String(x))).join(joiner).slice(0, 160) : '-');
      const rows = [
        rich.tableCell('Record', { header: true }),
        rich.tableCell('Nilai', { header: true }),
      ];
      rows.push(rich.tableRow(rich.tableCell('A'), rich.tableCell(fmt(rec.A))));
      rows.push(rich.tableRow(rich.tableCell('AAAA'), rich.tableCell(fmt(rec.AAAA))));
      rows.push(rich.tableRow(rich.tableCell('MX'), rich.tableCell(fmt((rec.MX || []).map((m) => `${m.exchange}:${m.priority}`)))));
      rows.push(rich.tableRow(rich.tableCell('NS'), rich.tableCell(fmt(rec.NS))));
      rows.push(rich.tableRow(rich.tableCell('TXT'), rich.tableCell(fmt((rec.TXT || []).slice(0, 4), ' | '))));
      rows.push(rich.tableRow(rich.tableCell('CNAME'), rich.tableCell(fmt(rec.CNAME))));
      rows.push(rich.tableRow(rich.tableCell('CAA'), rich.tableCell(fmt(rec.CAA))));
      const es = info.emailSecurity || {};
      const blocks = [
        rich.tableBlock(rows),
        rich.divider(),
        rich.paragraph('Keamanan Email:'),
        rich.bulletList([
          `SPF: ${es.spf ? 'ada' : 'TIDAK ADA (rentan spoofing)'}`,
          `DMARC: ${es.dmarc ? 'ada' : 'TIDAK ADA (kebijakan lemah)'}`,
          `MTA-STS: ${es.mtaSts ? 'ada' : 'tidak ada'}`,
        ]),
      ];
      replyRich(ctx, `DNS Info - ${t.host}`, blocks);
    } catch (err) {
      logger.error('/dnsinfo error:', err);
      replyRich(ctx, 'Error', rich.paragraph(sanitizeText(err.message, 200)));
    }
  });

  bot.command('ipinfo', async (ctx) => {
    const t = requireTargetArg(ctx);
    if (!t) return;
    const g = await guardTarget(ctx, t.host);
    if (!g) return;
    await rich.showThinking(ctx, 'Mengambil info IP via RDAP...', 600);
    try {
      const dns = require('dns').promises;
      const ips = (g.ips && g.ips.length ? g.ips : (await dns.resolve4(t.host).catch(() => []))) || [];
      if (!ips.length) {
        replyRich(ctx, 'Resolusi gagal', rich.paragraph(`Tidak dapat me-resolve ${t.host}`));
        return;
      }
      const ip = ips[0];
      const rows = [
        rich.tableCell('Item', { header: true }),
        rich.tableCell('Nilai', { header: true }),
      ];
      rows.push(rich.tableRow(rich.tableCell('Host'), rich.tableCell(t.host)));
      rows.push(rich.tableRow(rich.tableCell('IP'), rich.tableCell(ips.slice(0, 3).join(', '))));
      let rdapNote = 'RDAP tidak tersedia';
      try {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 12000);
        const res = await fetch(`https://rdap.org/ip/${ip}`, { signal: ctrl.signal });
        clearTimeout(timer);
        if (res.ok) {
          const data = await res.json();
          const name = (data.name || (data.entities && data.entities[0] && data.entities[0].vcardArray && '') || '').toString();
          const country = (data.country || '').toString();
          const range = `${data.startAddress || '?'} - ${data.endAddress || '?'}`;
          rows.push(rich.tableRow(rich.tableCell('Jaringan'), rich.tableCell(String(name).slice(0, 60) || '-')));
          rows.push(rich.tableRow(rich.tableCell('Negara'), rich.tableCell(country || '-')));
          rows.push(rich.tableRow(rich.tableCell('Rentang'), rich.tableCell(range.slice(0, 60))));
          rows.push(rich.tableRow(rich.tableCell('Tipe'), rich.tableCell(String(data.type || '-').slice(0, 40))));
          rdapNote = 'data RDAP resmi';
        }
      } catch (_) {
        /* RDAP gagal - tampilkan IP saja */
      }
      const blocks = [rich.tableBlock(rows), rich.quoteBlock(`Sumber: ${rdapNote}. Gunakan informasi ini untuk kontak pelaporan keamanan (abuse/ASG).`)];
      replyRich(ctx, `IP Info - ${t.host}`, blocks);
    } catch (err) {
      logger.error('/ipinfo error:', err);
      replyRich(ctx, 'Error', rich.paragraph(sanitizeText(err.message, 200)));
    }
  });

  // ---------- laporan kerentanan cerdas ----------
  const VR_UID_RE = /VR-[a-f0-9]{16}/;

  function vReportActionRow(uid) {
    return [
      Markup.button.callback('Preview', `vrp:${uid}`),
      Markup.button.callback('Edit', `vre:${uid}`),
      Markup.button.callback('Mark Reviewed', `vrr:${uid}`),
      Markup.button.callback('Export', `vrx:${uid}`),
    ];
  }

  function ownedVReport(ctx, uid) {
    const found = vrStore.getReportWithScan(uid);
    if (!found || !found.report || !found.scan) return null;
    if (found.scan.owner_id !== ctx.from.id && ctx.role !== 'admin') return null;
    return found;
  }

  /** Teks + keyboard daftar laporan cerdas satu scan (dipakai /vreports dan callback). */
  function vReportListMessage(scanId, page) {
    const perPage = 5;
    const total = vrStore.countReports(scanId);
    if (!total) {
      return {
        text: 'Tidak ada laporan kerentanan cerdas (tidak ada temuan yang menghasilkan laporan). Scan kosong BUKAN pernyataan target aman.',
        keyboard: undefined,
      };
    }
    const rows = vrStore.listReports(scanId, { limit: perPage, offset: (page || 0) * perPage });
    const blocks = [rich.paragraph(`Total: ${total} laporan`), rich.divider()];
    for (const r of rows) {
      blocks.push(rich.paragraph(`${severityBadge(r.severity_assessed)} ${r.title}`));
      blocks.push(rich.paragraph(`UID: ${r.report_uid} | status=${r.validation_status}${r.needs_review ? ' | NEEDS_REVIEW' : ''}${r.review_status === 'REVIEWED' ? ' | REVIEWED' : ''}`));
    }
    const keyboard = rows.map((r) => vReportActionRow(r.report_uid));
    const nav = [];
    if ((page || 0) > 0) nav.push(Markup.button.callback('Sebelumnya', `vrl:${scanId}:${page - 1}`));
    if (total > (page + 1) * perPage) nav.push(Markup.button.callback('Berikutnya', `vrl:${scanId}:${page + 1}`));
    if (nav.length) keyboard.push(nav);
    return { blocks, keyboard: Markup.inlineKeyboard(keyboard) };
  }

  async function sendVulnReportSummary(chatId, scanId) {
    try {
      const scanRow = store.getScan(scanId);
      if (!scanRow) return;
      const sum = summarizeForTelegram(store, scanRow, 5);
      if (!sum.total) {
        await rich.sendRich(bot.telegram, chatId, 'Laporan Kerentanan Cerdas', [
          rich.paragraph('Tidak ada temuan terekam, sehingga tidak ada laporan yang dibuat.'),
          rich.quoteBlock('Scan kosong BUKAN pernyataan bahwa target aman.'),
        ]);
        return;
      }
      const statusLine = Object.entries(sum.byStatus).map(([k, v]) => `${k}=${v}`).join(' | ');
      const typeLine = Object.entries(sum.byType).map(([k, v]) => `${k}=${v}`).join(', ');
      const blocks = [
        rich.paragraph(`Job: ${scanRow.job_id} | Target: ${scanRow.target}`),
        rich.paragraph(`Total: ${sum.total} laporan (dari temuan nyata semua engine yang berjalan)`),
        rich.paragraph(`Status validasi: ${statusLine || '-'}`),
        rich.paragraph(`Per jenis: ${typeLine || '-'}`),
        rich.divider(),
        rich.paragraph('Gunakan tombol di bawah untuk Preview / Edit / Mark Reviewed / Export tiap laporan.'),
      ];
      const keyboard = sum.list.map((r) => vReportActionRow(r.report_uid));
      if (sum.total > sum.list.length) {
        keyboard.push([Markup.button.callback('Lihat semua laporan', `vrl:${scanRow.id}:0`)]);
      }
      await rich.sendRich(bot.telegram, chatId, 'Laporan Kerentanan Cerdas Siap', blocks, Markup.inlineKeyboard(keyboard));
    } catch (err) {
      logger.warn('Gagal mengirim ringkasan laporan cerdas:', err.message);
    }
  }

  bot.action(/vrl:(\d+):(\d+)/, async (ctx) => {
    try {
      const scanId = Number(ctx.match[1]);
      const page = Number(ctx.match[2]) || 0;
      const scan = store.getScan(scanId);
      if (!scan || (scan.owner_id !== ctx.from.id && ctx.role !== 'admin')) {
        await ctx.answerCbQuery('Scan tidak ditemukan / bukan milik Anda');
        return;
      }
      await ctx.answerCbQuery();
      const msg = vReportListMessage(scanId, page);
      if (msg.keyboard) await rich.editRich(ctx, msg.blocks, msg.keyboard);
      else await rich.editRich(ctx, msg.blocks);
    } catch (err) {
      logger.error('action vrl error:', err);
    }
  });

  bot.action(new RegExp(`vrp:(${VR_UID_RE.source})`), async (ctx) => {
    try {
      const uid = ctx.match[1];
      const found = ownedVReport(ctx, uid);
      if (!found) {
        await ctx.answerCbQuery('Laporan tidak ditemukan / bukan milik Anda');
        return;
      }
      await ctx.answerCbQuery('Pratinjau laporan');
      const payload = JSON.parse(found.report.payload_json || '{}');
      const text = renderVReportText(payload);
      const parts = splitMessage(text, 3900);
      for (let i = 0; i < parts.length; i++) {
        // eslint-disable-next-line no-await-in-loop
        await ctx.reply(parts[i]);
      }
    } catch (err) {
      logger.error('action vrp error:', err);
    }
  });

  bot.action(new RegExp(`vre:(${VR_UID_RE.source})`), async (ctx) => {
    try {
      const uid = ctx.match[1];
      const found = ownedVReport(ctx, uid);
      if (!found) {
        await ctx.answerCbQuery('Laporan tidak ditemukan / bukan milik Anda');
        return;
      }
      await ctx.answerCbQuery();
      const buttons = VALIDATION_STATUSES.map((s) => [Markup.button.callback(s, `vrs:${uid}:${s}`)]);
      buttons.push([Markup.button.callback('Tandai sudah direview', `vrr:${uid}`)]);
      await rich.editRich(
        ctx,
        [
          rich.paragraph(`Status saat ini: ${found.report.validation_status}`),
          rich.paragraph('Pilih status validasi baru (perubahan tercatat sebagai versi baru):'),
        ],
        Markup.inlineKeyboard(buttons)
      );
    } catch (err) {
      logger.error('action vre error:', err);
    }
  });

  bot.action(new RegExp(`vrs:(${VR_UID_RE.source}):([A-Z_]+)`), async (ctx) => {
    try {
      const [, uid, status] = ctx.match;
      const found = ownedVReport(ctx, uid);
      if (!found) {
        await ctx.answerCbQuery('Laporan tidak ditemukan / bukan milik Anda');
        return;
      }
      vrStore.setStatus(found.report.id, status, ctx.from.id);
      await ctx.answerCbQuery(`Status diubah: ${status}`);
      await rich.editRich(
        ctx,
        [
          rich.paragraph(`Status laporan ${uid} kini: ${status}`),
          rich.quoteBlock('Konfirmasi adalah tindakan manusia dan tercatat pada riwayat versi laporan.'),
        ],
        Markup.inlineKeyboard([vReportActionRow(uid)])
      );
    } catch (err) {
      logger.error('action vrs error:', err);
      try {
        await ctx.answerCbQuery(`Gagal: ${err.message}`.slice(0, 190));
      } catch (_) {
        /* diamkan */
      }
    }
  });

  bot.action(new RegExp(`vrr:(${VR_UID_RE.source})`), async (ctx) => {
    try {
      const uid = ctx.match[1];
      const found = ownedVReport(ctx, uid);
      if (!found) {
        await ctx.answerCbQuery('Laporan tidak ditemukan / bukan milik Anda');
        return;
      }
      vrStore.markReviewed(found.report.id, ctx.from.id);
      await ctx.answerCbQuery('Ditandai sudah direview');
      await rich.editRich(
        ctx,
        [
          rich.paragraph(`Laporan ${uid} ditandai REVIEWED oleh Anda.`),
          rich.paragraph(`Tambah catatan: /vreport note ${uid} teks-catatan`),
        ],
        Markup.inlineKeyboard([vReportActionRow(uid)])
      );
    } catch (err) {
      logger.error('action vrr error:', err);
    }
  });

  bot.action(new RegExp(`vrx:(${VR_UID_RE.source})`), async (ctx) => {
    try {
      const uid = ctx.match[1];
      const found = ownedVReport(ctx, uid);
      if (!found) {
        await ctx.answerCbQuery('Laporan tidak ditemukan / bukan milik Anda');
        return;
      }
      await ctx.answerCbQuery();
      await replyRich(
        ctx,
        'Format Ekspor',
        rich.paragraph(`Pilih format untuk laporan ${uid}:`),
        Markup.inlineKeyboard([
          [Markup.button.callback('TXT', `vrf:${uid}:txt`), Markup.button.callback('Markdown', `vrf:${uid}:md`)],
          [Markup.button.callback('JSON', `vrf:${uid}:json`), Markup.button.callback('HTML', `vrf:${uid}:html`)],
        ])
      );
    } catch (err) {
      logger.error('action vrx error:', err);
    }
  });

  bot.action(new RegExp(`vrf:(${VR_UID_RE.source}):(txt|md|json|html)`), async (ctx) => {
    try {
      const [, uid, fmt] = ctx.match;
      const found = ownedVReport(ctx, uid);
      if (!found) {
        await ctx.answerCbQuery('Laporan tidak ditemukan / bukan milik Anda');
        return;
      }
      await ctx.answerCbQuery('Menyiapkan file');
      const payload = JSON.parse(found.report.payload_json || '{}');
      const p = writeVReportFile(config, found.scan, payload, fmt);
      await ctx.replyWithDocument(
        { source: fs.createReadStream(p), filename: path.basename(p) },
        { caption: `Laporan ${fmt.toUpperCase()} - ${uid}` }
      );
    } catch (err) {
      logger.error('action vrf error:', err);
      try {
        await ctx.answerCbQuery(`Gagal mengekspor: ${String(err.message).slice(0, 150)}`);
      } catch (_) {
        /* diamkan */
      }
    }
  });

  bot.command('vreports', (ctx) => {
    const parts = String(ctx.message.text || '').trim().split(/\s+/);
    let scan = null;
    if (parts[1]) {
      scan = store.getScanByJobId(parts[1]);
      if (!scan || (scan.owner_id !== ctx.from.id && ctx.role !== 'admin')) {
        replyRich(ctx, 'Tidak ditemukan', rich.paragraph('Scan tidak ditemukan / bukan milik Anda.'));
        return;
      }
    } else {
      scan = store.lastFinishedScan(ctx.from.id);
      if (!scan) {
        replyRich(ctx, 'Belum ada scan', rich.paragraph('Jalankan /scan domain.com terlebih dahulu atau gunakan /vreports jobId.'));
        return;
      }
    }
    const msg = vReportListMessage(scan.id, 0);
    replyRich(ctx, 'Laporan Kerentanan Cerdas', msg.blocks, msg.keyboard);
  });

  bot.command('vreport', (ctx) => {
    const parts = String(ctx.message.text || '').trim().split(/\s+/);
    const usage = '/vreport VR-xxxx (pratinjau)\n/vreport status VR-xxxx STATUS\n/vreport note VR-xxxx teks';
    if (!parts[1]) {
      replyRich(ctx, 'Penggunaan', rich.codeBlock(usage));
      return;
    }
    if (parts[1] === 'status') {
      const uid = parts[2];
      const status = (parts[3] || '').toUpperCase();
      if (!uid || !status) {
        replyRich(ctx, 'Penggunaan', rich.codeBlock(usage));
        return;
      }
      const found = ownedVReport(ctx, uid);
      if (!found) {
        replyRich(ctx, 'Tidak ditemukan', rich.paragraph('Laporan tidak ditemukan / bukan milik Anda.'));
        return;
      }
      try {
        vrStore.setStatus(found.report.id, status, ctx.from.id);
        replyRich(ctx, 'Status Diperbarui', rich.paragraph(`${uid} diubah ke ${status}. Perubahan tercatat pada riwayat versi.`));
      } catch (err) {
        replyRich(ctx, 'Gagal', rich.paragraph(err.message));
      }
      return;
    }
    if (parts[1] === 'note') {
      const uid = parts[2];
      const note = parts.slice(3).join(' ');
      if (!uid || !note) {
        replyRich(ctx, 'Penggunaan', rich.codeBlock(usage));
        return;
      }
      const found = ownedVReport(ctx, uid);
      if (!found) {
        replyRich(ctx, 'Tidak ditemukan', rich.paragraph('Laporan tidak ditemukan / bukan milik Anda.'));
        return;
      }
      vrStore.setNote(found.report.id, note, ctx.from.id);
      replyRich(ctx, 'Catatan Tersimpan', rich.paragraph(`Catatan review untuk ${uid} tersimpan.`));
      return;
    }
    const uid = parts[1];
    const found = ownedVReport(ctx, uid);
    if (!found) {
      replyRich(ctx, 'Tidak ditemukan', rich.paragraph('Laporan tidak ditemukan / bukan milik Anda. Lihat /vreports.'));
      return;
    }
    const payload = JSON.parse(found.report.payload_json || '{}');
    const text = renderVReportText(payload);
    const rows = vReportActionRow(uid).map((b, i, arr) => (i % 2 === 0 ? arr.slice(i, i + 2) : null)).filter(Boolean);
    replyRich(ctx, `Pratinjau ${uid}`, [rich.codeBlock(text.slice(0, 3500))], Markup.inlineKeyboard(rows));
  });

  // ---------- pekerjaan ----------
  bot.command('status', (ctx) => {
    const lines = [];
    const running = queue.listRunning();
    const queued = queue.listQueued();
    if (!running.length && !queued.length) {
      replyRich(ctx, 'Status Pekerjaan', rich.paragraph('Tidak ada pekerjaan berjalan atau dalam antrean.'));
      return;
    }
    const items = [];
    for (const j of running) {
      const mine = j.ownerId === ctx.from.id || ctx.role === 'admin';
      items.push(`RUN ${j.jobId} ${MODE_LABEL[j.mode] || j.mode} ${j.target}${mine ? '' : ' (milik pengguna lain)'}`);
    }
    for (const j of queued) {
      const mine = j.ownerId === ctx.from.id || ctx.role === 'admin';
      items.push(`ANTRE ${j.jobId} ${MODE_LABEL[j.mode] || j.mode} ${j.target}${mine ? '' : ' (milik pengguna lain)'}`);
    }
    replyRich(ctx, 'Status Pekerjaan', rich.bulletList(items));
  });

  bot.command('stop', (ctx) => {
    const parts = String(ctx.message.text || '').trim().split(/\s+/);
    const arg = parts[1];
    const mineRunning = queue.listRunning().filter((j) => j.ownerId === ctx.from.id);
    const mineQueued = queue.listQueued().filter((j) => j.ownerId === ctx.from.id);
    let jobId = arg;
    if (!jobId) {
      if (mineRunning.length) jobId = mineRunning[0].jobId;
      else if (mineQueued.length) jobId = mineQueued[0].jobId;
      else {
        replyRich(ctx, 'Tidak ada pekerjaan', rich.paragraph('Tidak ada pekerjaan milik Anda yang aktif. Admin dapat memakai /stop jobId.'));
        return;
      }
    }
    const res = queue.cancel(jobId, ctx.from.id, ctx.role === 'admin');
    replyRich(ctx, 'Hasil Pembatalan', rich.paragraph(res.reason));
  });

  bot.command('results', (ctx) => {
    const scan = store.lastFinishedScan(ctx.from.id);
    if (!scan) {
      replyRich(ctx, 'Belum ada hasil', rich.paragraph('Jalankan /scan domain.com terlebih dahulu.'));
      return;
    }
    const sevRows = store.findingsBySeverity(scan.id);
    const top = store.topFindings(scan.id, 8);
    const blocks = [
      rich.tableBlock([
        [rich.tableCell('Item', { header: true }), rich.tableCell('Nilai', { header: true })],
        [rich.tableCell('Job'), rich.tableCell(scan.job_id)],
        [rich.tableCell('Target'), rich.tableCell(scan.target)],
        [rich.tableCell('Mode'), rich.tableCell(MODE_LABEL[scan.mode] || scan.mode)],
        [rich.tableCell('Status'), rich.tableCell(scanStatusLabel(scan.status))],
        [rich.tableCell('Temuan'), rich.tableCell(sevRows.length ? sevRows.map((r) => `${r.severity}=${r.n}`).join(' | ') : 'tidak ada')],
      ]),
    ];
    if (top.length) {
      blocks.push(rich.divider(), rich.paragraph('Temuan teratas:'));
      blocks.push(rich.bulletList(top.map((f) => `${sevEmoji(f.severity)} [${vulnIdOfRow(f)}] ${f.name || f.external_id || '-'}\n   ${String(f.target || '').slice(0, 80)}`)));
    }
    blocks.push(rich.divider(), rich.paragraph(`Gunakan /report ${scan.job_id} untuk laporan lengkap.`));
    const btnRows = [
      [
        Markup.button.callback('TXT', `rep:${scan.id}:txt`),
        Markup.button.callback('JSON', `rep:${scan.id}:json`),
        Markup.button.callback('HTML', `rep:${scan.id}:html`),
      ],
    ];
    for (const r of findingButtons(scan.id, top.map(rowToFindingLike))) btnRows.push(r);
    replyRich(
      ctx,
      'Hasil Scan Terakhir',
      blocks,
      Markup.inlineKeyboard(btnRows)
    );
  });

  bot.action('menu:lastresults', (ctx) => {
    ctx.answerCbQuery().catch(() => {});
    // reply baru (pesan progres mungkin sudah diedit)
    const scan = store.lastFinishedScan(ctx.from.id);
    if (!scan) {
      replyRich(ctx, 'Belum ada hasil', rich.paragraph('Jalankan /scan domain.com terlebih dahulu.'));
      return;
    }
    const sevRows = store.findingsBySeverity(scan.id);
    const top = store.topFindings(scan.id, 8);
    const blocks = [
      rich.paragraph(`Job: ${scan.job_id} | Target: ${scan.target} | ${scanStatusLabel(scan.status)}`),
      rich.paragraph(`Temuan: ${sevRows.length ? sevRows.map((r) => `${r.severity}=${r.n}`).join(' | ') : 'tidak ada'}`),
    ];
    if (top.length) {
      blocks.push(rich.divider(), rich.bulletList(top.map((f) => `${sevEmoji(f.severity)} [${vulnIdOfRow(f)}] ${f.name || f.external_id || '-'}`)));
    }
    const btnRows = [[Markup.button.callback('TXT', `rep:${scan.id}:txt`), Markup.button.callback('JSON', `rep:${scan.id}:json`), Markup.button.callback('HTML', `rep:${scan.id}:html`)]];
    for (const r of findingButtons(scan.id, top.map(rowToFindingLike))) btnRows.push(r);
    replyRich(ctx, 'Hasil Scan Terakhir', blocks, Markup.inlineKeyboard(btnRows));
  });

  bot.action('menu:lastreport', (ctx) => {
    ctx.answerCbQuery().catch(() => {});
    const scan = store.lastFinishedScan(ctx.from.id);
    if (!scan) {
      replyRich(ctx, 'Belum ada laporan', rich.paragraph('Jalankan /scan domain.com terlebih dahulu.'));
      return;
    }
    replyRich(
      ctx,
      'Pilih Format Laporan',
      rich.paragraph(`Job: ${scan.job_id}`),
      Markup.inlineKeyboard([[Markup.button.callback('TXT', `rep:${scan.id}:txt`), Markup.button.callback('JSON', `rep:${scan.id}:json`), Markup.button.callback('HTML', `rep:${scan.id}:html`)]])
    );
  });

  bot.command('history', (ctx) => cmdHistory(ctx));
  bot.action('menu:history', (ctx) => {
    ctx.answerCbQuery().catch(() => {});
    cmdHistory(ctx);
  });

  function cmdHistory(ctx) {
    const rows = store.listScans({ ownerId: ctx.from.id, limit: 10 });
    if (!rows.length) {
      replyRich(ctx, 'Riwayat Scan', rich.paragraph('Riwayat kosong.'));
      return;
    }
    const blocks = [
      rich.tableBlock([
        [rich.tableCell('Job', { header: true }), rich.tableCell('Mode', { header: true }), rich.tableCell('Target', { header: true }), rich.tableCell('Status', { header: true }), rich.tableCell('Temuan', { header: true })],
      ].concat(rows.map((r) => rich.tableRow(rich.tableCell(r.job_id.slice(0, 14)), rich.tableCell(MODE_LABEL[r.mode] || r.mode), rich.tableCell(String(r.target).slice(0, 24)), rich.tableCell(scanStatusLabel(r.status)), rich.tableCell(String(store.countFindings(r.id))))))),
      rich.divider(),
      rich.paragraph(rows.map((r) => `${fmtDateTime(r.created_at)}`).join('\n')),
    ];
    replyRich(ctx, 'Riwayat Scan Anda', blocks);
  }

  bot.command('report', async (ctx) => {
    const parts = String(ctx.message.text || '').trim().split(/\s+/);
    const arg = parts[1];
    if (!arg) {
      replyRich(ctx, 'Penggunaan', rich.paragraph('Format: /report jobId (lihat /history)'));
      return;
    }
    const scan = store.getScanByJobId(arg);
    if (!scan || (scan.owner_id !== ctx.from.id && ctx.role !== 'admin')) {
      replyRich(ctx, 'Tidak ditemukan', rich.paragraph('Laporan tidak ditemukan / bukan milik Anda.'));
      return;
    }
    if (!['COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED'].includes(scan.status)) {
      replyRich(ctx, 'Belum siap', rich.paragraph('Scan belum selesai; laporan belum tersedia.'));
      return;
    }
    await replyRich(
      ctx,
      'Pilih Format Laporan',
      rich.paragraph(`Job: ${scan.job_id} | Target: ${scan.target}`),
      Markup.inlineKeyboard([
        [
          Markup.button.callback('TXT', `rep:${scan.id}:txt`),
          Markup.button.callback('JSON', `rep:${scan.id}:json`),
          Markup.button.callback('HTML', `rep:${scan.id}:html`),
        ],
      ])
    );
  });

  bot.action(/rep:(\d+):(txt|json|html)/, async (ctx) => {
    try {
      const [, scanIdStr, fmt] = ctx.match;
      const scan = store.getScan(Number(scanIdStr));
      if (!scan || (scan.owner_id !== ctx.from.id && ctx.role !== 'admin')) {
        await ctx.answerCbQuery('Laporan tidak ditemukan / bukan milik Anda');
        return;
      }
      await ctx.answerCbQuery('Menyiapkan file');
      await sendReportFile(ctx, scan, fmt);
    } catch (err) {
      logger.error('action rep error:', err);
    }
  });

  async function sendReportFile(ctx, scan, fmt) {
    let p = null;
    if (fmt === 'json') p = scan.report_json_path;
    else if (fmt === 'txt') p = scan.report_txt_path;
    else p = scan.report_html_path;
    if (!p || !fs.existsSync(p)) {
      try {
        const { buildReportFiles } = require('./reports/json');
        const paths = buildReportFiles(store, config, scan);
        p = fmt === 'json' ? paths.jsonPath : fmt === 'txt' ? paths.txtPath : paths.htmlPath;
      } catch (err) {
        logger.error('Gagal membuat laporan ulang:', err);
        replyRich(ctx, 'Gagal', rich.paragraph('Gagal membuat laporan: ' + err.message));
        return;
      }
    }
    await ctx.replyWithDocument({ source: fs.createReadStream(p), filename: path.basename(p) }, { caption: `Laporan ${fmt.toUpperCase()} - ${scan.job_id}` });
  }

  // ---------- sistem ----------
  async function showTools(ctx, force) {
    const rows = [
      rich.tableCell('Engine', { header: true }),
      rich.tableCell('Status', { header: true }),
      rich.tableCell('Versi', { header: true }),
    ];
    const internalCount = { n: 0 };
    for (const eng of engines.list) {
      // eslint-disable-next-line no-await-in-loop
      const chk = await eng.checkInstalled(force);
      const isInternal = !!eng.builtIn;
      if (isInternal) internalCount.n++;
      rows.push(
        rich.tableRow(
          rich.tableCell(eng.name + (isInternal ? ' (internal)' : '')),
          rich.tableCell(engineStatusLabel(chk.status)),
          rich.tableCell(chk.version ? String(chk.version).slice(0, 28) : chk.error ? sanitizeText(chk.error, 28) : '-')
        )
      );
    }
    const blocks = [
      rich.tableBlock(rows),
      rich.divider(),
      rich.paragraph(`${internalCount.n} engine internal aktif - scan BERJALAN walau binary eksternal tidak terpasang (fallback otomatis).`),
      rich.paragraph('Gunakan /checktools untuk verifikasi ulang, /installtools untuk instalasi binary (admin).'),
    ];
    replyRich(ctx, 'Status Engine', blocks);
  }

  bot.command('tools', (ctx) => showTools(ctx, false));
  bot.action('menu:tools', (ctx) => {
    ctx.answerCbQuery().catch(() => {});
    showTools(ctx, false);
  });

  bot.command('checktools', (ctx) => showTools(ctx, true));

  bot.command('installtools', async (ctx) => {
    if (ctx.role !== 'admin') {
      replyRich(ctx, 'Khusus Admin', rich.paragraph('Perintah ini hanya untuk admin.'));
      return;
    }
    if (installing.size) {
      replyRich(ctx, 'Sedang berjalan', rich.paragraph('Installer sedang berjalan. Tunggu hingga selesai.'));
      return;
    }
    const nonce = randomId('i').slice(0, 16);
    pending.set(nonce, { ownerId: ctx.from.id, mode: 'install', ts: Date.now() });
    replyRich(
      ctx,
      'Installer Engine Terkontrol',
      [
        rich.paragraph('Akan menjalankan install.sh --tools-only --yes:'),
        rich.bulletList(['Unduh dari rilis resmi GitHub', 'Verifikasi checksum', 'Uji setiap binary']),
        rich.paragraph('Butuh internet, bisa 5-30 menit. Lanjutkan?'),
      ],
      Markup.inlineKeyboard([
        [Markup.button.callback('Jalankan installer', `inst:${nonce}`), Markup.button.callback('Batal', 'cx:' + nonce)],
      ])
    );
  });

  bot.action(/inst:(n[a-z0-9]+)/, async (ctx) => {
    try {
      const nonce = ctx.match[1];
      const p = pending.get(nonce);
      if (!p || p.ownerId !== ctx.from.id || ctx.role !== 'admin') {
        await ctx.answerCbQuery('Tidak diizinkan');
        return;
      }
      pending.delete(nonce);
      await ctx.answerCbQuery('Installer dimulai');
      installing.set(ctx.from.id, true);
      await rich.editRich(ctx, [rich.heading('Installer Berjalan'), rich.paragraph('Installer berjalan di latar belakang. Anda akan diberi tahu setelah selesai.'), rich.thinkingBlock('Mengunduh & memverifikasi binary...')]);
      const logFile = path.join(config.logsDir, `install-${Date.now()}.log`);
      const { runProcess } = require('./utils/processRunner');
      const r = await runProcess({
        cmd: 'bash',
        args: ['install.sh', '--tools-only', '--yes'],
        cwd: config.rootDir,
        timeoutMs: 30 * 60 * 1000,
        env: { ...process.env, NONINTERACTIVE: '1' },
      });
      fs.mkdirSync(config.logsDir, { recursive: true });
      fs.writeFileSync(logFile, (r.stdout || '') + '\n=== STDERR ===\n' + (r.stderr || ''), 'utf8');
      installing.delete(ctx.from.id);
      const summary = r.ok
        ? 'Installer selesai. Cek /tools untuk status terbaru.'
        : `Installer selesai dengan exit=${r.code}${r.timedOut ? ' (timeout)' : ''}. Periksa log untuk detail.`;
      replyRich(ctx, 'Hasil Installer', [
        rich.paragraph(summary),
        rich.paragraph(`Log: ${logFile}`),
      ]);
      try {
        await ctx.replyWithDocument({ source: fs.createReadStream(logFile), filename: path.basename(logFile) });
      } catch (_) {
        /* kirim log gagal - tidak fatal */
      }
    } catch (err) {
      installing.delete(ctx.from.id);
      logger.error('installer error:', err);
      replyRich(ctx, 'Installer Gagal', rich.paragraph(err.message));
    }
  });

  bot.command('stats', (ctx) => {
    const st = store.globalStats();
    const mine = store.countScansByOwner(ctx.from.id);
    const sev = st.findingsBySeverity || {};
    const stat = st.scansByStatus || {};
    replyRich(
      ctx,
      'Statistik Lokal',
      [
        rich.tableBlock([
          [rich.tableCell('Item', { header: true }), rich.tableCell('Nilai', { header: true })],
          [rich.tableCell('Scan Anda'), rich.tableCell(String(mine))],
          [rich.tableCell('Total pengguna'), rich.tableCell(String(st.users))],
          [rich.tableCell('Scan COMPLETED/PARTIAL/FAILED/CANCELLED'), rich.tableCell(`${stat.COMPLETED || 0}/${stat.PARTIAL || 0}/${stat.FAILED || 0}/${stat.CANCELLED || 0}`)],
          [rich.tableCell('Temuan (critical/high/medium/low/info)'), rich.tableCell(`${sev.critical || 0}/${sev.high || 0}/${sev.medium || 0}/${sev.low || 0}/${sev.info || 0}`)],
          [rich.tableCell('Database driver'), rich.tableCell(store.driver)],
        ]),
      ]
    );
  });
  bot.action('menu:stats', (ctx) => {
    ctx.answerCbQuery().catch(() => {});
    const st = store.globalStats();
    const mine = store.countScansByOwner(ctx.from.id);
    replyRich(ctx, 'Statistik Lokal', rich.paragraph(`Scan Anda: ${mine} | Pengguna: ${st.users} | DB: ${store.driver}`));
  });

  // fallback perintah tak dikenal
  bot.on('text', async (ctx) => {
    const text = String(ctx.message.text || '');
    if (text.startsWith('/')) {
      replyRich(ctx, 'Perintah tidak dikenal', rich.paragraph('Gunakan /help atau /menu untuk panduan.'));
    }
  });

  bot.catch((err, ctx) => {
    logger.error(`Bot error pada update ${ctx && ctx.update ? ctx.update.update_id : '?'}:`, err);
  });

  bot.launchInfo = () => `Bot aktif. Admin: ${config.adminIds.length ? config.adminIds.join(',') : '(belum diset)'}`;
  return bot;
}

module.exports = { createBot, MODE_LABEL };
