'use strict';

/**
 * Template laporan spesifik per jenis kerentanan (A-M pada spesifikasi) + fallback.
 *
 * ATURAN KERAS:
 * - Semua builder HANYA membaca data yang benar-benar ada pada temuan/bukti.
 * - Data yang tidak tersedia -> dikeluarkan dari field ATAU masuk daftar `gaps`
 *   ("bukti kurang"), BUKAN diisi teks generik yang mengesankan pasti.
 * - Remediasi adalah panduan perbaikan per tipe (boleh generik per tipe), bukan
 *   hasil scan. Dampak selalu diberi bingkai kondisional ("bila terverifikasi").
 * - Disclaimer per tipe yang diwajibkan spesifikasi (IDOR != ID numerik, CORS
 *   wildcard != otomatis rentan, RCE signature = indikasi, banner versi != rentan)
 *   ditegaskan pada field `notes` template terkait.
 */

const { VULN_TYPES } = require('./mappings');
const { redactText } = require('./redactor');

/** --- util umum --- */

function parseTargetUrl(target) {
  const raw = String(target || '');
  try {
    const u = new URL(raw);
    return {
      raw,
      ok: true,
      url: u.toString(),
      host: u.host,
      hostname: u.hostname,
      path: u.pathname || '/',
      params: Array.from(new Set(u.searchParams.keys())).slice(0, 20),
      hasQuery: Array.from(u.searchParams.keys()).length > 0,
    };
  } catch (_) {
    return { raw, ok: false, url: raw, host: raw.split('/')[0] || raw, hostname: raw.split('/')[0] || raw, path: '', params: [], hasQuery: false };
  }
}

function evidenceJson(finding) {
  try {
    const obj = JSON.parse(String(finding.evidence || ''));
    return obj && typeof obj === 'object' ? obj : null;
  } catch (_) {
    return null;
  }
}

function evidenceText(finding, max) {
  return String(finding.evidence || '').slice(0, max || 2000);
}

/** Langkah reproduksi dari curl-command yang benar-benar diproduksi engine. */
function reproFromCurl(finding) {
  const obj = evidenceJson(finding);
  const curl = obj && typeof obj.curl === 'string' ? obj.curl.trim() : '';
  if (!curl) return null;
  const r = redactText(curl);
  return {
    curl: r.text,
    redacted: r.redactions.length > 0,
  };
}

function reproForHeaderProbe(finding) {
  const id = String(finding.externalId || '');
  const steps = [];
  if (id.startsWith('header:')) {
    steps.push(`Lakukan permintaan GET/HEAD ke URL target dan amati keberadaan header "${id.replace('header:', '')}" pada respons (pemeriksaan pasif, tanpa payload).`);
  } else if (id === 'cookie:flags') {
    steps.push('Lakukan permintaan ke URL target dan amati atribut atribut Set-Cookie pada respons (Secure/HttpOnly/SameSite) - tanpa upaya login atau brute force.');
  } else if (id === 'server:version' || id === 'server:poweredby') {
    steps.push('Lakukan permintaan ke URL target dan amati header Server / X-Powered-By - hanya membaca header respons.');
  } else if (id.startsWith('tls:')) {
    steps.push('Lakukan negosiasi TLS ke host target dan catat protokol/sertifikat yang ditawarkan server - tanpa eksploitasi.');
  } else if (id === 'redirect:downgrade' || id === 'redirect:scope') {
    steps.push('Ikuti redirect awal dari URL target (maksimal seperti yang dilakukan engine) dan bandingkan skema/awal-tujuan - tanpa menguji parameter yang tidak ada pada bukti.');
  } else if (id === 'page:dirlisting') {
    steps.push('Buka URL target pada browser/perintah GET dan amati halaman daftar direktori - hanya GET biasa.');
  } else if (id.startsWith('page:stacktrace') || id === 'page:5xx') {
    steps.push('Lakukan permintaan GET ke URL target dan amati isi respons yang memuat pesan error - tanpa payload injeksi.');
  } else if (id.startsWith('exposed:')) {
    const p = id.replace('exposed:', '');
    steps.push(`Lakukan permintaan GET ke path "${p}" dan catat status respons TANPA mengunduh/menyimpan isi file (kebijakan privasi engine).`);
  } else {
    steps.push('Lakukan permintaan GET biasa ke URL target dan bandingkan dengan kondisi yang dicatat engine (langkah lebih rinci tidak dapat direkonstruksi dari bukti).');
  }
  return steps;
}

function refsFromFinding(finding) {
  return String(finding.reference || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .slice(0, 5);
}

function cweRefs(meta) {
  const refs = [];
  if (meta.cwe) refs.push(`https://cwe.mitre.org/data/definitions/${meta.cwe.replace('CWE-', '')}.html`);
  if (meta.cve) refs.push(`https://nvd.nist.gov/vuln/detail/${meta.cve}`);
  return refs;
}

function uniq(list, max) {
  return Array.from(new Set(list.filter(Boolean))).slice(0, max || 8);
}

/** --- definisi per tipe --- */
// ctx: { finding, meta, urls, cls, evidenceRedacted }
const TEMPLATES = {
  /* A. SQL Injection */
  sqli: {
    fields(ctx) {
      const f = ctx.finding;
      const obj = evidenceJson(f);
      const variant = /blind/i.test(`${f.name} ${f.externalId}`)
        ? 'blind (indikasi dari nama template)'
        : obj && /error|syntax/i.test(JSON.stringify(obj))
          ? 'error-based (indikasi dari pola error pada bukti)'
          : 'tidak dapat ditentukan dari bukti';
      const out = [
        { label: 'Metode deteksi', value: `Engine ${f.engine}, template "${f.externalId || '-'}", klasifikasi ${f.classification}.` },
        { label: 'Parameter terdampak (dari URL/bukti)', value: ctx.urls.params.length ? ctx.urls.params.join(', ') : ctx.urls.hasQuery ? '(ada query - nama tidak terekstrak dari bukti)' : 'tidak teridentifikasi dari bukti (gap)' },
        { label: 'Varian (berbasis bukti)', value: variant },
      ];
      if (obj && obj.extracted && obj.extracted.length) {
        out.push({ label: 'Data terekstrak engine', value: String(obj.extracted.join(' | ')).slice(0, 300) });
      }
      return out;
    },
    repro(ctx) {
      const curl = reproFromCurl(ctx.finding);
      if (curl) {
        return [
          `Perintah yang dipakai scanner saat deteksi (bukan uji destruktif baru):`,
          curl.curl,
          'Ulangi hanya pada target yang Anda izinkan dan amati respons.',
        ];
      }
      return ['Langkah reproduksi otomatis tidak dapat disusun dari bukti yang tersedia (curl-command tidak direkam). Verifikasi manual dengan payload non-destruktif di lingkungan uji milik Anda.'];
    },
    impact() {
      return ['Bila terverifikasi: akses dan manipulasi data database melalui injeksi query (baca, ubah, atau hapus data sesuai kueri yang terekspos).', 'Tingkat dampak aktual bergantung pada hak akun database aplikasi - belum dinilai oleh scan ini.'];
    },
    remediation: [
      'Gunakan parameterized queries / prepared statements untuk seluruh akses database.',
      'Validasi dan normalisasi input sesuai konteks (type-casting, allowlist nilai).',
      'Jangan menyusun query lewat konkatenasi string; batasi detail error database yang tampil ke klien.',
    ],
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'],
  },

  /* B. XSS */
  xss: {
    fields(ctx) {
      const f = ctx.finding;
      const hay = `${f.name} ${f.externalId} ${f.tags}`;
      const variant = /dom/i.test(hay) ? 'DOM-based (indikasi dari penamaan template)' : /stored/i.test(hay) ? 'stored (indikasi dari penamaan template)' : /reflect/i.test(hay) ? 'reflected (indikasi dari penamaan template)' : 'tidak dapat dibuktikan dari bukti (reflected/stored/DOM tidak terpisah)';
      const obj = evidenceJson(f);
      return [
        { label: 'Metode deteksi', value: `Engine ${f.engine}, template "${f.externalId || '-'}", klasifikasi ${f.classification}.` },
        { label: 'Jenis XSS', value: variant },
        { label: 'Parameter/konteks output', value: ctx.urls.params.length ? `parameter: ${ctx.urls.params.join(', ')}` : 'konteks output (HTML/atribut/JS) tidak dapat ditentukan dari bukti (gap)' },
        obj && obj.extracted && obj.extracted.length ? { label: 'Data terekstrak engine', value: String(obj.extracted.join(' | ')).slice(0, 300) } : null,
      ].filter(Boolean);
    },
    repro(ctx) {
      const curl = reproFromCurl(ctx.finding);
      if (curl) {
        return ['Perintah uji yang dipakai scanner saat deteksi:', curl.curl, 'Amati apakah keluaran benar-benar tereksekusi pada konteks browser - jangan menguji pada target tanpa izin.'];
      }
      return ['Langkah reproduksi otomatis tidak tersedia dari bukti; verifikasi manual harus menguji konteks output (HTML/atribut/JS) dengan payload aman milik Anda.'];
    },
    impact() {
      return ['Bila terverifikasi: skrip arbitrer berjalan pada konteks browser korban (pencurian sesi, aksi atas nama pengguna) tergantung halaman terdampak.', 'Dampak stored umumnya lebih luas daripada reflected; jenis belum terbukti dari bukti scan.'];
    },
    remediation: [
      'Terapkan contextual output encoding (HTML, atribut, JS, URL) sesuai lokasi keluaran data.',
      'Sanitasi input dengan library sanitasi yang terawat untuk konteks yang relevan.',
      'Evaluasi Content Security Policy sebagai lapisan pertahanan tambahan (bukan pengganti encoding).',
    ],
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html', 'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html'],
  },

  /* C. Broken Access Control / IDOR */
  'access-control': {
    fields(ctx) {
      return [
        { label: 'Resource/endpoint terdampak', value: ctx.urls.ok ? `${ctx.urls.path || ctx.urls.url}` : ctx.urls.raw },
        { label: 'Metode deteksi', value: `Engine ${ctx.finding.engine}, template "${ctx.finding.externalId || '-'}", klasifikasi ${ctx.finding.classification}.` },
        { label: 'Jenis kontrol yang diduga gagal', value: 'otorisasi akses objek/fungsi (INDIKASI dari template - belum diuji antar-peran)' },
        { label: 'Batas bukti', value: 'Scan ini TIDAK membandingkan akses antar akun uji; temuan bukan bukti IDOR terkonfirmasi.' },
      ];
    },
    repro() {
      return [
        'Verifikasi hanya dengan akun uji milik Anda:',
        '1. Akses resource sebagai akun pemilik, catat respons.',
        '2. Akses resource yang sama dari akun uji kedua yang TIDAK berhak, bandingkan status/isi.',
        '3. Jangan pernah memakai akun/data pengguna nyata untuk pembuktian.',
      ];
    },
    impact() {
      return ['Bila terverifikasi: pengguna dapat mengakses/mengubah objek di luar otorisasinya (IDOR / akses fungsi terlarang).', 'Catatan: keberadaan ID numerik atau UUID saja BUKAN bukti IDOR; bukti perbandingan antar-peran belum ada.'];
    },
    remediation: [
      'Validasi otorisasi di sisi server untuk setiap permintaan objek (deny-by-default), bukan hanya menyembunyikan UI.',
      'Gunakan ID tak-terduga sebagai lapisan tambahan, tetapi tetap cek kepemilikan objek.',
      'Uji ulang dengan matriks peran (akun uji) setelah perbaikan.',
    ],
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Testing_Cheat_Sheet.html'],
  },

  /* D. SSRF */
  ssrf: {
    fields(ctx) {
      return [
        { label: 'Endpoint/parameter terdampak', value: ctx.urls.params.length ? `${ctx.urls.path || ''} (parameter: ${ctx.urls.params.join(', ')})` : ctx.urls.ok ? ctx.urls.path : ctx.urls.raw },
        { label: 'Metode deteksi', value: `Engine ${ctx.finding.engine}, template "${ctx.finding.externalId || '-'}", klasifikasi ${ctx.finding.classification}.` },
        { label: 'Bukti perilaku server', value: ctx.evidenceRedacted && typeof ctx.evidenceRedacted === 'object' ? '(bukti tersimpan pada payload; lihat Evidence)' : 'lihat Evidence' },
        { label: 'Batas & kemungkinan false positive', value: 'Perilaku request server yang diamati terbatas pada interaksi yang terekam engine; respons berbeda/timing saja belum membuktikan SSRF penuh.' },
        { label: 'Batasan etika scan', value: 'Scanner ini TIDAK mengirim request ke endpoint metadata cloud (169.254.169.254 dsb.) atau sistem internal di luar scope.' },
      ];
    },
    repro(ctx) {
      const curl = reproFromCurl(ctx.finding);
      if (curl) return ['Perintah uji yang dipakai scanner saat deteksi:', curl.curl, 'Untuk verifikasi aman, gunakan callback host milik Anda sendiri (bukan metadata cloud/internal).'];
      return ['Verifikasi manual dengan callback server milik Anda pada host yang diizinkan; jangan mengarahkan request ke metadata cloud atau jaringan internal.'];
    },
    impact() {
      return ['Bila terverifikasi: server dapat dipaksa melakukan request ke tujuan pilihan penyerang (layanan internal, endpoint metadata cloud bila lingkungannya demikian).', 'Dampak aktual tergantung topologi jaringan internal - tidak dinilai oleh scan ini.'];
    },
    remediation: [
      'Terapkan allowlist tujuan (host/IP/port) yang boleh diminta oleh fitur tersebut.',
      'Validasi hasil resolusi DNS/IP terhadap allowlist dan tolak rentang internal/link-local/loopback.',
      'Batasi akses jaringan keluar dari layanan yang memproses URL pengguna.',
    ],
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'],
  },

  /* E. LFI / Path Traversal */
  lfi: {
    fields(ctx) {
      return [
        { label: 'Endpoint/parameter terdampak', value: ctx.urls.params.length ? `${ctx.urls.path || ''} (parameter: ${ctx.urls.params.join(', ')})` : ctx.urls.ok ? ctx.urls.path : ctx.urls.raw },
        { label: 'Metode deteksi', value: `Engine ${ctx.finding.engine}, template "${ctx.finding.externalId || '-'}", klasifikasi ${ctx.finding.classification}.` },
        { label: 'Bukti terbatas', value: 'Indikasi bahwa validasi path tidak memadai; scanner tidak membaca file rahasia untuk membuktikan dampak (kebijakan non-destruktif).' },
      ];
    },
    repro(ctx) {
      const curl = reproFromCurl(ctx.finding);
      if (curl) return ['Perintah uji yang dipakai scanner saat deteksi:', curl.curl, 'Jangan mengambil file sensitif pada produksi untuk membuktikan; cukup pastikan validasi path gagal pada file uji milik Anda.'];
      return ['Verifikasi dengan file uji milik Anda (bukan file rahasia) untuk membuktikan validasi path gagal tanpa mengekspos data.'];
    },
    impact() {
      return ['Bila terverifikasi: pembacaan file arbitrer pada server (kode sumber, konfigurasi) tergantung hak proses aplikasi.', 'Bukti scan ini tidak memuat isi file yang dibaca - dampak belum terbukti.'];
    },
    remediation: [
      'Lakukan canonicalization path lalu cocokkan hasilnya terhadap allowlist file/direktori.',
      'Jangan membangun path file dari input mentah; pakai indeks/ID yang dipetakan ke path tetap.',
      'Batasi hak akses filesystem proses aplikasi sesuai kebutuhan minimal.',
    ],
    references: ['https://owasp.org/www-community/attacks/Path_Traversal'],
  },

  /* F. Authentication / Session */
  'auth-session': {
    fields(ctx) {
      const f = ctx.finding;
      const obj = evidenceJson(f);
      const detail = obj && obj.detail ? String(obj.detail) : evidenceText(f, 400);
      const cookieNameMatch = /Cookie tanpa proteksi:\s*([^\s,]+)/.exec(detail);
      const flags = /tanpa ([^,.]+)/g;
      const missing = [];
      let m;
      while ((m = flags.exec(detail)) !== null) missing.push(m[1]);
      return [
        { label: 'Mekanisme terdampak', value: cookieNameMatch ? `cookie "${cookieNameMatch[1]}"` : `temuan "${f.name || f.externalId}" pada ${ctx.urls.host}` },
        { label: 'Kondisi teramati', value: missing.length ? `atribut yang tidak ditemukan: ${missing.join(', ')}` : detail.slice(0, 300) },
        { label: 'Cookie/header terkait', value: '(nilai rahasia telah disensor pada bagian Evidence; hanya nama & atribut yang ditampilkan)' },
      ];
    },
    repro() {
      return ['Lakukan permintaan biasa ke URL target dan amati atribut cookie/header pada respons (tanpa brute force, tanpa upaya pengambilalihan akun).'];
    },
    impact() {
      return ['Bila terverifikasi: cookie sesi tanpa proteksi dapat terekspos via XSS/mitm atau terkirim pada koneksi tidak aman, meningkatkan risiko pembajakan sesi.', 'Tidak ada uji brute-force atau pengambilalihan akun yang dilakukan scan ini.'];
    },
    remediation: [
      'Setel atribut cookie Secure, HttpOnly, dan SameSite pada seluruh cookie sesi.',
      'Rotasi ID sesi setelah autentikasi dan perubahan privilege; terapkan kedaluwarsa sesi.',
      'Pastikan validasi autentikasi berjalan di sisi server pada setiap request.',
    ],
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html', 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'],
  },

  /* G. Security Misconfiguration */
  misconfig: {
    fields(ctx) {
      const obj = evidenceJson(ctx.finding);
      const detail = obj && obj.detail ? String(obj.detail) : evidenceText(ctx.finding, 400);
      return [
        { label: 'Item konfigurasi ditemukan', value: ctx.finding.name || ctx.finding.externalId || '-' },
        { label: 'Kondisi pengamatan', value: detail.slice(0, 400) },
        { label: 'Metode deteksi', value: `Engine ${ctx.finding.engine}, check "${ctx.finding.externalId}" (pemeriksaan pasif).` },
      ];
    },
    repro(ctx) {
      return reproForHeaderProbe(ctx.finding);
    },
    impact() {
      return ['Bila dibiarkan: mengurangi lapisan pertahanan browser/pengguna (mis. clickjacking, MIME-sniffing) atau memaparkan informasi yang mempermudah serangan lanjutan.', 'Dampak aktual bergantung konteks aplikasi; daftar header yang hilang pada kondisi pengamatan.'];
    },
    remediation: [
      'Tetapkan header keamanan yang hilang sesuai baseline (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HSTS untuk HTTPS).',
      'Matikan directory listing, halaman debug, dan endpoint administratif yang tidak diperlukan di produksi.',
      'Proses deploy repeatable + pemeriksaan drift konfigurasi.',
    ],
    references: ['https://owasp.org/www-project-secure-headers/'],
  },

  /* H. Sensitive Information Exposure */
  'info-exposure': {
    fields(ctx) {
      const obj = evidenceJson(ctx.finding);
      const detail = obj && obj.detail ? String(obj.detail) : evidenceText(ctx.finding, 400);
      return [
        { label: 'Jenis informasi terpapar', value: ctx.finding.name || ctx.finding.externalId || '-' },
        { label: 'Lokasi', value: ctx.urls.ok ? ctx.urls.url : ctx.urls.raw },
        { label: 'Bukti (disensor)', value: detail.slice(0, 300) },
        { label: 'Analisis sensitivitas', value: 'Perlu penilaian manual: paparan versi/teknologi adalah informasi pendukung serangan, bukan kerentanan berdiri sendiri; paparan file konfigurasi berpotensi kritis. ISI file sensitif TIDAK diunduh scanner.' },
      ];
    },
    repro(ctx) {
      return reproForHeaderProbe(ctx.finding);
    },
    impact() {
      return ['Bila terverifikasi: mempermudah pemetaan serangan (versi rentan, struktur internal) atau langsung membocorkan data/secret (tergantung jenis paparan).', 'Nilai rahasia tidak dimasukkan ke laporan ini; rotasi secret diperlukan bila verifikasi manual menemukan secret asli terekspos.'];
    },
    remediation: [
      'Hapus/blokir sumber paparan dari akses publik (pesan error, listing, file konfigurasi, header versi).',
      'Rotasi secret/kredensial bila verifikasi menunjukkan nilai asli terekspos.',
      'Batasi detail error pada respons klien; log penuh cukup di sisi server.',
    ],
    references: ['https://owasp.org/www-project-top-ten/'],
  },

  /* I. RCE */
  rce: {
    fields(ctx) {
      const f = ctx.finding;
      return [
        { label: 'Nama template & sumber deteksi', value: `template "${f.externalId || '-'}" dari engine ${f.engine}` },
        { label: 'Bukti tersedia', value: f.evidence ? '(lihat Evidence - bukti hasil pencocokan template, telah disensor)' : 'tidak ada bukti tersimpan (gap)' },
        { label: 'Batas validasi', value: 'Hasil berbasis signature/pencocokan template diberi label INDIKASI; TIDAK ada perintah berbahaya yang dijalankan untuk membuktikan eksekusi kode.' },
      ];
    },
    repro(ctx) {
      const curl = reproFromCurl(ctx.finding);
      if (curl) return ['Perintah uji yang dipakai scanner saat deteksi (bukan eksekusi perintah berbahaya):', curl.curl, 'Verifikasi lanjutan WAJIB aman: gunakan marker unik non-berbahaya (mis. ID unik yang dicatat) pada lingkungan uji milik Anda.'];
      return ['Verifikasi hanya di lingkungan uji milik Anda dengan payload non-berbahaya yang tidak menjalankan perintah sistem nyata.'];
    },
    impact() {
      return ['Bila terverifikasi: eksekusi kode/perintah di sisi server - dampak tertinggi pada kelas web (akses penuh aplikasi).', 'Hingga diverifikasi secara aman, temuan ini berstatus indikasi, bukan RCE terkonfirmasi.'];
    },
    remediation: [
      'Perbarui komponen terdampak ke versi yang telah memperbaiki kerentanan.',
      'Batasi hak proses aplikasi (least privilege) dan isolasikan lingkungan eksekusi.',
      'Tutup jalur eksekusi dinamis: validasi input, hindari eval/deserialisasi tidak tepercaya.',
    ],
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Command_Injection_Defense_Cheat_Sheet.html'],
  },

  /* J. Open Redirect */
  'open-redirect': {
    fields(ctx) {
      const obj = evidenceJson(ctx.finding);
      const detail = obj && obj.detail ? String(obj.detail) : evidenceText(ctx.finding, 600);
      const locMatch = /(?:->|location:\s*)(https?:\/\/[^\s"',]+)/i.exec(detail);
      return [
        { label: 'URL terdampak', value: ctx.urls.ok ? ctx.urls.url : ctx.urls.raw },
        { label: 'Parameter terdampak', value: ctx.urls.params.length ? ctx.urls.params.join(', ') : 'tidak teridentifikasi dari bukti (gap)' },
        { label: 'Tujuan redirect teramati', value: locMatch ? locMatch[1] : 'belum ada tujuan redirect aktual pada bukti (perlu verifikasi manual)' },
        { label: 'Batas bukti', value: 'Redirect ke host luar scope yang diamati engine adalah INDIKASI; belum dibuktikan bahwa tujuan dapat dikontrol penyerang bebas.' },
      ];
    },
    repro() {
      return ['Uji dengan parameter redirect milik target menggunakan nilai tujuan host uji milik Anda; catat Location hasilnya. Jangan memakai domain pihak ketiga sebagai tujuan uji.'];
    },
    impact() {
      return ['Bila terverifikasi: pengguna diarahkan ke domain penyerang lewat domain tepercaya (phishing yang meyakinkan, penyalahgunaan token pada redirect).'];
    },
    remediation: [
      'Gunakan allowlist tujuan redirect (domain/path yang diizinkan).',
      'Hindari redirect berdasarkan URL mentah dari input; pakai indeks tujuan.',
      'Sertakan konfirmasi interstisial untuk redirect keluar yang tidak terhindarkan.',
    ],
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html'],
  },

  /* K. CORS Misconfiguration */
  cors: {
    fields(ctx) {
      const detail = evidenceText(ctx.finding, 1200);
      const aco = /Access-Control-Allow-Origin:\s*([^\s"',]+)/i.exec(detail);
      const acac = /Access-Control-Allow-Credentials:\s*([^\s"',]+)/i.exec(detail);
      return [
        { label: 'Header CORS teramati', value: aco ? `Access-Control-Allow-Origin: ${aco[1]}` : '(header CORS belum terekam pada bukti - perlu verifikasi manual)' },
        { label: 'Origin pengujian', value: 'Scanner ini TIDAK mengirim Origin pihak ketiga pada pengujian pasif; kondisi refleksi origin belum diuji otomatis (gap).' },
        { label: 'Kondisi kredensial', value: acac ? `Access-Control-Allow-Credentials: ${acac[1]}` : 'tidak teramati dari bukti' },
        { label: 'Batas interpretasi', value: 'Access-Control-Allow-Origin: * TIDAK otomatis menjadi kerentanan; dampak hanya muncul bila kredensial terlibat atau data sensitif terbaca lintas origin.' },
      ];
    },
    repro() {
      return ['Verifikasi manual: kirim permintaan dengan header Origin dari domain uji milik Anda, amati ACAO/ACAC pada respons, lalu uji akses data dengan kredensial hanya bila kebijakan target mengizinkan.'];
    },
    impact() {
      return ['Bila terverifikasi (refleksi origin arbitrer + kredensial): data terproteksi dapat dibaca lintas origin dari browser korban.', 'Tanpa kredensial/data sensitif, dampak terbatas - perlu konteks aplikasi.'];
    },
    remediation: [
      'Gunakan allowlist origin eksplisit; jangan merefleksikan header Origin request secara mentah.',
      'Jangan kombinasikan kredensial (ACAC true) dengan wildcard.',
      'Batasi metode/header yang diizinkan sesuai kebutuhan aplikasi.',
    ],
    references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS'],
  },

  /* L. TLS / Cryptographic Weakness */
  'tls-crypto': {
    fields(ctx) {
      const obj = evidenceJson(ctx.finding);
      const detail = obj && obj.detail ? String(obj.detail) : evidenceText(ctx.finding, 600);
      const proto = /(TLSv1(?:\.[01])?)/.exec(detail);
      return [
        { label: 'Host/layanan', value: ctx.urls.host || ctx.urls.raw },
        { label: 'Protokol/konfigurasi terdeteksi', value: proto ? proto[1] : detail.slice(0, 200) || ctx.finding.name },
        { label: 'Batasan hasil', value: 'Pemeriksaan hanya negosiasi/validasi koneksi standar; tidak ada eksploitasi kripto (mis. MITM) yang dilakukan.' },
      ];
    },
    repro(ctx) {
      return [`Negosiasi ulang TLS ke ${ctx.urls.host} dengan klien yang menawarkan protokol lama dan amati versi yang diterima server.`];
    },
    impact() {
      return ['Bila terverifikasi: protokol lama mengurangi jaminan kerahasiaan/integritas koneksi (downgrade, kelemahan cipher usang).'];
    },
    remediation: [
      'Aktifkan TLS 1.2+ (disarankan 1.3) dan nonaktifkan TLS 1.0/1.1.',
      'Gunakan cipher suite modern; kelola sertifikat (validitas, rantai, rotasi).',
      'Aktifkan HSTS setelah seluruh konten aman di HTTPS.',
    ],
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cipher_String_Cheat_Sheet.html'],
  },

  /* M. Known Vulnerable Component */
  'known-component': {
    fields(ctx) {
      const f = ctx.finding;
      const obj = evidenceJson(f);
      const extracted = obj && Array.isArray(obj.extracted) ? obj.extracted : [];
      const versionSource = extracted.length
        ? `versi terekstrak engine: ${extracted.join(', ')} (terkonfirmasi oleh ekstraksi)`
        : 'versi dari penamaan/banner (PERKIRAAN, belum terkonfirmasi)';
      return [
        { label: 'Produk & versi', value: f.name || f.externalId || '-' },
        { label: 'Sumber identifikasi', value: `engine ${f.engine}, template "${f.externalId || '-'}"` },
        { label: 'Status versi', value: versionSource },
        { label: 'CVE/advisory', value: ctx.meta.cve ? `${ctx.meta.cve} (dari metadata engine)` : 'pemetaan CVE belum tersedia dari sumber tervalidasi (tidak dipaksakan)' },
        { label: 'Batas interpretasi', value: 'Komponen TIDAK dinyatakan rentan hanya dari banner versi; perlu bukti tambahan bahwa konfigurasi/versi benar-benar terdampak.' },
      ];
    },
    repro() {
      return ['Verifikasi manual: pastikan versi produk yang berjalan (bukan hanya banner), lalu cocokkan dengan persyaratan eksploitasi pada advisori resmi.'];
    },
    impact() {
      return ['Bila versi & konfigurasi terkonfirmasi terdampak: dampak sesuai advisori (dari RCE hingga disclosure) - belum dinilai oleh scan ini.'];
    },
    remediation: [
      'Perbarui komponen ke versi yang tidak terdampak sesuai advisori vendor.',
      'Terapkan mitigasi sementara dari vendor bila upgrade belum memungkinkan.',
      'Inventarisasi komponen (SBOM) dan pantau advisori keamanan secara berkala.',
    ],
    references: ['https://owasp.org/www-project-top-ten/'],
  },

  /* Fallback - jenis tidak dikenali */
  fallback: {
    fields(ctx) {
      return [
        { label: 'Metode deteksi', value: `Engine ${ctx.finding.engine}, temuan "${ctx.finding.name || ctx.finding.externalId || '-'}", klasifikasi ${ctx.finding.classification}.` },
        { label: 'Alasan fallback', value: 'Klasifikasi otomatis tidak menemukan kombinasi sinyal yang cukup yakin; temuan dipertahankan apa adanya untuk review manual.' },
      ];
    },
    repro() {
      return ['Tidak ada langkah reproduksi otomatis untuk temuan tak terklasifikasi - review manual terhadap bukti diperlukan.'];
    },
    impact() {
      return ['Belum dinilai: jenis kerentanan belum terklasifikasi sehingga dampak tidak dapat dirumuskan dari data tersedia.'];
    },
    remediation: [],
    references: [],
  },
};

/**
 * Bangun bagian spesifik untuk tipe tertentu.
 * Hasil: { fields, repro, impact, remediation, references }
 */
function buildSpecifics(typeKey, ctx) {
  const tpl = TEMPLATES[typeKey] || TEMPLATES.fallback;
  const base = {
    fields: [],
    repro: [],
    impact: [],
    remediation: [],
    references: [],
  };
  try {
    if (tpl.fields) base.fields = tpl.fields(ctx).filter((x) => x && x.value);
    if (tpl.repro) base.repro = tpl.repro(ctx) || [];
    if (tpl.impact) base.impact = tpl.impact(ctx) || [];
    base.remediation = (tpl.remediation || []).slice();
    base.references = uniq([...refsFromFinding(ctx.finding), ...(tpl.references || []), ...cweRefs(ctx.meta)], 8);
  } catch (_) {
    // builder tidak boleh meruntuhkan generator; biarkan bagian dasar
  }
  return base;
}

module.exports = { TEMPLATES, buildSpecifics, parseTargetUrl, evidenceJson, evidenceText };
