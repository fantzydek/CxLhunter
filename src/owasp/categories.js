'use strict';

/**
 * Definisi OWASP Top 10:2025 (Web Application Security).
 * Sumber kerangka: https://owasp.org/Top10/
 * PENTING: kategori 2025 dipakai EKSKLUSIF; tidak dicampur dengan 2021 tanpa label versi.
 * Scanner otomatis TIDAK dapat memeriksa semua kategori secara penuh - untuk setiap
 * kategori didefinisikan apa yang tercakup otomatis dan apa yang wajib manual.
 */

const OWASP_CATEGORIES = [
  {
    id: 'A01',
    name: 'Broken Access Control',
    desc: 'Pengguna dapat bertindak di luar izin yang seharusnya (IDOR, akses fungsi tanpa otorisasi, eskalasi peran).',
    autoCoverage:
      'Hanya indikator eksternal: endpoint sensitif yang terekspos tanpa auth, template akses-tanpa-otorisasi non-destruktif, header kontrol cache pada respons publik.',
    limits:
      'IDOR/privilege escalation TIDAK dapat dipastikan dari URL atau respons tunggal; butuh akun uji multi-peran dan penilaian manual.',
    manualChecklist: [
      'Uji akses objek antar-peran dengan akun uji (IDOR pada ID numerik/UUID).',
      'Uji akses fungsi administratif dari peran biasa.',
      'Periksa kontrol akses sisi server pada API (bukan hanya UI yang menyembunyikan tombol).',
      'Review aturan rate-limit dan bypass antrean/proses bisnis.',
    ],
    mitigations: [
      'Terapkan otorisasi di sisi server untuk setiap permintaan (deny-by-default).',
      'Gunakan ID acak tak-terduga tetapi tetap validasi kepemilikan objek.',
      'Catat dan alarmkan penolakan akses massal.',
    ],
  },
  {
    id: 'A02',
    name: 'Security Misconfiguration',
    desc: 'Konfigurasi tidak aman: header keamanan hilang, halaman debug terekspos, directory listing, layanan default.',
    autoCoverage:
      'Pemeriksaan header keamanan HTTP (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy), cookie flags, directory listing, halaman debug/error, file konfigurasi terekspos (GET terbatas, isi tidak disimpan), versi server berlebihan.',
    limits: 'Konfigurasi internal (server, orchestrator, IaC) tidak terlihat dari luar.',
    manualChecklist: [
      'Review konfigurasi server/orkestrasi (hardening baseline).',
      'Nonaktifkan endpoint debug/actuator yang tidak perlu di produksi.',
      'Pastikan environment production tidak memakai kredensial default.',
      'Audit izin bucket storage/CDN.',
    ],
    mitigations: [
      'Tetapkan semua header keamanan yang relevan.',
      'Proses deploy yang repeatable + pemeriksaan drift konfigurasi.',
    ],
  },
  {
    id: 'A03',
    name: 'Software Supply Chain Failures',
    desc: 'Rantai pasok perangkat lunak: dependensi/versi rentan, komponen tidak terverifikasi, build yang dikompromikan.',
    autoCoverage:
      'Identifikasi teknologi/versi yang terlihat dari luar (server header, tech-detect) dan pencocokan indikatif dengan template advisori. Pemeriksaan dependency/SBOM HANYA bila pemilik menyediakan file dependensi.',
    limits:
      'Versi terdeteksi != kerentanan dapat dieksploitasi; perlu konfirmasi manual. Source code/SBOM tidak tersedia dari luar.',
    manualChecklist: [
      'Hasilkan SBOM dan cocokkan dengan advisori (OSV/CVE) dari sisi build.',
      'Kunci dependensi (lockfile) dan verifikasi checksum/artefak build.',
      'Review provenance pipeline CI/CD.',
    ],
    mitigations: [
      'Pembaruan dependensi terjadwal + pemantauan advisori.',
      'Sertifikat/signing artefak build.',
    ],
  },
  {
    id: 'A04',
    name: 'Cryptographic Failures',
    desc: 'Kegagalan kriptografi: transport tanpa TLS, sertifikat tidak valid, versi TLS lemah, cookie tanpa Secure.',
    autoCoverage:
      'Pemeriksaan HTTPS/TLS yang dapat diamati dengan aman: validitas sertifikat, versi protokol yang dinegosiasikan, HSTS, redirect turun ke HTTP, cookie tanpa atribut Secure.',
    limits: 'Algoritma internal (hash password, enkripsi data-at-rest) tidak dapat dinilai dari luar.',
    manualChecklist: [
      'Review pemilihan algoritma & mode (mis. password hashing Argon2/bcrypt).',
      'Rotasi kunci dan pengelolaan secret.',
      'Verifikasi kebijakan TLS di seluruh subdomain (termasuk mail/API).',
    ],
    mitigations: [
      'Paksa HTTPS + HSTS di semua host.',
      'Matikan TLS < 1.2, aktifkan konfigurasi modern.',
    ],
  },
  {
    id: 'A05',
    name: 'Injection',
    desc: 'Injeksi: SQLi, XSS, command injection, template injection, dan varian lain.',
    autoCoverage:
      'Template Nuclei non-destruktif ber-tag injection; deteksi pesan error SQL/eksekusi reflektif pasif. Payload destruktif, dump database, dan eksekusi perintah sistem TIDAK dijalankan.',
    limits:
      'Scanner otomatis hanya melihat permukaan; temuan adalah indikasi/kecocokan template yang wajib diverifikasi manual sebelum dilaporkan ke program.',
    manualChecklist: [
      'Uji injeksi terarah pada parameter kritis dengan payload aman yang disetujui policy program.',
      'Review kode untuk query terkonkatenasi dan eval.',
    ],
    mitigations: [
      'Parameterized query/ORM, escaping konteks untuk output.',
      'Validasi input sisi server yang ketat.',
    ],
  },
  {
    id: 'A06',
    name: 'Insecure Design',
    desc: 'Cacat desain: alur bisnis yang dapat disalahgunakan, absennya threat modeling, kontrol yang tidak proporsional.',
    autoCoverage: 'TIDAK ada pemeriksaan otomatis yang bermakna untuk kategori ini.',
    limits: 'Membutuhkan pemahaman alur bisnis, threat modeling, dan konteks produk.',
    manualChecklist: [
      'Lakukan threat modeling pada alur bisnis utama (auth, pembayaran, reset).',
      'Uji abuse case: negasi sumber daya, race condition, logika keranjang/voucher.',
      'Evaluasi kontrol anti-automation (captcha, throttling) pada fungsi sensitif.',
    ],
    mitigations: [
      'Secure design pattern + referensi ke kebijakan keamanan aplikasi.',
      'Pisahkan lingkungan dan batasi trust antar komponen.',
    ],
  },
  {
    id: 'A07',
    name: 'Authentication Failures',
    desc: 'Kegagalan autentikasi: kredensial default, sesi lemah, cookie tanpa proteksi, halaman login tanpa kontrol.',
    autoCoverage:
      'Indikator dari luar: cookie tanpa HttpOnly/SameSite/Secure pada halaman yang ditemukan, template default-login non-bruteforce, pengungkapan halaman login/admin. Credential stuffing, brute force, dan bypass TIDAK dilakukan.',
    limits: 'Kebijakan kata sandi, MFA, dan manajemen sesi server-side butuh akses/akun uji.',
    manualChecklist: [
      'Uji alur reset kata sandi dan session invalidation.',
      'Verifikasi kebijakan rate limit login dan mekanisme lockout.',
      'Review konfigurasi MFA dan remember-me.',
    ],
    mitigations: [
      'Terapkan kebijakan sesi aman (rotasi, timeout, invalidasi massal).',
      'Aktifkan proteksi brute force di semua endpoint autentikasi.',
    ],
  },
  {
    id: 'A08',
    name: 'Software or Data Integrity Failures',
    desc: 'Integritas: update tanpa verifikasi, deserialisasi tidak aman, CI/CD tanpa kontrol integritas.',
    autoCoverage:
      'Indikator terlihat (mis. manifest/asset tanpa SRI) hanya bila ditemukan template. Pemeriksaan pipeline/source code ditandai MANUAL_REQUIRED bila data tidak tersedia.',
    limits: 'Butuh akses ke artefak build, repo, atau konfigurasi deployment dari pemilik.',
    manualChecklist: [
      'Verifikasi tanda tangan artefak dan mekanisme auto-update.',
      'Review deserialisasi data tidak terpercaya.',
      'Lindungi pipeline CI/CD (least privilege, izin token).',
    ],
    mitigations: ['Terapkan verifikasi integritas (SRI, signature) untuk aset dan dependensi.'],
  },
  {
    id: 'A09',
    name: 'Security Logging and Alerting Failures',
    desc: 'Tidak adanya logging/alerting yang efektif terhadap aktivitas berbahaya.',
    autoCoverage:
      'TIDAK dapat dinilai dari luar. Scanner eksternal tidak melihat log internal; menyatakan "logging gagal" tanpa bukti internal adalah klaim palsu.',
    limits: 'Butuh konfigurasi/bukti dari pemilik aplikasi.',
    manualChecklist: [
      'Pastikan event keamanan kunci tercatat (login gagal, perubahan izin, error 5xx).',
      'Uji jalur alerting (siapa diberi tahu, seberapa cepat).',
      'Review retensi dan proteksi log.',
    ],
    mitigations: ['Definisikan log schema terpusat + alert berbasis anomali.'],
  },
  {
    id: 'A10',
    name: 'Mishandling of Exceptional Conditions',
    desc: 'Penanganan kondisi luar biasa yang buruk: stack trace terekspos, error verbose, respons abnormal yang membocorkan informasi.',
    autoCoverage:
      'Deteksi stack trace/error verbose pada respons (GET aman, jumlah terbatas), respons 5xx, dan template error-disclosure. Tidak memicu crash atau beban berlebih.',
    limits: 'Perilaku error di bawah kondisi beban/race butuh pengujian terkontrol bersama pemilik.',
    manualChecklist: [
      'Uji input tidak valid pada parameter utama dan amati konsistensi respons.',
      'Pastikan halaman error generik untuk publik, detail masuk ke log.',
    ],
    mitigations: ['Handler error global + halaman error generik + logging terstruktur.'],
  },
];

const VALID_STATUSES = [
  'CHECKED_FINDINGS',
  'CHECKED_NO_FINDINGS',
  'PARTIAL',
  'MANUAL_REQUIRED',
  'NOT_TESTED',
  'ENGINE_UNAVAILABLE',
];

function byId(id) {
  return OWASP_CATEGORIES.find((c) => c.id === id) || null;
}

module.exports = { OWASP_CATEGORIES, VALID_STATUSES, byId };
