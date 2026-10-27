# CxL Bug Bounty Scanner

Bot Telegram untuk mengorkestrasi security assessment non-destruktif terhadap **aplikasi web/domain yang Anda miliki atau Anda izinkan untuk diuji** (bug bounty dengan policy yang mengizinkan). Berjalan langsung di **Termux (Android, target utama ARM64)** tanpa VPS/cloud. Node.js adalah runtime utama; engine scanning dipanggil sebagai proses lokal via CLI resmi masing-masing tool.

> **PERINGATAN LEGAL**: Gunakan HANYA terhadap sistem yang Anda miliki atau yang Anda memiliki izin tertulis untuk menguji. Pengujian tanpa izin dapat melanggar hukum. Pengguna bertanggung jawab penuh atas penggunaan alat ini.

---

## Status kejujuran proyek (WAJIB DIBACA)

Dikembangkan dan diverifikasi di lingkungan **Linux x86_64 (Node 24)**. Yang **sudah diverifikasi** di lingkungan tersebut:

| Verifikasi | Status |
|---|---|
| Unit test (scope, network guard, parser, owasp, orchestrator, db, auth) | LULUS (`npm test`) |
| Self-test mandiri (`--self-test`, tanpa memindai target publik) | LULUS |
| Migrasi database (`--db-migrate`) dengan driver adapter | LULUS |
| Render laporan TXT/JSON/HTML + sanitasi XSS | LULUS |
| Simulasi engine gagal/timeout/dibatalkan (stub engine, tanpa jaringan) | LULUS |

Yang **BELUM dapat diverifikasi** oleh pengembang dan harus Anda uji sendiri di perangkat:

| Item | Keterangan |
|---|---|
| Eksekusi di Termux/perangkat Android nyata | TIDAK diklaim terbukti. Jalankan `install.sh` lalu `npm run check` di perangkat Anda. |
| Kompilasi `better-sqlite3` di Termux | Bergantung toolchain; jika gagal, driver fallback `node:sqlite` (Node >= 22.5) dipakai otomatis. |
| Kompatibilitas binary engine di Android ARM64 | Installer memverifikasi setiap binary dengan `-version`; binary yang tidak berjalan dilaporkan `INCOMPATIBLE`, bukan "sukses". |
| Xray di Termux | Rilis resmi xray memakai glibc; umumnya **INCOMPATIBLE** natif di Termux (bionic). Status akan tampil jujur; alternatif: proot-distro atau host terpisah. |
| Alur Telegram end-to-end | Memerlukan BOT_TOKEN Anda sendiri. |

Semua fitur yang tidak dapat diimplementasikan diberi label `NOT_IMPLEMENTED`/`UNAVAILABLE` di kode/laporan (contoh: scan terautentikasi dengan akun uji belum didukung).

---

## Fitur

- **Mode scan**: `quick`, `full`, `deep`, `recon`, `owasp`, `sans`, `xss`, `sqli`, `malware`, `nuclei`, `endpoints`, `secrets`, `custom` (pilih engine).
- **Menu picker `/scan`**: pilih jenis scan lewat tombol - Full Scan, XSS, SQL Injection, OWASP Top 10, SANS Top 25, Malware, Quick, Subdomain.
- **Kontrol job saat scan berjalan**: tombol `⏹ Stop Scan`, `📋 Cek Status`, `📄 Hasil`, `🗂 Laporan` + progress per tahap secara live.
- **Kamus Bug (Vuln KB) v1.5**: 52 jenis kerentanan dengan **Vuln ID (CXL-xxx)**, **CWE ID**, **severity (critical/high/medium/low/info)**, penjelasan bug, dampak, **CONTOH PAYLOAD**, **CONTOH BUG DETAIL** (kode rentan + request serangan + respons rentan), cara perbaikan, dan referensi. Tampil di 3 tempat:
  1. **Live saat scan** - bug yang baru ditemukan langsung ditampilkan: `🟠 [CXL-021 | CWE-79] Reflected XSS - target - payload: ...` + tombol `🔎 Detail Bug`.
  2. **Tombol Detail Bug** di hasil scan - halaman lengkap bug: apa ini, dampak, payload, kode rentan, request serangan, respons rentan, cara fix.
  3. **Perintah `/vuln`** - kamus bug manual: `/vuln` (daftar), `/vuln xss`, `/vuln CXL-001`, `/vuln CWE-89`.
- **Engine adapter nyata** (CLI resmi, tanpa mock): Nuclei (utama), Subfinder, DNSx, HTTPx, Katana, Xray (opsional), plus **headerProbe** (engine internal Node murni untuk header keamanan/TLS/file terekspos).
- **Engine INTERNAL baru v1.4 - scan bekerja tanpa binary eksternal** (fallback otomatis, 100% Node murni):
  - `subfinder-internal` - enumerasi subdomain pasif via Certificate Transparency (crt.sh) + brute DNS wordlist ringan.
  - `dnsx-internal` - resolusi A/AAAA/CNAME via `node:dns`.
  - `httpx-internal` - deteksi layanan HTTP: status, title, webserver, teknologi, redirect.
  - `katana-internal` - crawler ringan: tautan, script JS, form action, endpoint API (tanpa eksekusi JS, tanpa mengikuti redirect keluar scope).
  - `vulnscan-internal` - pemindai kerentanan non-destruktif: header keamanan + skor, cookie flags, CORS misconfiguration (reflected origin/wildcard+credentials), open redirect (kanari domain), reflected XSS (marker aman), SQLi error-based signature, path traversal signature, 38+ file sensitif terekspos (.env, .git, backup, actuator, phpinfo, dll), directory listing, HTTP methods berisiko, mixed content, TLS lemah/sertifikat kedaluwarsa, info disclosure (stack trace, IP privat, email), dan indikasi subdomain takeover (CNAME + fingerprint layanan mati).
  - `secrets-internal` - deteksi API key/secret bocor di halaman & file JS (AWS, Google, Azure, GitHub, Slack, Stripe, JWT, private key, MongoDB/Postgres URI, dll) dengan REDAKSI otomatis (nilai mentah tidak pernah disimpan).
  - `ports-internal` - scan port web umum (TCP connect, timeout ketat).
  - `dnsinfo-internal` - record DNS lengkap + keamanan email (SPF/DMARC/MTA-STS).
- **Rich message Telegram (gaya base.zip)**: semua output memakai API `sendRichMessage` dengan blok terstruktur (heading, divider, paragraph, list, table, buttons, thinking) + fallback otomatis ke HTML bila server Bot API tidak mendukung. Menu utama dengan tombol inline fungsional.
- **Tools instan** (hasil langsung tanpa antrean): `/headers`, `/cors`, `/paths`, `/tech`, `/ports`, `/dnsinfo`, `/ipinfo` - semuanya tetap tervalidasi scope + network guard.
- **Verifikasi flag CLI**: setiap flag diverifikasi terhadap output `--help` versi yang terinstal; flag yang tidak didukung tidak pernah dikarang.
- **OWASP Top 10:2025**: pemetaan temuan ke kategori + matriks coverage dengan status jujur (`CHECKED_FINDINGS`, `CHECKED_NO_FINDINGS`, `PARTIAL`, `MANUAL_REQUIRED`, `NOT_TESTED`, `ENGINE_UNAVAILABLE`). A06/A09 selalu manual; tidak ada klaim "Top 10 teruji penuh".
- **Scope validation & network guard**: allowlist root domain/port/protokol, penolakan IP private/loopback/link-local/CGNAT/multicast/reserved, DNS fail-closed, re-check DNS antar tahap, catatan keputusan ALLOW/DENY ke database, penolakan URL ber-kredensial/IP literal (kecuali LAB MODE), validasi redirect.
- **Keamanan template**: tag `intrusive,destructive,bruteforce,dos,fuzz,stealth` dieksekusi (dikecualikan) secara default.
- **Telegram bot**: semua perintah fungsional, role admin/user berbasis user ID, konfirmasi target sebelum scan, progress per tahap dari status proses nyata (tanpa persentase palsu), pagination, kirim laporan sebagai file.
- **Database**: SQLite dengan driver adapter (`better-sqlite3` utama, `node:sqlite` fallback) - trade-off terdokumentasi di bawah.
- **Laporan**: TXT, JSON, dan HTML (dengan escape ketat + CSP; hasil scan tidak bisa menyisipkan script ke laporan).
- **Laporan kerentanan cerdas**: klasifikasi per-jenis dari temuan nyata, status validasi berversi, catatan review, ekspor TXT/MD/JSON/HTML.
- **Installer Termux idempotent**: dari rilis resmi GitHub + verifikasi checksum resmi; tidak ada mirror acak; status gagal dilaporkan apa adanya.
---

## Perintah Bot (v1.5)

### Scan (via antrean + laporan lengkap)
| Perintah | Fungsi |
|---|---|
| `/scan domain.com` | **Menu tombol pilih jenis scan**: Full, XSS, SQL Injection, OWASP Top 10, SANS Top 25, Malware, Quick, Subdomain |
| `/fullscan domain.com` | Full: quick + crawling + vuln scan |
| `/deepscan domain.com` | **Deep**: crawl + vuln mendalam (XSS/SQLi/redirect/CORS/traversal) + secrets |
| `/subdomain domain.com` | Enumerasi subdomain (subfinder + dnsx + cek host hidup) |
| `/xss domain.com` | Fokus deteksi XSS |
| `/sqli domain.com` | Fokus deteksi SQL injection |
| `/sans domain.com` | Penilaian SANS/CWE Top 25 |
| `/malware domain.com` | Deteksi malware/defacement/webshell/miner/spam |
| `/owasp domain.com` | Coverage OWASP Top 10:2025 |
| `/nuclei domain.com` | Vuln scan dengan pilih severity |
| `/endpoints domain.com` | Kumpulkan endpoint dalam scope |
| `/secrets domain.com` | Cari API key/secret bocor di JS |
| `/recon domain.com` | Recon: DNS + subdomain + port web |

### Tools instan (hasil langsung, tanpa antrean)
| Perintah | Fungsi |
|---|---|
| `/headers domain.com` | Analisis header keamanan + skor 0-100 |
| `/cors domain.com` | Uji CORS misconfig (3 varian origin) |
| `/paths domain.com` | File sensitif terekspos (.env, .git, backup, dll) |
| `/tech domain.com` | Fingerprint teknologi |
| `/ports domain.com` | Port web umum terbuka |
| `/dnsinfo domain.com` | Record DNS + SPF/DMARC |
| `/ipinfo domain.com` | Info IP/ASN via RDAP |

### Kamus Bug (KB kerentanan)
| Perintah | Fungsi |
|---|---|
| `/vuln` | Daftar semua jenis bug (52) dikelompokkan per severity + tombol detail |
| `/vuln xss` | Cari bug: penjelasan + contoh payload + kode rentan + cara fix |
| `/vuln CXL-021` | Detail bug berdasarkan Vuln ID |
| `/vuln CWE-89` | Detail bug berdasarkan CWE ID |
| Tombol `🔎 Detail Bug` | Halaman bug detail dari temuan live/hasil scan: payload + contoh kode rentan + request/respons serangan + cara perbaiki |

### Manajemen
`/status`, `/stop`, `/results`, `/history`, `/report jobId`, `/vreports`, `/menu`, `/tools`, `/scope`, `/stats`, `/help`

## Instalasi dari nol (Termux)

```bash
# 1. Instal Termux (disarankan dari F-Droid atau GitHub termux-app, bukan Play Store)
# 2. Perbarui dan instal dasar
pkg update && pkg upgrade
pkg install git
# 3. Ambil proyek
git clone <url-repo-anda> cxl-bug-bounty-scanner
cd cxl-bug-bounty-scanner
# 4. Jalankan installer (idempotent; aman diulang)
bash install.sh
# 5. Konfigurasi
nano .env     # isi BOT_TOKEN & ADMIN_IDS (ALLOWED_TARGETS opsional - kosong = mode terbuka)
# 6. Jalankan
npm start
```

Instalasi manual (tanpa installer):

```bash
pkg install nodejs-lts git curl unzip
npm install
node src/index.js --db-migrate
npm test
npm start
```

### Checklist sebelum dipakai (CxL v1.3.0)

- Isi `BOT_TOKEN` dan `ADMIN_IDS` di `.env`. Batasi `ALLOWED_USERS` ke Telegram user ID milik Anda/tim; jangan biarkan bot pemindaian terbuka untuk umum.
- `ALLOWED_TARGETS` bersifat OPSIONAL. Kosong = mode terbuka (domain publik apa pun bisa di-scan); diisi = scanner terkunci ke root domain tersebut. Gunakan mode terbuka hanya untuk target yang Anda miliki izin resminya.
- Pastikan domain berada dalam scope tertulis program bug bounty dan aturan program mengizinkan jenis pemindaian yang dipilih.
- Jalankan `npm run check`, `npm test`, dan `npm run tools:check` sebelum scan pertama.
- Mulai dari mode `quick`, rate-limit rendah, dan satu scan bersamaan. Jangan aktifkan OOB/Interactsh atau template invasif untuk mengejar hasil.
- Simpan laporan secara privat. Tinjau dan redaksi bukti sebelum mengirim laporan ke platform; jangan otomatis mengirim laporan tanpa pemeriksaan manusia.
- Hasil scanner adalah indikasi, bukan bukti final. Validasi manual dengan permintaan minimal yang aman, catat dampak yang dapat dibuktikan, dan hindari mengakses/mengekspor data pengguna.
- Gunakan `/stop` jika target melambat, muncul error tak terduga, atau scan mulai menyentuh area di luar scope.

## Perintah npm

| Perintah | Fungsi |
|---|---|
| `npm start` | Jalankan bot |
| `npm test` | Unit test + test integrasi (stub, tanpa jaringan) |
| `npm run check` | Self-test (`--self-test`) |
| `npm run tools:check` | Verifikasi executable + versi semua engine |
| `npm run db:migrate` | Jalankan migrasi database |

### Perintah bot

| Perintah | Fungsi |
|---|---|
| `/start`, `/help` | Menu & panduan |
| `/scan domain.com` | Quick scan |
| `/fullscan domain.com` | Full scan |
| `/owasp domain.com` | Coverage OWASP Top 10:2025 |
| `/nuclei domain.com` | Nuclei saja (pilih severity via tombol) |
| `/endpoints domain.com` | Kumpulkan endpoint |
| `/status`, `/stop [jobId]` | Status & pembatalan (hanya milik sendiri; admin dapat semua) |
| `/results`, `/history`, `/report ID` | Hasil, riwayat, laporan (TXT/JSON/HTML) |
| `/tools`, `/checktools` | Status engine (cache) & verifikasi live |
| `/installtools` | Installer terkontrol (admin) |
| `/scope`, `/stats` | Konfigurasi scope & statistik lokal |

---

## Konfigurasi scope (OPSIONAL - mode terbuka)

```ini
# KOSONGKAN ALLOWED_TARGETS = MODE TERBUKA: scanner menerima domain publik apa pun.
# ISI ALLOWED_TARGETS       = terkunci hanya ke domain tersebut.
ALLOWED_TARGETS=                            # kosong = mode terbuka (v1.5)
ALLOWED_PORTS=80,443,8080,8443
ALLOWED_PROTOCOLS=https,http
LAB_MODE=false                              # hanya untuk lab lokal milik sendiri
LAB_ALLOWED_TARGETS=                        # mis. 127.0.0.1 saat LAB_MODE=true
```

> v1.5: `ALLOWED_TARGETS` TIDAK WAJIB lagi. Saat kosong, scanner berjalan dalam **mode terbuka**
> (domain publik apa pun diterima). Pelindung keamanan TETAP AKTIF dan tidak bisa dimatikan:
> IP privat/loopback/internal selalu ditolak, DNS fail-closed, URL dengan kredensial ditolak,
> dan hanya protokol/port yang diizinkan dipakai. Isi `ALLOWED_TARGETS` bila ingin mengunci scanner.

Aturan yang ditegakkan kode (bukan sekadar dokumentasi):

- Scan tanpa konfirmasi target + scope tidak mungkin (tombol konfirmasi Telegram).
- Hasil enumerasi/crawl di luar scope dibuang dan dicatat sebagai `DENY` di tabel `scope_decisions`.
- `localhost`, IP private/loopback/link-local/CGNAT/multicast/reserved ditolak default; lab mode memerlukan konfigurasi eksplisit per host/CIDR.
- Input shell/argumen CLI arbitrer dari Telegram tidak pernah diteruskan ke proses (semua spawn memakai array argumen, tanpa shell).
- URL dengan kredensial (userinfo), skema non-HTTP(S), dan IP literal (mode normal) ditolak.

### Keterbatasan mitigasi DNS rebinding (jujur)

Guard memvalidasi semua IP hasil resolusi **sebelum setiap tahap** dan re-check antar tahap; request internal (headerProbe) memakai **DNS pinning** (custom `lookup`). Namun engine eksternal (nuclei/httpx/katana) melakukan resolusi sendiri saat berjalan — jendela TOCTOU kecil tidak dapat dihilangkan dari luar proses mereka. Ini didokumentasikan sebagai keterbatasan di laporan.

---

## Database: driver & trade-off

| Driver | Kapan dipakai | Trade-off |
|---|---|---|
| `better-sqlite3` | default bila modul termuat | Matang & cepat; butuh kompilasi native di Termux (`pkg install clang python make binutils`). |
| `node:sqlite` | fallback otomatis (Node >= 22.5) atau `DB_DRIVER=node:sqlite` | Tanpa kompilasi, bawaan Node; API lebih baru, cukup untuk bot tunggal (koneksi tunggal, WAL, busy_timeout). |

Keduanya sinkron dan memakai skema/migrasi yang sama. Migrasi idempotent, dibungkus transaksi `BEGIN IMMEDIATE`.

## Menjaga proses tetap hidup di Termux

```bash
termux-wake-lock        # cegah sleep CPU (pkg install termux-api bila belum ada)
tmux                    # sesi tahan tutup: pkg install tmux
tmux new -s cxl
npm start               # detach: Ctrl+B lalu D ; attach: tmux attach -t cxl
```

**Catatan Android**: sistem dapat menghentikan proses latar belakang. Mitigasi: matikan optimasi baterai untuk Termux (Pengaturan > Aplikasi > Termux > Baterai > Tidak dibatasi), kunci aplikasi di recent apps, dan pahami bahwa beberapa produsen (mis. Xiaomi/Huawei) lebih agresif. Bot menandai scan yang terputus oleh restart sebagai `FAILED` dengan alasan jelas (recovery restart), bukan menggantung selamanya.

## Troubleshooting

| Gejala | Penyebab & solusi |
|---|---|
| `Executable tidak ditemukan` di /tools | Engine belum terpasang: `bash install.sh --tools-only` lalu `/checktools`. |
| `INCOMPATIBLE (EXEC_FORMAT)` | Binary release tidak cocok arsitektur/OS (umum untuk xray di Termux). Coba `go install` (butuh `pkg install golang`) atau jalankan tool di host lain. |
| `better-sqlite3 gagal dimuat` | Kompilasi native gagal: `pkg install clang python make binutils && npm rebuild better-sqlite3`, atau biarkan fallback `node:sqlite` (Node >= 22.5), atau set `DB_DRIVER=node:sqlite`. |
| Bot error 401 Unauthorized | BOT_TOKEN salah. Buat ulang token via @BotFather. |
| Bot error 409 Conflict | Instansi lain berjalan dengan token sama. Hentikan salah satu. |
| Target ditolak "di luar scope" | ALLOWED_TARGETS terisi dan target tidak cocok. Tambahkan root domain di .env lalu restart, ATAU kosongkan ALLOWED_TARGETS untuk mode terbuka. |
| Scan berhenti saat layar mati | Lihat bagian "Menjaga proses tetap hidup". Phantom process killer Android 12+ juga dapat menghentikan Termux; gunakan wake-lock + nonaktifkan optimasi baterai. |
| DNS gagal (fail-closed) | Perangkat tanpa DNS kerja; cek `ping 1.1.1.1` dan konfigurasi resolver Termux. Guard tetap menolak bila DNS tidak jelas (by design). |
| `Flag wajib ... tidak didukung` | Versi engine terlalu lama; perbarui engine (`nuclei -version` untuk cek). Aplikasi menolak menebak flag. |
| Antrean penuh | Tunggu atau naikkan `QUEUE_MAX` dengan hati-hati (perangkat mobile: jangan). |

## Struktur proyek

```
cxl-bug-bounty-scanner/
├── package.json            install.sh             .env.example        README.md
├── src/
│   ├── index.js            # entry point + mode CLI
│   ├── bot.js              # Telegraf: semua perintah, RBAC, progress nyata
│   ├── config.js           # buildConfig/loadConfig (env -> konfigurasi tervalidasi)
│   ├── selfTest.js         # --self-test (tanpa memindai target publik)
│   ├── database/           # db.js (driver adapter + store), migrations.js
│   ├── scope/              # validator.js (allowlist), networkGuard.js (private IP/DNS)
│   ├── engines/            # baseEngine.js, nuclei.js, subfinder.js, dnsx.js,
│   │                       # httpx.js, katana.js, xray.js, headerProbe.js, index.js
│   ├── scanner/            # orchestrator.js, queue.js, worker.js, cancellation.js
│   ├── owasp/              # categories.js (2025), mapping.js, coverage.js
│   ├── reports/            # json.js, text.js, html.js (escaped + CSP)
│   ├── vulnreports/        # Intelligent Vulnerability Report Generator:
│   │                       # classifier, mappings (CWE/OWASP tervalidasi), redactor,
│   │                       # templates (13 tipe + fallback), generator, store, exporters
│   └── utils/              # logger.js, processRunner.js, validation.js, auth.js, format.js
├── tests/                  # scope, networkGuard, parser, owasp, orchestrator, db, auth,
│                           # vulnreports + fixtures
├── data/                   # (runtime) database, log, tmp - TIDAK berisi token
└── reports/                # (runtime) laporan txt/json/html + laporan cerdas per job
```

## Laporan Kerentanan Cerdas (Intelligent Vulnerability Report Generator)

Setiap scan selesai, sistem membuat **laporan berbeda per jenis kerentanan** dari temuan nyata engine yang benar-benar berjalan (nuclei, headerProbe, dan xray bila kompatibel + berlisensi). Prinsip yang sama dengan seluruh proyek: tidak ada hasil hardcode, tidak ada temuan rekayasa.

**Alur otomatis** (dijalankan di tahap finalize):

1. Parse temuan nyata dari database (semua engine yang berhasil berjalan).
2. Klasifikasi multi-sinyal: checkId engine internal, CWE dari metadata engine (mis. `classification.cwe-id` Nuclei), pola template-id, tag, nama, dan penanda isi bukti. Sinyal diberi bobot; hasil = tipe + confidence `HIGH/MEDIUM/LOW`.
3. Tidak pasti? otomatis ditandai `NEEDS_REVIEW`. Tidak dikenali? **template fallback** + `NEEDS_REVIEW` (tidak pernah dipaksa).
4. Pilih template spesifik: SQL Injection, XSS, Broken Access Control/IDOR, SSRF, LFI/Path Traversal, Auth/Session, Security Misconfiguration, Sensitive Information Exposure, RCE, Open Redirect, CORS, TLS/Crypto, Known Vulnerable Component.
5. Isi HANYA data yang tersedia; data/bukti yang kurang masuk daftar **gaps** (bukti kurang) - bukan diisi teks generik.
6. Sensor bukti: token, `Authorization`/`Cookie`, JWT, kunci AWS, kunci privat, parameter rahasia di URL, password disensor sebelum disimpan/ditampilkan.
7. Deduplikasi lintas-temuan (tipe + endpoint) dengan tetap merujuk semua temuan sumber.
8. Ringkasan dikirim ke Telegram dengan tombol **Preview / Edit / Mark Reviewed / Export** per laporan.

**Struktur laporan (16 bagian universal, bagian tak relevan dihilangkan):** judul spesifik, ringkasan, aset terdampak, jenis, severity (sumber + penilaian ulang), confidence, pemetaan CWE/CVE/OWASP (berlabel sumber), bukti tersensor, langkah reproduksi (hanya yang didukung bukti, mis. curl-command nyata dari engine), hasil diharapkan, hasil aktual, dampak (bingkai kondisional), remediasi per tipe, referensi, scanner & template, status validasi + keterbatasan + gaps.

**Keterbukaan status & severity:**

- Status validasi: `DETECTED` (bukti konkret), `NEEDS_MANUAL_VERIFICATION` (default; semua temuan scanner dimulai dari sini bila bukti minim), serta `CONFIRMED` / `FALSE_POSITIVE` / `NOT_REPRODUCED` yang **hanya** bisa disetel manusia via tombol Edit atau `/vreport status`.
- Severity sumber dipertahankan dari engine. Penilaian ulang sistem terpisah dan terdokumentasi: `TEMPLATE_MATCH` mengikuti engine; `INDICATOR` (pemeriksaan internal) dibatasi maksimum `medium` sampai diverifikasi. **Sistem tidak membuat skor CVSS.**
- CWE hanya ditampilkan bila benar-benar ada di metadata engine; pemetaan OWASP per-CWE memakai OWASP Top 10:2021 (resmi) dan diberi label versi. Kategori 2025 tetap dari pipeline scan. `Access-Control-Allow-Origin: *` saja tidak menyatakan CORS rentan; `IDOR` tidak dinyatakan terkonfirmasi hanya karena ada ID numerik; temuan RCE berbasis signature diberi label indikasi; banner versi saja tidak menyatakan komponen rentan.
- Scan tanpa temuan tidak membuat laporan apa pun dan BUKAN pernyataan target aman.

**Perintah Telegram:** `/vreports [jobId]` (daftar), `/vreport <uid>` (pratinjau + tombol), `/vreport status <uid> <STATUS>`, `/vreport note <uid> <teks>`. Ekspor per laporan: TXT / Markdown / JSON / HTML; berkas disimpan di `reports/<jobId>/`. Setiap perubahan status/review/regenerasi tercatat sebagai **versi baru** (jejak audit) di tabel `vuln_report_versions`; regenerasi scan mempertahankan status manual dan status review manusia.

## Keamanan data

- `BOT_TOKEN` hanya hidup di `.env`/memori; logger menyamarkan pola token dan `key=value` rahasia.
- `data/` dan `reports/` tidak pernah memuat token; isi laporan adalah hasil scan target Anda.
- Saat update, installer tidak pernah menghapus `.env`, `data/`, atau `reports/`.
- Isi file sensitif yang ditemukan (mis. `/.env`) **tidak diunduh/disimpan** — hanya indikator keberadaan.

## Pengujian

```bash
npm test                 # 10 berkas test: scope, networkGuard, parser, owasp, orchestrator, db, auth, vulnreports, reports, xray-parser
npm run check            # self-test mandiri (tanpa jaringan keluar, tanpa target publik)
npm run tools:check      # status engine nyata di perangkat Anda
```

Test integrasi memakai **engine stub** dan database sementara (tanpa jaringan, tanpa binary eksternal), mencakup: engine gagal -> `PARTIAL`, engine tidak terpasang -> `UNAVAILABLE`, abort -> `CANCELLED`, scope ditolak -> `FAILED`, duplikasi temuan, dan migrasi idempotent.

## Riwayat perubahan

- **v1.2.0** - Rekonstruksi modul `src/reports/` (ringkasan scan JSON/TXT/HTML dari data store nyata; kolom `report_*_path` kembali terisi). **Parsing output Xray otomatis** dari file `--json-output` resmi (array JSON / objek pembungkus / JSONL; baris rusak dihitung; dokumen non-JSON dilaporkan jujur). Tag `cors`/`csp`/`hsts` kini dipetakan ke A02 (Security Misconfiguration). 73 unit test.
- **v1.1.0** - Intelligent Vulnerability Report Generator: klasifikasi multi-sinyal, 13 template + fallback, sensor bukti, 5 status validasi, tombol Telegram Preview/Edit/Mark Reviewed/Export, versi + audit, ekspor TXT/MD/JSON/HTML.
- **v1.0.0** - Bot Telegram, engine adapter (Nuclei, Subfinder, DNSx, HTTPx, Katana, Xray, headerProbe), scope validator + network guard, coverage OWASP Top 10:2025, installer Termux.

## Perintah berguna di perangkat

```bash
node src/index.js --self-test     # periksa kesehatan instalasi
node src/index.js --tools-check   # verifikasi engine
node src/index.js --db-migrate    # jalankan migrasi
bash install.sh --tools-only      # (re)instal engine saja
nuclei -update-templates          # update template MANUAL dari sumber resmi (opsional; default aplikasi tidak auto-update)
```

## Catatan desain penting

1. **`CHECKED_NO_FINDINGS` bukan berarti aman.** Matriks coverage menyatakan apa yang diperiksa dan apa yang tidak.
2. **Klasifikasi temuan**: `INDICATOR` (headerProbe) < `TEMPLATE_MATCH` (nuclei) — semua wajib diverifikasi manual sebelum dikirim ke program bug bounty. Status `VERIFIED` hanya dicapai oleh penilaian manusia (tidak dihasilkan aplikasi).
3. **Tidak ada hasil hardcode/mock** di jalur runtime; setiap temuan berasal dari output engine yang diparsing, dan baris output yang rusak dihitung, bukan diabaikan diam-diam.
4. **Tahap gagal != scan kosong**: kegagalan engine menghasilkan status `PARTIAL` + baris error tersimpan, tidak pernah "berhasil tanpa temuan".
5. **Laporan cerdas tidak pernah otomatis terkonfirmasi**: `CONFIRMED/FALSE_POSITIVE/NOT_REPRODUCED` hanya lewat tindakan manusia; bukti kosong menghasilkan `NEEDS_MANUAL_VERIFICATION` + gap, bukan laporan "pasti".
6. **Xray (sejak v1.2.0)**: temuan Xray **diparsing otomatis** dari file output JSON resmi (`--json-output`, mendukung array JSON / objek pembungkus / JSONL; baris rusak dihitung, dokumen non-JSON dilaporkan `tidak-dikenali`, bukan diabaikan). Bila engine tidak terpasang / tidak kompatibel / tanpa lisensi, tidak ada laporan cerdas yang dihasilkan darinya - status tetap ditampilkan jujur (`UNAVAILABLE`/`INCOMPATIBLE`/`FAILED`).

## Uji mandiri dengan lab lokal (tanpa target eksternal)

Proyek menyertakan server lab rentan SENGAJA untuk memverifikasi scanner bekerja
end-to-end di perangkat Anda tanpa menyentuh target publik:

```bash
# Terminal 1: jalankan lab (HANYA di 127.0.0.1)
node lab/lab-server.js

# Terminal 2: isi .env (LAB_MODE=true, LAB_ALLOWED_TARGETS=127.0.0.1,
# ALLOWED_PORTS=7777,80,443,8080,8443) lalu di Telegram:
/recon 127.0.0.1
/scan 127.0.0.1
```

Lab menanam kerentanan untuk pengujian: header keamanan hilang, cookie tanpa flag,
/.env & /.git terekspos, directory listing, CORS reflektif, open redirect,
reflected XSS, SQL error disclosure, versi server terungkap, dan secret di JS.
