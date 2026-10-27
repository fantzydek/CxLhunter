#!/usr/bin/env bash
# ============================================================
# CxL Bug Bounty Scanner - Installer Termux
# Idempotent: aman dijalankan ulang; tidak menghapus data pengguna.
#
# Penggunaan:
#   bash install.sh                 # instal lengkap (deps + tools + env + test)
#   bash install.sh --tools-only    # hanya instal/verifikasi engine CLI
#   bash install.sh --skip-tests    # lewati npm test di akhir
#   bash install.sh --yes           # tanpa prompt (NONINTERACTIVE)
#
# Sumber unduhan HANYA rilis resmi GitHub (api.github.com + github.com/release)
# dan checksum resmi per rilis. Tidak ada mirror acak.
# Status yang gagal dilaporkan apa adanya - installer TIDAK mengklaim sukses palsu.
# ============================================================
set -u

VERSION="1.0.0"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$PROJECT_DIR/bin"
TOOLS_ONLY=0
SKIP_TESTS=0
ASSUME_YES=0

for arg in "$@"; do
  case "$arg" in
    --tools-only) TOOLS_ONLY=1 ;;
    --skip-tests) SKIP_TESTS=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    *) echo "Argumen tidak dikenal: $arg (diabaikan)" ;;
  esac
done

# ---------- tampilan ----------
if [ -t 1 ]; then
  C_G='\033[0;32m'; C_Y='\033[0;33m'; C_R='\033[0;31m'; C_B='\033[0;34m'; C_0='\033[0m'
else
  C_G=''; C_Y=''; C_R=''; C_B=''; C_0=''
fi
log()  { printf "${C_B}[*]${C_0} %s\n" "$1"; }
ok()   { printf "${C_G}[OK]${C_0} %s\n" "$1"; }
warn() { printf "${C_Y}[!!]${C_0} %s\n" "$1"; }
err()  { printf "${C_R}[XX]${C_0} %s\n" "$1"; }

require_cmd() { command -v "$1" >/dev/null 2>&1; }

# ---------- 1. deteksi lingkungan ----------
log "CxL installer v$VERSION"
IS_TERMUX=0
if [ -n "${TERMUX_VERSION:-}" ] || [[ "${PREFIX:-}" == *com.termux* ]]; then
  IS_TERMUX=1
fi
ARCH="$(uname -m)"
KERNEL="$(uname -s)"
case "$ARCH" in
  aarch64)          GOARCH="arm64" ;;
  armv7l|armv8l)    GOARCH="arm" ;;
  x86_64)           GOARCH="amd64" ;;
  i686|i386)        GOARCH="386" ;;
  *)                GOARCH="" ;;
esac

if [ "$IS_TERMUX" -eq 1 ]; then
  ok "Lingkungan Termux terdeteksi (Android, arch=$ARCH)"
else
  if [ "${CXL_ALLOW_NON_TERMUX:-0}" = "1" ] || [ "${NONINTERACTIVE:-0}" = "1" ]; then
    warn "Bukan Termux (kernel=$KERNEL arch=$ARCH). Lanjut karena CXL_ALLOW_NON_TERMUX/NONINTERACTIVE=1."
  else
    err "Lingkungan ini bukan Termux. Installer ditujukan untuk Termux Android."
    err "Untuk menjalankan di lingkungan lain secara sadar: CXL_ALLOW_NON_TERMUX=1 bash install.sh"
    exit 1
  fi
fi

if [ -z "$GOARCH" ]; then
  err "Arsitektur '$ARCH' tidak dikenali; instalasi binary release dilewati (Go install masih mungkin)."
fi

# ---------- 2. paket dasar ----------
termux_install() {
  if [ "$IS_TERMUX" -eq 1 ] && require_cmd pkg; then
    pkg install -y "$@"
  fi
}

ensure_base() {
  log "Memeriksa paket dasar (nodejs-lts, git, curl, unzip)..."
  local missing=()
  require_cmd node  || missing+=("nodejs-lts")
  require_cmd git   || missing+=("git")
  require_cmd curl  || missing+=("curl")
  require_cmd unzip || missing+=("unzip")
  if [ "${#missing[@]}" -gt 0 ]; then
    log "Menginstal: ${missing[*]}"
    termux_install "${missing[@]}"
  fi
  if ! require_cmd node; then
    err "Node.js tidak tersedia. Instal manual: pkg install nodejs-lts"
    exit 1
  fi
  NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
  if [ "$NODE_MAJOR" -lt 20 ]; then
    err "Node.js >= 20 diperlukan (disarankan >= 22.5 untuk fallback node:sqlite). Terdeteksi: $(node -v)"
    exit 1
  fi
  ok "Node.js $(node -v) siap"
}

# ---------- 3. tools engine ----------
GH_LATEST() { curl -fsSL --max-time 30 "https://api.github.com/repos/$1/releases/latest" | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1; }

# cmd path go install per tool (jalur resmi)
GO_CMD_PATH_nuclei="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
GO_CMD_PATH_subfinder="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
GO_CMD_PATH_dnsx="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
GO_CMD_PATH_httpx="github.com/projectdiscovery/httpx/cmd/httpx@latest"
GO_CMD_PATH_katana="github.com/projectdiscovery/katana/cmd/katana@latest"

declare -a SUMMARY=()

verify_binary() { # verify_binary <path> <versionArgs...>
  local bin="$1"; shift
  ( "$bin" "$@" >/dev/null 2>&1 )
}

install_pd_tool() { # install_pd_tool <name> <repo>
  local name="$1" repo="$2"
  local binpath="$BIN_DIR/$name"
  if [ -x "$binpath" ] && verify_binary "$binpath" -version; then
    local v; v="$("$binpath" -version 2>/dev/null | head -n 1)"
    ok "$name sudah terpasang & berfungsi ($v) - lewati (idempotent)"
    SUMMARY+=("OK       $name  $v")
    return 0
  fi
  if [ -z "$GOARCH" ]; then
    warn "$name dilewati: arsitektur tidak didukung pengunduhan release"
    SUMMARY+=("SKIPPED  $name  arsitektur tidak dikenali")
    return 0
  fi
  log "Menginstal $name dari rilis resmi $repo ..."
  local tag; tag="$(GH_LATEST "$repo")"
  if [ -z "$tag" ]; then
    warn "$name: gagal membaca tag rilis terbaru (jaringan/API rate-limit?)"
    SUMMARY+=("FAILED   $name  tidak dapat membaca rilis")
    return 0
  fi
  local ver="${tag#v}"
  local asset="${name}_${ver}_linux_${GOARCH}.zip"
  local checksums="${name}_${ver}_checksums.txt"
  local tmp; tmp="$(mktemp -d)"
  local base="https://github.com/$repo/releases/download/$tag"
  if ! curl -fsSL --max-time 120 -o "$tmp/$asset" "$base/$asset"; then
    warn "$name: asset $asset tidak tersedia untuk linux_${GOARCH}"
    SUMMARY+=("FAILED   $name  asset linux_${GOARCH} tidak tersedia")
    rm -rf "$tmp"
    return 0
  fi
  if curl -fsSL --max-time 60 -o "$tmp/$checksums" "$base/$checksums"; then
    local expected
    expected="$(grep "  $asset$" "$tmp/$checksums" | awk '{print $1}' | head -n 1)"
    if [ -n "$expected" ]; then
      local actual; actual="$(sha256sum "$tmp/$asset" | awk '{print $1}')"
      if [ "$expected" != "$actual" ]; then
        err "$name: checksum TIDAK cocok - dibatalkan"
        SUMMARY+=("FAILED   $name  checksum mismatch")
        rm -rf "$tmp"
        return 0
      fi
      ok "$name: checksum resmi cocok"
    else
      warn "$name: checksum asset tidak ditemukan di $checksums - lanjut (sumber tetap resmi)"
    fi
  else
    warn "$name: checksums.txt tidak tersedia - lanjut (sumber tetap resmi)"
  fi
  mkdir -p "$BIN_DIR"
  if ! unzip -o -j -q "$tmp/$asset" -d "$tmp/x" 2>/dev/null; then
    mkdir -p "$tmp/x"; ( cd "$tmp/x" && unzip -o -q "$tmp/$asset" )
  fi
  local found; found="$(find "$tmp/x" -type f -name "$name" | head -n 1)"
  if [ -z "$found" ]; then
    err "$name: binary tidak ditemukan dalam arsip"
    SUMMARY+=("FAILED   $name  binary tidak ada di arsip")
    rm -rf "$tmp"
    return 0
  fi
  mv "$found" "$binpath"
  chmod +x "$binpath"
  rm -rf "$tmp"
  if verify_binary "$binpath" -version; then
    ok "$name terpasang: $("$binpath" -version 2>/dev/null | head -n 1)"
    SUMMARY+=("OK       $name  $("$binpath" -version 2>/dev/null | head -n 1)")
  else
    err "$name: binary terunduh TIDAK dapat dijalankan di arsitektur/OS ini (INCOMPATIBLE)"
    rm -f "$binpath"
    SUMMARY+=("INCOMPAT $name  binary tidak berjalan di perangkat ini")
  fi
}

fallback_go_install() { # untuk tool yang asset-nya gagal
  local name="$1"
  local cmdpath_var="GO_CMD_PATH_$name"
  local cmdpath="${!cmdpath_var:-}"
  if [ -z "$cmdpath" ]; then return 0; fi
  if ! require_cmd go; then
    warn "$name: fallback go install dilewati (go tidak terpasang; pkg install golang bila ingin memakainya)"
    return 0
  fi
  log "Fallback: go install $cmdpath (bisa lama di perangkat mobile)..."
  if GOBIN="$BIN_DIR" go install -v "$cmdpath"; then
    ok "$name terpasang via go"
    SUMMARY+=("OK       $name  (go install)")
  else
    err "$name: go install gagal"
    SUMMARY+=("FAILED   $name  go install")
  fi
}

install_xray() {
  local binpath="$BIN_DIR/xray"
  if [ -x "$binpath" ] && verify_binary "$binpath" version; then
    ok "xray sudah terpasang & berfungsi ($( "$binpath" version 2>/dev/null | head -n 1 ))"
    SUMMARY+=("OK       xray  $($binpath version 2>/dev/null | head -n 1)")
    return 0
  fi
  log "Mencoba xray (chaitin/xray) dari rilis resmi..."
  local tag; tag="$(GH_LATEST "chaitin/xray")"
  if [ -z "$tag" ]; then
    warn "xray: gagal membaca rilis"
    SUMMARY+=("FAILED   xray  tidak dapat membaca rilis")
    return 0
  fi
  local ver="${tag#v}"
  local asset="xray_linux_${GOARCH}.zip"
  local tmp; tmp="$(mktemp -d)"
  if ! curl -fsSL --max-time 300 -o "$tmp/$asset" "https://github.com/chaitin/xray/releases/download/$tag/$asset"; then
    warn "xray: asset $asset tidak tersedia"
    SUMMARY+=("SKIPPED  xray  asset tidak tersedia")
    rm -rf "$tmp"
    return 0
  fi
  mkdir -p "$BIN_DIR"
  ( cd "$tmp" && unzip -o -q "$asset" ) || true
  local found; found="$(find "$tmp" -type f -name xray | head -n 1)"
  if [ -n "$found" ]; then
    mv "$found" "$binpath"; chmod +x "$binpath"
    if verify_binary "$binpath" version; then
      ok "xray terpasang (ingat: butuh lisensi community chaitin untuk webscan)"
      SUMMARY+=("OK       xray  $($binpath version 2>/dev/null | head -n 1)")
    else
      err "xray: binary tidak dapat dijalankan di Termux (glibc vs bionic) - INCOMPATIBLE (harapkan)"
      rm -f "$binpath"
      SUMMARY+=("INCOMPAT xray  binary glibc tidak berjalan natif di Termux")
    fi
  else
    err "xray: binary tidak ditemukan dalam arsip"
    SUMMARY+=("FAILED   xray  arsip tidak berisi binary")
  fi
  rm -rf "$tmp"
}

install_tools() {
  log "Menginstal engine CLI (sumber: rilis resmi GitHub)..."
  mkdir -p "$BIN_DIR"
  local failed_tools=()
  for spec in "nuclei projectdiscovery/nuclei" "subfinder projectdiscovery/subfinder" "dnsx projectdiscovery/dnsx" "httpx projectdiscovery/httpx" "katana projectdiscovery/katana"; do
    set -- $spec
    local name="$1" repo="$2"
    install_pd_tool "$name" "$repo"
    if ! [ -x "$BIN_DIR/$name" ]; then
      fallback_go_install "$name"
    fi
    if ! [ -x "$BIN_DIR/$name" ]; then
      failed_tools+=("$name")
    fi
  done
  install_xray
  if [ "${#failed_tools[@]}" -gt 0 ]; then
    warn "Tool yang belum terpasang: ${failed_tools[*]}"
    warn "Status final tetap diperiksa oleh: npm run tools:check"
  fi
}

# ---------- 4. dependensi node ----------
install_node_deps() {
  if [ "$TOOLS_ONLY" -eq 1 ]; then return 0; fi
  log "Memasang dependensi Node.js (npm install)..."
  if ( cd "$PROJECT_DIR" && npm install --no-audit --no-fund ); then
    ok "Dependensi Node terpasang"
  else
    err "npm install gagal - periksa koneksi dan ruang penyimpanan"
    exit 1
  fi
  # Uji better-sqlite3 (opsional; fallback node:sqlite bila gagal)
  if ( cd "$PROJECT_DIR" && node -e "require('better-sqlite3')" ) 2>/dev/null; then
    ok "better-sqlite3 siap (driver utama)"
  else
    warn "better-sqlite3 tidak dapat dimuat - bot otomatis memakai driver node:sqlite bawaan (Node >= 22.5)."
    warn "Untuk kompilasi native: pkg install clang python make binutils && npm rebuild better-sqlite3"
  fi
}

# ---------- 5. env, folder, db ----------
setup_env() {
  if [ "$TOOLS_ONLY" -eq 1 ]; then return 0; fi
  cd "$PROJECT_DIR"
  if [ ! -f .env ]; then
    cp .env.example .env
    ok ".env dibuat dari .env.example - ISI BOT_TOKEN dan ALLOWED_TARGETS sebelum memakai bot"
  else
    ok ".env sudah ada - tidak diubah (data pengguna aman)"
  fi
  mkdir -p data reports bin
  log "Menjalankan migrasi database..."
  if node src/index.js --db-migrate; then
    ok "Database siap"
  else
    err "Migrasi database gagal"
    exit 1
  fi
}

run_tests() {
  if [ "$TOOLS_ONLY" -eq 1 ] || [ "$SKIP_TESTS" -eq 1 ]; then return 0; fi
  log "Menjalankan unit test (npm test)..."
  if ( cd "$PROJECT_DIR" && npm test ); then
    ok "Unit test lulus"
  else
    err "Unit test GAGAL - periksa output di atas"
    exit 1
  fi
  log "Menjalankan self-test (npm run check)..."
  ( cd "$PROJECT_DIR" && npm run check ) || warn "Self-test melaporkan item yang perlu diperhatikan (lihat output)"
}

summary() {
  echo
  printf "${C_B}========== RINGKASAN ==========${C_0}\n"
  if [ "${#SUMMARY[@]}" -eq 0 ]; then
    echo "(tidak ada tool yang diproses)"
  fi
  for s in "${SUMMARY[@]:-}"; do
    [ -n "$s" ] && printf "  %s\n" "$s"
  done
  echo
  if [ "$TOOLS_ONLY" -eq 0 ]; then
    echo "Langkah berikutnya:"
    echo "  1. Edit .env : isi BOT_TOKEN, ADMIN_IDS, ALLOWED_TARGETS"
    echo "  2. npm start  (atau: node src/index.js)"
    echo "  3. Di Telegram: /tools untuk verifikasi, /scan domain.com"
  fi
  printf "${C_B}===============================${C_0}\n"
}

main() {
  ensure_base
  if [ "$ASSUME_YES" -ne 1 ] && [ -t 0 ]; then
    printf "Lanjutkan instalasi? [y/N] "
    read -r ans
    case "$ans" in
      y|Y|yes|Yes) ;;
      *) err "Dibatalkan pengguna"; exit 1 ;;
    esac
  fi
  install_tools
  install_node_deps
  setup_env
  run_tests
  summary
}

main "$@"
