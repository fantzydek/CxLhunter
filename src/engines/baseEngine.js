'use strict';

/**
 * BaseEngine: pemeriksaan dependensi, verifikasi flag terhadap --help versi terinstal
 * (agar tidak pernah mengarang CLI flag yang tidak didukung), eksekusi JSONL dengan
 * timeout/abort, dan parsing defensif.
 */

const fs = require('fs');
const path = require('path');
const { runProcess, spawnErrorMessage, stderrHead } = require('../utils/processRunner');
const { sanitizeText } = require('../utils/validation');

class EngineError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'EngineError';
    this.code = code || 'ENGINE_ERROR';
  }
}

function flagSupported(helpText, flag, aliases) {
  if (!helpText) return null;
  const candidates = [flag, ...(aliases || [])];
  for (const f of candidates) {
    const esc = f.replace(/[-]/g, '\\-');
    // flag harus muncul sebagai token utuh (tidak termasuk dalam nama flag lain, mis. -json di -jsonl)
    const re = new RegExp(`${esc}(?![A-Za-z0-9_-])`, 'm');
    if (re.test(helpText)) return f;
  }
  return null;
}

class Engine {
  /**
   * name: id internal (subfinder/dnsx/httpx/katana/nuclei/xray)
   * opts: { binary, versionArgs, installHint, homepage, identityCheck(fn(out,run)=>bool), helpArgs }
   */
  constructor(name, opts, config, logger) {
    this.name = name;
    this.binary = opts.binary;
    this.versionArgs = opts.versionArgs || ['-version'];
    this.helpArgs = opts.helpArgs || ['--help', '-h'];
    this.installHint = opts.installHint || '';
    this.homepage = opts.homepage || '';
    this.identityCheck = opts.identityCheck || null;
    this.config = config;
    this.logger = logger && logger.child ? logger.child(name) : logger || { debug() {}, info() {}, warn() {}, error() {} };
    this._installCache = null;
    this._helpCache = null;
  }

  /** Cari path executable: override .env -> ./bin -> PATH (tanpa shell). */
  resolveBinaryPath() {
    const override = this.config.enginePaths && this.config.enginePaths[this.name];
    if (override) {
      try {
        fs.accessSync(override, fs.constants.X_OK);
        return override;
      } catch (_) {
        this.logger.warn(`Override path ${this.name} tidak dapat dieksekusi: ${override}`);
      }
    }
    const dirs = [this.config.binDir, ...(process.env.PATH || '').split(path.delimiter)].filter(Boolean);
    for (const dir of dirs) {
      const p = path.join(dir, this.binary);
      try {
        fs.accessSync(p, fs.constants.X_OK);
        return p;
      } catch (_) {
        /* lanjut */
      }
    }
    return null;
  }

  /** Hasil: { status: AVAILABLE|UNAVAILABLE|INCOMPATIBLE, version, binaryPath, reason, error } */
  async checkInstalled(force) {
    if (this._installCache && !force && Date.now() - this._installCache.at < 60000) {
      return this._installCache.value;
    }
    const value = await this._probe();
    this._installCache = { at: Date.now(), value };
    return value;
  }

  async _probe() {
    const bin = this.resolveBinaryPath();
    if (!bin) {
      return {
        status: 'UNAVAILABLE',
        reason: 'NOT_INSTALLED',
        error: `Executable '${this.binary}' tidak ditemukan di PATH atau ./bin`,
        installHint: this.installHint,
        homepage: this.homepage,
        binaryPath: null,
        version: null,
      };
    }
    const r = await runProcess({ cmd: bin, args: this.versionArgs, timeoutMs: 20000 });
    if (r.spawnError) {
      const msg = spawnErrorMessage(r.spawnError);
      const incompatible = r.spawnError.code === 'ENOEXEC' || r.spawnError.code === 'EACCES';
      return {
        status: incompatible ? 'INCOMPATIBLE' : 'UNAVAILABLE',
        reason: incompatible ? 'EXEC_FORMAT' : 'SPAWN_ERROR',
        error: msg,
        installHint: this.installHint,
        homepage: this.homepage,
        binaryPath: bin,
        version: null,
      };
    }
    const out = (r.stdout && r.stdout.trim()) || (r.stderr && r.stderr.trim()) || '';
    const firstLine = out.split('\n')[0] || '';
    if (r.timedOut) {
      return {
        status: 'INCOMPATIBLE',
        reason: 'VERSION_TIMEOUT',
        error: 'Pemeriksaan versi timeout - binary mungkin tidak kompatibel dengan arsitektur ini',
        installHint: this.installHint,
        homepage: this.homepage,
        binaryPath: bin,
        version: null,
      };
    }
    if (r.code !== 0) {
      // Python tools (mis. httpx pip) mencetak usage/traceback => bukan engine yang benar
      const wrongBinary = /usage:|traceback|python|pip/i.test(out);
      return {
        status: 'INCOMPATIBLE',
        reason: wrongBinary ? 'WRONG_BINARY' : 'VERSION_CHECK_FAILED',
        error: `Exit code ${r.code}: ${sanitizeText(firstLine, 200)}`,
        installHint: this.installHint,
        homepage: this.homepage,
        binaryPath: bin,
        version: null,
      };
    }
    if (this.identityCheck && !this.identityCheck(out, r)) {
      return {
        status: 'INCOMPATIBLE',
        reason: 'WRONG_BINARY',
        error: 'Output versi tidak cocok dengan engine resmi yang diharapkan',
        installHint: this.installHint,
        homepage: this.homepage,
        binaryPath: bin,
        version: sanitizeText(firstLine, 120),
      };
    }
    return {
      status: 'AVAILABLE',
      reason: 'OK',
      error: null,
      installHint: null,
      homepage: this.homepage,
      binaryPath: bin,
      version: sanitizeText(firstLine, 120),
    };
  }

  /** Ambil --help / -h (cache 10 menit) untuk verifikasi dukungan flag. */
  async getHelpText(force) {
    if (this._helpCache && !force && Date.now() - this._helpCache.at < 600000) {
      return this._helpCache.value;
    }
    const bin = this.resolveBinaryPath();
    if (!bin) return null;
    let text = '';
    for (const arg of this.helpArgs) {
      const r = await runProcess({ cmd: bin, args: [arg], timeoutMs: 20000 });
      text = (r.stdout || '') + (r.stderr || '');
      if (text.trim().length > 40) break;
    }
    const value = text || null;
    this._helpCache = { at: Date.now(), value };
    return value;
  }

  /**
   * Susun argumen hanya dari flag yang terverifikasi ada di --help.
   * wants: [{ flag, aliases[], value|null, required, when }]
   * Hasil: { used: string[], dropped: string[] } ; melempar EngineError bila flag wajib tidak didukung.
   */
  async resolveFlags(wants) {
    const help = await this.getHelpText();
    if (!help) {
      // Tidak bisa verifikasi => hanya flag wajib minimum yang dianggap aman? TIDAK.
      // Kebijakan: gagal-aman, jangan jalankan engine tanpa verifikasi.
      throw new EngineError(
        `Tidak dapat memverifikasi dukungan flag ${this.binary} (help tidak tersedia). Engine dilewati demi keamanan.`,
        'HELP_UNAVAILABLE'
      );
    }
    const used = [];
    const dropped = [];
    for (const w of wants) {
      if (w.when === false) continue;
      const resolved = flagSupported(help, w.flag, w.aliases);
      if (!resolved) {
        if (w.required) {
          throw new EngineError(
            `Flag wajib ${w.flag} tidak didukung oleh versi ${this.binary} yang terinstal.`,
            'FLAG_UNSUPPORTED'
          );
        }
        dropped.push(w.flag);
        continue;
      }
      used.push(resolved);
      if (w.value !== null && w.value !== undefined) used.push(String(w.value));
    }
    return { used, dropped };
  }

  /**
   * Jalankan tool dengan output JSONL / baris, streaming ke parser.
   * onLine dipanggil per baris; hasil agregasi disiapkan oleh caller.
   */
  async runLines({ args, jobCtx, timeoutMs, onLine }) {
    const bin = this.resolveBinaryPath();
    if (!bin) throw new EngineError('Executable tidak ditemukan', 'NOT_INSTALLED');
    const r = await runProcess({
      cmd: bin,
      args,
      cwd: jobCtx.workDir,
      timeoutMs: timeoutMs || 120000,
      maxOutputBytes: this.config.maxOutputBytes,
      signal: jobCtx.signal,
      onLine,
    });
    return r;
  }
}

module.exports = { Engine, EngineError, flagSupported };
