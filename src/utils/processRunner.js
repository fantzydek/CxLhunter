'use strict';

/**
 * processRunner - menjalankan proses CLI engine dengan aman:
 * - spawn dengan executable + array argumen (TANPA shell)
 * - timeout + pembatalan (AbortSignal) dengan kill process group
 * - batas ukuran stdout/stderr (head disimpan, overflow ditandai truncated)
 * - streaming baris stdout ke callback (untuk parsing JSONL tanpa menumpuk memori)
 * - TIDAK pernah reject; selalu resolve dengan objek hasil terstruktur
 */

const { spawn } = require('child_process');
const KILL_GRACE_MS = 5000;

function killTree(child) {
  if (!child || child.pid == null) return;
  if (child.exitCode !== null || child.signalCode !== null) return;
  try {
    if (process.platform === 'win32') {
      child.kill('SIGKILL');
      return;
    }
    // child di-spawn detached => leader group sendiri; hentikan satu group
    try {
      process.kill(-child.pid, 'SIGTERM');
    } catch (_) {
      try {
        child.kill('SIGTERM');
      } catch (_e) {
        /* sudah mati */
      }
    }
  } catch (_) {
    /* diamkan */
  }
}

function killTreeHard(child) {
  if (!child || child.pid == null) return;
  if (child.exitCode !== null || child.signalCode !== null) return;
  try {
    if (process.platform === 'win32') {
      child.kill('SIGKILL');
      return;
    }
    try {
      process.kill(-child.pid, 'SIGKILL');
    } catch (_) {
      try {
        child.kill('SIGKILL');
      } catch (_e) {
        /* sudah mati */
      }
    }
  } catch (_) {
    /* diamkan */
  }
}

function makeSink(capBytes) {
  return {
    cap: capBytes,
    text: '',
    bytes: 0,
    truncated: false,
    push(chunkStr) {
      const size = Buffer.byteLength(chunkStr, 'utf8');
      this.bytes += size;
      const remain = this.cap - this.text.length;
      if (remain > 0) {
        this.text += chunkStr.length > remain ? chunkStr.slice(0, remain) : chunkStr;
      }
      if (this.text.length >= this.cap && size > 0) this.truncated = true;
    },
  };
}

function attachLineStream(stream, sink, emitLine) {
  let remainder = '';
  stream.setEncoding('utf8');
  stream.on('data', (chunk) => {
    sink.push(chunk);
    remainder += chunk;
    let idx;
    while ((idx = remainder.indexOf('\n')) >= 0) {
      let line = remainder.slice(0, idx);
      remainder = remainder.slice(idx + 1);
      if (line.endsWith('\r')) line = line.slice(0, -1);
      if (emitLine) {
        try {
          emitLine(line);
        } catch (_) {
          // callback parse tidak boleh menjatuhkan runner
        }
      }
    }
    if (remainder.length > 1024 * 1024) remainder = remainder.slice(-1024 * 1024);
  });
  return function flush() {
    const rest = remainder;
    remainder = '';
    if (rest && emitLine) {
      try {
        emitLine(rest);
      } catch (_) {
        /* diamkan */
      }
    }
  };
}

/**
 * Jalankan proses. Opsi:
 *  cmd, args[], cwd, env, timeoutMs, maxOutputBytes, signal (AbortSignal),
 *  onLine(line), stdinData (string)
 * Hasil (SELALU resolve):
 *  { spawnError, code, signalName, timedOut, aborted, stdout, stderr,
 *    stdoutBytes, stderrBytes, truncated, ok }
 */
function runProcess(opts) {
  const o = opts || {};
  const maxOutputBytes = o.maxOutputBytes || 32 * 1024 * 1024;
  const timeoutMs = o.timeoutMs || 120000;

  return new Promise((resolve) => {
    const stdoutSink = makeSink(maxOutputBytes);
    const stderrSink = makeSink(Math.min(maxOutputBytes, 4 * 1024 * 1024));
    let timedOut = false;
    let aborted = false;
    let settled = false;
    let timeoutTimer = null;
    let graceTimer = null;

    const finish = (child, spawnError, code, signalName) => {
      if (settled) return;
      settled = true;
      if (timeoutTimer) clearTimeout(timeoutTimer);
      if (graceTimer) clearTimeout(graceTimer);
      if (o.signal) {
        try {
          o.signal.removeEventListener('abort', onAbort);
        } catch (_) {
          /* diamkan */
        }
      }
      const r = {
        spawnError: spawnError || null,
        code: code === undefined ? null : code,
        signalName: signalName || null,
        timedOut,
        aborted,
        stdout: stdoutSink.text,
        stderr: stderrSink.text,
        stdoutBytes: stdoutSink.bytes,
        stderrBytes: stderrSink.bytes,
        truncated: stdoutSink.truncated || stderrSink.truncated,
        get ok() {
          return !spawnError && !timedOut && !aborted && code === 0;
        },
      };
      resolve(r);
    };

    const onAbort = () => {
      if (settled) return;
      aborted = true;
    };

    let child;
    try {
      child = spawn(o.cmd, o.args || [], {
        cwd: o.cwd,
        env: o.env || process.env,
        stdio: o.stdinData != null ? ['pipe', 'pipe', 'pipe'] : ['ignore', 'pipe', 'pipe'],
        detached: process.platform !== 'win32',
      });
    } catch (err) {
      finish(null, { code: err.code || 'SPAWN_ERROR', message: err.message }, null, null);
      return;
    }

    if (o.signal) {
      if (o.signal.aborted) onAbort();
      else {
        try {
          o.signal.addEventListener('abort', onAbort, { once: true });
        } catch (_) {
          /* diamkan */
        }
      }
    }

    const flushOut = attachLineStream(child.stdout, stdoutSink, o.onLine);
    attachLineStream(child.stderr, stderrSink, null);

    if (o.stdinData != null) {
      try {
        child.stdin.write(o.stdinData);
      } catch (_) {
        /* diamkan */
      }
      child.stdin.end();
    }

    timeoutTimer = setTimeout(() => {
      if (settled) return;
      timedOut = true;
      killTree(child);
      graceTimer = setTimeout(() => killTreeHard(child), KILL_GRACE_MS);
    }, timeoutMs);

    // Pemantau abort: kill sesegera mungkin saat sinyal dibatalkan
    const abortWatch = setInterval(() => {
      if (aborted && !settled) {
        killTree(child);
        clearInterval(abortWatch);
        graceTimer = setTimeout(() => killTreeHard(child), KILL_GRACE_MS);
      }
      if (settled) clearInterval(abortWatch);
    }, 250);
    if (abortWatch.unref) abortWatch.unref();

    child.on('error', (err) => {
      clearInterval(abortWatch);
      finish(child, { code: err.code || 'SPAWN_ERROR', message: err.message }, null, null);
    });

    child.on('close', (code, signalName) => {
      clearInterval(abortWatch);
      flushOut();
      finish(child, null, code, signalName);
    });
  });
}

/** Klasifikasikan hasil run menjadi status ringkas. */
function outcomeOf(r) {
  if (!r) return 'FAILED';
  if (r.aborted) return 'CANCELLED';
  if (r.timedOut) return 'TIMEOUT';
  if (r.spawnError) return 'SPAWN_ERROR';
  if (r.code === 0) return 'COMPLETED';
  return 'FAILED';
}

/** Deskripsi ramah-manusia untuk spawn error. */
function spawnErrorMessage(spawnError) {
  if (!spawnError) return null;
  if (spawnError.code === 'ENOENT') return 'Executable tidak ditemukan (belum terinstal / tidak ada di PATH)';
  if (spawnError.code === 'EACCES') return 'Executable tidak dapat dieksekusi (masalah permission)';
  if (spawnError.code === 'ENOEXEC') return 'Format executable tidak didukung arsitektur ini (INCOMPATIBLE)';
  return spawnError.message || String(spawnError.code || 'SPAWN_ERROR');
}

/** Ambil beberapa baris pertama stderr (sudah disanitasi) untuk disimpan sebagai bukti error. */
function stderrHead(r, maxLen) {
  if (!r || !r.stderr) return '';
  const lines = r.stderr.split('\n').filter(Boolean).slice(0, 12).join(' | ');
  return lines.slice(0, maxLen || 1500);
}

module.exports = { runProcess, outcomeOf, spawnErrorMessage, stderrHead, killTree };
