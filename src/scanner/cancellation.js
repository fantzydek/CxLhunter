'use strict';

/**
 * Registry pembatalan: jobId -> AbortController.
 * Menjamin proses scanner TIDAK tertinggal (yatim): abort memicu kill process tree
 * di processRunner, dan semua controller di-abort saat shutdown.
 */

class CancellationRegistry {
  constructor() {
    this._map = new Map();
  }

  create(jobId) {
    if (this._map.has(jobId)) return this._map.get(jobId);
    const ac = new AbortController();
    this._map.set(jobId, ac);
    return ac;
  }

  get(jobId) {
    return this._map.get(jobId) || null;
  }

  signal(jobId) {
    const ac = this._map.get(jobId);
    return ac ? ac.signal : null;
  }

  abort(jobId, reason) {
    const ac = this._map.get(jobId);
    if (ac && !ac.signal.aborted) {
      ac.abort(reason || 'dibatalkan');
      return true;
    }
    return false;
  }

  abortAll(reason) {
    let n = 0;
    for (const [id, ac] of this._map.entries()) {
      if (!ac.signal.aborted) {
        ac.abort(reason || 'shutdown');
        n++;
      }
    }
    return n;
  }

  remove(jobId) {
    this._map.delete(jobId);
  }

  activeJobIds() {
    return Array.from(this._map.keys());
  }
}

module.exports = { CancellationRegistry };
