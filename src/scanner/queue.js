'use strict';

/**
 * ScanQueue: FIFO dengan batas ukuran antrean + batas scan per pengguna.
 * Worker (worker.js) mengonsumsi antrean ini secara berurutan sesuai MAX_CONCURRENT_SCANS.
 */

class ScanQueue {
  constructor({ config, store, logger, orchestrator, registry }) {
    this.config = config;
    this.store = store;
    this.logger = logger;
    this.orchestrator = orchestrator;
    this.registry = registry;
    this.items = []; // { job }
    this.running = new Map(); // jobId -> job
  }

  get queuedCount() {
    return this.items.length;
  }

  get runningCount() {
    return this.running.size;
  }

  /** Hasil: {ok, reason} - memvalidasi batas antrean & per pengguna. */
  canEnqueue(ownerId) {
    if (this.items.length >= this.config.queueMax) {
      return { ok: false, reason: `Antrean penuh (${this.config.queueMax}). Coba lagi nanti.` };
    }
    const mine =
      this.items.filter((i) => i.job.ownerId === ownerId).length +
      Array.from(this.running.values()).filter((j) => j.ownerId === ownerId).length;
    if (mine >= this.config.maxScansPerUser) {
      return {
        ok: false,
        reason: `Anda sudah memiliki ${mine} scan aktif/antre (batas ${this.config.maxScansPerUser}). Gunakan /status atau /stop.`,
      };
    }
    return { ok: true };
  }

  /**
   * Tambahkan job. job: { jobId, ownerId, ownerUsername, mode, target, scopeRoot, options, onProgress }
   * Membuat baris scan QUEUED + AbortController.
   */
  enqueue(job) {
    const ac = this.registry.create(job.jobId);
    job.signal = ac.signal;
    job.scanId = this.store.createScan({
      jobId: job.jobId,
      ownerId: job.ownerId,
      ownerUsername: job.ownerUsername,
      mode: job.mode,
      target: job.target,
      scopeRoot: job.scopeRoot,
      options: job.options,
      labMode: this.config.labMode,
    });
    this.items.push({ job });
    this.logger.info(`[${job.jobId}] masuk antrean (${job.mode} ${job.target})`);
    return job.scanId;
  }

  /** Ambil job berikutnya untuk dikerjakan. */
  takeNext() {
    const item = this.items.shift();
    if (!item) return null;
    this.running.set(item.job.jobId, item.job);
    return item.job;
  }

  markFinished(jobId) {
    this.running.delete(jobId);
  }

  /** Batalkan job milik userId (admin boleh semua). Hasil: {ok, reason} */
  cancel(jobId, userId, isAdmin) {
    const runningJob = this.running.get(jobId);
    if (runningJob) {
      if (!isAdmin && runningJob.ownerId !== userId) {
        return { ok: false, reason: 'Anda hanya dapat membatalkan scan milik Anda sendiri.' };
      }
      this.registry.abort(jobId, 'dibatalkan pengguna');
      return { ok: true, reason: 'Pembatalan dikirim; proses sedang dihentikan.' };
    }
    const idx = this.items.findIndex((i) => i.job.jobId === jobId);
    if (idx >= 0) {
      const item = this.items[idx];
      if (!isAdmin && item.job.ownerId !== userId) {
        return { ok: false, reason: 'Anda hanya dapat membatalkan scan milik Anda sendiri.' };
      }
      this.items.splice(idx, 1);
      this.store.updateScan(item.job.scanId, { status: 'CANCELLED', finished_at: Date.now(), error: 'Dibatalkan saat antre' });
      this.registry.remove(jobId);
      return { ok: true, reason: 'Job dalam antrean dibatalkan.' };
    }
    return { ok: false, reason: 'Job tidak ditemukan atau sudah selesai.' };
  }

  listRunning() {
    return Array.from(this.running.values());
  }

  listQueued() {
    return this.items.map((i) => i.job);
  }
}

module.exports = { ScanQueue };
