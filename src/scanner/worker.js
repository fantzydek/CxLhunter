'use strict';

/**
 * Worker loop: mengambil job dari ScanQueue dan menjalankannya lewat Orchestrator
 * sesuai MAX_CONCURRENT_SCANS. Tidak ada perulangan berjalan tanpa penghentian:
 * loop dijalankan lazy (setelah enqueue / setelah job selesai) dan berhenti saat kosong.
 */

class Worker {
  constructor({ config, logger, queue, orchestrator }) {
    this.config = config;
    this.logger = logger;
    this.queue = queue;
    this.orchestrator = orchestrator;
    this.stopped = false;
    this._kicking = false;
  }

  kick() {
    if (this.stopped || this._kicking) return;
    this._kicking = true;
    setImmediate(() => this._loop());
  }

  async _loop() {
    try {
      while (!this.stopped) {
        if (this.queue.runningCount >= this.config.maxConcurrentScans) break;
        const job = this.queue.takeNext();
        if (!job) break;
        // jalankan tanpa menunggu satu sama lain bila concurrency > 1
        this._runJob(job);
      }
    } finally {
      this._kicking = false;
    }
    // bila masih ada kapasitas & antrean (mis. job selesai cepat) dorong lagi
    if (!this.stopped && this.queue.queuedCount > 0 && this.queue.runningCount < this.config.maxConcurrentScans) {
      setImmediate(() => this.kick());
    }
  }

  async _runJob(job) {
    const started = Date.now();
    try {
      const res = await this.orchestrator.executeJob(job);
      this.logger.info(`[${job.jobId}] selesai: ${res.status} dalam ${Math.round((Date.now() - started) / 1000)}s`);
    } catch (err) {
      this.logger.error(`[${job.jobId}] error worker:`, err);
      try {
        this.storeSafeFail(job, err);
      } catch (_) {
        /* diamkan */
      }
    } finally {
      this.queue.markFinished(job.jobId);
      setImmediate(() => this.kick());
    }
  }

  storeSafeFail(job, err) {
    // dipanggil hanya bila orchestrator sendiri melempar (harusnya tidak)
    this.queue.store.updateScan(job.scanId, {
      status: 'FAILED',
      finished_at: Date.now(),
      error: String(err.message || 'worker error').slice(0, 300),
    });
  }

  stopAll() {
    this.stopped = true;
  }
}

module.exports = { Worker };
