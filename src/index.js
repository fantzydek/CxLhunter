'use strict';

/**
 * Entry point CxL Bug Bounty Scanner.
 * Mode:
 *   node src/index.js                 -> jalankan bot Telegram
 *   node src/index.js --self-test     -> pemeriksaan mandiri (tidak memindai target publik)
 *   node src/index.js --tools-check   -> verifikasi executable + versi engine
 *   node src/index.js --db-migrate    -> jalankan migrasi database
 *   node src/index.js --version       -> versi aplikasi
 */

const { loadConfig } = require('./config');
const { createLogger } = require('./utils/logger');
const { openDatabase, createStore } = require('./database/db');
const { runMigrations } = require('./database/migrations');

const VERSION = '1.4.0';

function openStore(config, logger) {
  const db = openDatabase(config, logger);
  const applied = runMigrations(db, logger);
  const store = createStore(db, logger);
  return { db, store, applied };
}

async function main() {
  const args = process.argv.slice(2);

  if (args.includes('--version')) {
    process.stdout.write(`CxL Bug Bounty Scanner v${VERSION}\n`);
    process.exit(0);
  }

  const config = loadConfig();
  const logger = createLogger({ logLevel: config.logLevel, logsDir: config.logsDir });

  if (args.includes('--db-migrate')) {
    const { db } = openStore(config, logger);
    process.stdout.write(`Migrasi selesai. Driver: ${db.driver}\n`);
    db.close();
    process.exit(0);
  }

  if (args.includes('--tools-check')) {
    const { createEngines } = require('./engines');
    const engines = createEngines(config, logger);
    process.stdout.write('Status engine (pemeriksaan live):\n');
    for (const eng of engines.list) {
      // eslint-disable-next-line no-await-in-loop
      const chk = await eng.checkInstalled(true);
      process.stdout.write(
        `- ${eng.name.padEnd(12)} ${chk.status.padEnd(13)} ${chk.version || chk.error || ''}\n`
      );
      if (chk.homepage) process.stdout.write(`   sumber: ${chk.homepage}\n`);
    }
    process.exit(0);
  }

  if (args.includes('--self-test')) {
    const { runSelfTest } = require('./selfTest');
    const code = await runSelfTest({ config, logger, openStore });
    process.exit(code);
  }

  // ===== Mode bot =====
  logger.info(`CxL Bug Bounty Scanner v${VERSION} mulai`);

  if (!config.botToken) {
    logger.error('BOT_TOKEN belum diisi. Salin .env.example ke .env, isi token dari @BotFather, lalu jalankan ulang.');
    process.exit(1);
  }
  if (!config.allowedTargets.length) {
    logger.warn('ALLOWED_TARGETS kosong: MODE TERBUKA aktif - scanner menerima domain publik apa pun.');
    logger.warn('Untuk mengunci scanner hanya ke domain Anda, isi ALLOWED_TARGETS di .env lalu restart.');
  }
  if (!config.adminIds.length) {
    logger.warn('ADMIN_IDS kosong: tidak ada admin; /installtools tidak dapat dipakai.');
  }

  const { db, store } = openStore(config, logger);
  const stale = store.markStaleRunningAsFailed('Dihentikan: proses bot restart');
  if (stale > 0) logger.warn(`${stale} scan bermasalah dari sesi sebelumnya ditandai FAILED (recovery restart).`);

  const { ScopeValidator } = require('./scope/validator');
  const { NetworkGuard } = require('./scope/networkGuard');
  const { createEngines } = require('./engines');
  const { CancellationRegistry } = require('./scanner/cancellation');
  const { Orchestrator } = require('./scanner/orchestrator');
  const { ScanQueue } = require('./scanner/queue');
  const { Worker } = require('./scanner/worker');
  const { createBot } = require('./bot');

  const validator = new ScopeValidator(config);
  const guard = new NetworkGuard({ config, store, logger });
  const engines = createEngines(config, logger);
  const registry = new CancellationRegistry();
  const orchestrator = new Orchestrator({ config, store, guard, validator, engines, logger, registry });
  const queue = new ScanQueue({ config, store, logger, orchestrator, registry });
  const worker = new Worker({ config, logger, queue, orchestrator });

  const bot = createBot({ config, store, queue, guard, validator, engines, logger, registry, worker });

  const shutdown = async (sig) => {
    logger.info(`Menerima ${sig}; menghentikan dengan aman...`);
    try {
      worker.stopAll();
      registry.abortAll('shutdown');
      // beri waktu proses child mati
      await new Promise((r) => setTimeout(r, 1500));
      bot.stop(sig).catch(() => {});
    } catch (_) {
      /* diamkan */
    }
    setTimeout(() => {
      try {
        db.close();
      } catch (_) {
        /* diamkan */
      }
      process.exit(0);
    }, 2500);
  };
  process.once('SIGINT', () => shutdown('SIGINT'));
  process.once('SIGTERM', () => shutdown('SIGTERM'));

  try {
    await bot.launch();
    logger.info('Bot berhenti.');
    db.close();
    process.exit(0);
  } catch (err) {
    if (/401|Unauthorized/i.test(String(err && err.message))) {
      logger.error('BOT_TOKEN ditolak Telegram (401 Unauthorized). Periksa token di .env.');
    } else if (/409/i.test(String(err && err.message))) {
      logger.error('Konflik 409: bot lain masih berjalan dengan token yang sama. Hentikan instance lain.');
    } else {
      logger.error('Bot berhenti karena error:', err);
    }
    registry.abortAll('shutdown');
    db.close();
    process.exit(1);
  }
}

main().catch((err) => {
  process.stderr.write(`Error fatal: ${err.stack || err.message}\n`);
  process.exit(1);
});
