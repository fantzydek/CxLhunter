'use strict';

const fs = require('fs');
const path = require('path');
const { maskSecrets } = require('./validation');

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };

function createLogger(opts) {
  const options = opts || {};
  const level = LEVELS[options.logLevel] || LEVELS.info;
  const component = options.component || 'cxl';

  let stream = null;
  if (options.logsDir) {
    try {
      fs.mkdirSync(options.logsDir, { recursive: true });
      const file = path.join(options.logsDir, `cxl-${new Date().toISOString().slice(0, 10)}.log`);
      stream = fs.createWriteStream(file, { flags: 'a' });
      stream.on('error', () => {
        stream = null;
      });
    } catch (_) {
      stream = null;
    }
  }

  function fmtArg(a) {
    if (a instanceof Error) return maskSecrets(a.stack || `${a.name}: ${a.message}`);
    if (typeof a === 'string') return maskSecrets(a);
    try {
      return maskSecrets(JSON.stringify(a));
    } catch (_) {
      return maskSecrets(String(a));
    }
  }

  function write(lvlName, args) {
    if (LEVELS[lvlName] < level) return;
    const ts = new Date().toISOString();
    const msg = args.map(fmtArg).join(' ');
    const line = `${ts} [${lvlName.toUpperCase()}] [${component}] ${msg}\n`;
    try {
      process.stderr.write(line);
    } catch (_) {
      /* diamkan */
    }
    if (stream) {
      try {
        stream.write(line);
      } catch (_) {
        /* diamkan */
      }
    }
  }

  const logger = {
    level: options.logLevel || 'info',
    debug: (...a) => write('debug', a),
    info: (...a) => write('info', a),
    warn: (...a) => write('warn', a),
    error: (...a) => write('error', a),
    child(sub) {
      return createLogger({
        logLevel: options.logLevel,
        logsDir: null, // satu stream saja, anak hanya menulis via stderr + stream induk
        component: `${component}:${sub}`,
      });
    },
    close() {
      if (stream) {
        try {
          stream.end();
        } catch (_) {
          /* diamkan */
        }
        stream = null;
      }
    },
  };
  return logger;
}

module.exports = { createLogger };
