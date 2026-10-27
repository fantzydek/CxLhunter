'use strict';

/**
 * Util format pesan Telegram (HTML parse mode) dan tampilan status.
 * Tanpa emoji: menggunakan penanda teks [OK] / [RUN] / [..] / [FAIL] / [SKIP].
 */

function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function splitMessage(text, limit) {
  const max = limit || 3800;
  const parts = [];
  let cur = '';
  for (const para of String(text || '').split('\n')) {
    if ((cur + para + '\n').length > max && cur) {
      parts.push(cur.replace(/\n+$/, ''));
      cur = '';
    }
    if (para.length > max) {
      // potong paragraf raksasa per karakter
      let rest = para;
      while (rest.length > max) {
        parts.push(rest.slice(0, max));
        rest = rest.slice(max);
      }
      cur = rest + '\n';
    } else {
      cur += para + '\n';
    }
  }
  if (cur.trim()) parts.push(cur.replace(/\n+$/, ''));
  return parts.length ? parts : [''];
}

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 };

function severityRank(s) {
  return SEVERITY_ORDER[String(s || 'unknown').toLowerCase()] != null
    ? SEVERITY_ORDER[String(s || 'unknown').toLowerCase()]
    : 5;
}

function severityBadge(s) {
  const v = String(s || 'unknown').toUpperCase();
  return `[${v}]`;
}

const STAGE_ICON = {
  pending: '[  ]',
  running: '[>>]',
  done: '[OK]',
  failed: '[FAIL]',
  skipped: '[SKIP]',
  cancelled: '[STOP]',
};

function stageIcon(status) {
  return STAGE_ICON[status] || '[  ]';
}

function fmtDuration(ms) {
  if (!Number.isFinite(ms) || ms < 0) return '-';
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rs = s % 60;
  if (m < 60) return `${m}m${rs}s`;
  const h = Math.floor(m / 60);
  return `${h}h${m % 60}m`;
}

function fmtDateTime(epochMs) {
  if (!epochMs) return '-';
  return new Date(epochMs).toISOString().replace('T', ' ').replace(/\..+$/, ' UTC');
}

const ENGINE_STATUS_LABEL = {
  AVAILABLE: 'TERPASANG',
  UNAVAILABLE: 'TIDAK TERPASANG',
  INCOMPATIBLE: 'TIDAK KOMPATIBEL',
};

function engineStatusLabel(s) {
  return ENGINE_STATUS_LABEL[s] || s || '-';
}

const SCAN_STATUS_LABEL = {
  QUEUED: 'DALAM ANTREAN',
  RUNNING: 'BERJALAN',
  COMPLETED: 'SELESAI',
  PARTIAL: 'SEBAGIAN (PARTIAL)',
  FAILED: 'GAGAL',
  CANCELLED: 'DIBATALKAN',
};

function scanStatusLabel(s) {
  return SCAN_STATUS_LABEL[s] || s || '-';
}

module.exports = {
  escapeHtml,
  splitMessage,
  severityRank,
  severityBadge,
  stageIcon,
  fmtDuration,
  fmtDateTime,
  engineStatusLabel,
  scanStatusLabel,
};
