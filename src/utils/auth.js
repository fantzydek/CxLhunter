'use strict';

/**
 * Otorisasi berbasis Telegram user ID.
 * - admin ditentukan oleh config.adminIds
 * - bila config.allowedUsers tidak kosong, hanya anggota daftar itu (plus admin) yang boleh
 * - input non-angka (null/undefined/objek) DITOLAK secara aman (tidak pernah dikonversi ke 0)
 */

function toUserId(userId) {
  if (typeof userId === 'number' && Number.isFinite(userId) && userId > 0) return userId;
  if (typeof userId === 'string' && /^\d{1,15}$/.test(userId.trim())) {
    const n = parseInt(userId.trim(), 10);
    return n > 0 ? n : null;
  }
  return null;
}

function isAdminId(config, userId) {
  const id = toUserId(userId);
  if (id === null) return false;
  return (config.adminIds || []).includes(id);
}

function isUserAllowed(config, userId) {
  const id = toUserId(userId);
  if (id === null) return false;
  if (isAdminId(config, id)) return true;
  const allow = config.allowedUsers || [];
  if (!allow.length) return true; // tidak dibatasi
  return allow.includes(id);
}

function resolveRole(config, userId) {
  return isAdminId(config, userId) ? 'admin' : 'user';
}

module.exports = { isAdminId, isUserAllowed, resolveRole };
