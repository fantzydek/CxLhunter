'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const { isAdminId, isUserAllowed, resolveRole } = require('../src/utils/auth');

const cfg = {
  adminIds: [111],
  allowedUsers: [],
};

const cfgRestricted = {
  adminIds: [111],
  allowedUsers: [222, 333],
};

test('auth: admin terdeteksi', () => {
  assert.ok(isAdminId(cfg, 111));
  assert.ok(!isAdminId(cfg, 222));
  assert.ok(!isAdminId(cfg, 'abc'));
  assert.strictEqual(resolveRole(cfg, 111), 'admin');
  assert.strictEqual(resolveRole(cfg, 999), 'user');
});

test('auth: allowedUsers kosong => semua user diizinkan (admin tetap terpisah)', () => {
  assert.ok(isUserAllowed(cfg, 999));
  assert.ok(isUserAllowed(cfg, 111));
});

test('auth: allowedUsers terisi => hanya anggota + admin', () => {
  assert.ok(isUserAllowed(cfgRestricted, 222));
  assert.ok(isUserAllowed(cfgRestricted, 111));
  assert.ok(!isUserAllowed(cfgRestricted, 999), 'user tak terdaftar ditolak');
});

test('auth: input tidak valid ditolak aman', () => {
  assert.ok(!isUserAllowed(cfg, null));
  assert.ok(!isUserAllowed(cfg, undefined));
  assert.ok(!isAdminId(cfg, {}));
});
