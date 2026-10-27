'use strict';

/**
 * Konstanta bersama Intelligent Vulnerability Report Generator.
 * Dipisah agar store dan generator tidak saling membutuhkan (menghindari siklus modul).
 */

/** Kosa kata status validasi yang sah (spesifikasi). */
const VALIDATION_STATUSES = ['DETECTED', 'NEEDS_MANUAL_VERIFICATION', 'CONFIRMED', 'FALSE_POSITIVE', 'NOT_REPRODUCED'];

/** Status yang HANYA dapat diset oleh manusia, bukan oleh generator otomatis. */
const MANUAL_STATUSES = ['CONFIRMED', 'FALSE_POSITIVE', 'NOT_REPRODUCED'];

module.exports = { VALIDATION_STATUSES, MANUAL_STATUSES };
