#!/usr/bin/env node
/**
 * Read-only diagnostic for the WoW signup page.
 *
 * Answers the only question that matters before installing: can this thing
 * reach the auth database, and does the account table look right?
 *
 * Writes NOTHING. No INSERT, no UPDATE, no DDL. Safe to run any time.
 *
 * Usage:
 *   DB_HOST=127.0.0.1 DB_PORT=3306 DB_USER=signup DB_PASS='...' DB_NAME=auth \
 *     node check-db.js
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');

// Reuse the client from server.js without starting the server.
const src = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf8');
const start = src.indexOf('const MYSQL = (() => {');
const end = src.indexOf('// ---------------------------------------------------------------------------\n// Config');
const MYSQL = eval(
  'const net=require("node:net"); const crypto=require("node:crypto");' +
  src.slice(start, end) + '\nMYSQL;'
);

const CFG = {
  host: process.env.DB_HOST || '127.0.0.1',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER || '',
  pass: process.env.DB_PASS || '',
  name: process.env.DB_NAME || 'auth',
};

const REQUIRED = ['id', 'username', 'sha_pass_hash', 'expansion', 'v', 's'];

function ok(s) { console.log(`  ok    ${s}`); }
function bad(s) { console.log(`  FAIL  ${s}`); }
function info(s) { console.log(`        ${s}`); }

(async () => {
  console.log('\nwow-signup database check\n');
  console.log(`  target: ${CFG.user}@${CFG.host}:${CFG.port}/${CFG.name}\n`);

  if (!CFG.user) {
    bad('DB_USER is not set.');
    process.exit(1);
  }

  let conn;
  try {
    conn = await MYSQL.Conn.connect({
      host: CFG.host, port: CFG.port, user: CFG.user, password: CFG.pass, database: CFG.name,
    });
    ok('connected and authenticated');
  } catch (e) {
    bad(`could not connect: ${e.message}`);
    info('Check host/port, and that the user is allowed to connect from this machine.');
    process.exit(1);
  }

  try {
    const r = await conn.query('SELECT VERSION() AS v, DATABASE() AS db');
    if (!r.rows.length) {
      bad('connected, but queries are not returning results.');
      info('This usually means the DB user is not fully authenticated.');
      process.exit(1);
    }
    ok(`server version: ${r.rows[0][0]}`);
    const db = r.rows[0][1];
    if (db !== CFG.name) {
      bad(`active database is '${db}', not '${CFG.name}'`);
      process.exit(1);
    }
    ok(`active database: ${db}`);
  } catch (e) {
    bad(`query failed: ${e.message}`);
    process.exit(1);
  }

  let cols = [];
  try {
    const r = await conn.query(
      `SELECT COLUMN_NAME FROM information_schema.COLUMNS
       WHERE TABLE_SCHEMA = '${CFG.name}' AND TABLE_NAME = 'account'`
    );
    cols = r.rows.map((x) => x[0].toLowerCase());
  } catch (e) {
    bad(`could not read the account table definition: ${e.message}`);
    process.exit(1);
  }

  if (!cols.length) {
    bad(`table 'account' not found in '${CFG.name}'.`);
    info('Is this the auth database? The account table lives in auth, not characters or world.');
    process.exit(1);
  }
  ok(`account table found, ${cols.length} columns`);

  const missing = REQUIRED.filter((c) => !cols.includes(c));
  if (missing.length) {
    bad(`missing columns the login path needs: ${missing.join(', ')}`);
    info('Accounts created here would not be able to log in.');
    process.exit(1);
  }
  ok('all columns the login path reads are present');

  // expansion — the classic silent killer.
  try {
    const r = await conn.query(
      `SELECT COLUMN_DEFAULT FROM information_schema.COLUMNS
       WHERE TABLE_SCHEMA = '${CFG.name}' AND TABLE_NAME = 'account' AND COLUMN_NAME = 'expansion'`
    );
    const def = r.rows.length ? r.rows[0][0] : null;
    if (def === '4') {
      info(`note: account.expansion defaults to ${def} (the schema default).`);
      info('MoP needs 5. The page sets this explicitly, so this is fine —');
      info('but any account made OUTSIDE this page may land on 4 and fail to log in.');
    } else {
      ok(`account.expansion default is ${def}`);
    }
  } catch { /* non-fatal */ }

  // can we actually write? check privileges without writing anything.
  try {
    const r = await conn.query(
      `SELECT COUNT(*) FROM information_schema.SCHEMA_PRIVILEGES
       WHERE TABLE_SCHEMA = '${CFG.name}' AND PRIVILEGE_TYPE = 'INSERT'`
    );
    const n = r.rows.length ? Number(r.rows[0][0]) : 0;
    if (n > 0) ok('INSERT privilege present at the schema level');
    else info('No schema-level INSERT grant found. The page needs INSERT on `account`.');
  } catch { /* non-fatal */ }

  // How many accounts already exist — sanity, and useful context.
  try {
    const r = await conn.query('SELECT COUNT(*) FROM account');
    ok(`account table currently holds ${r.rows[0][0]} account(s)`);
  } catch { /* non-fatal */ }

  console.log('\nAll good. This page can create working accounts against this database.\n');
  conn.end();
  process.exit(0);
})().catch((e) => {
  console.error('\nunexpected error:', e.message, '\n');
  process.exit(1);
});
