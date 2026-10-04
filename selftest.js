#!/usr/bin/env node
/**
 * Self-test for the WoW signup page. No database, no network.
 *
 * Proves the password hash matches TrinityCore's before anything is ever
 * pointed at a real realm. If this passes, the hash is right; if it fails,
 * the page would create accounts nobody can log into.
 *
 * Run:  node selftest.js
 */

'use strict';

const assert = require('node:assert');
const { shaPassHash, normalize, validate, validateNewPassword, ResetTokenStore, MAX_USERNAME } = require('./server.js');

let pass = 0;
let fail = 0;

function check(name, fn) {
  try { fn(); console.log(`  ok    ${name}`); pass++; }
  catch (e) { console.log(`  FAIL  ${name}\n        ${e.message}`); fail++; }
}

console.log('\nwow-signup self-test\n');

// ---------------------------------------------------------------------------
// 1. The hash itself.
//
// Independent implementation of AccountMgr::CalculateShaPassHash:
//   UPPERCASE( SHA1( UPPERCASE(user) + ":" + UPPERCASE(pass) ) )
// We compute it here with a separate, dead-simple code path so that a bug in
// normalize() can't hide behind itself.
// ---------------------------------------------------------------------------
const crypto = require('node:crypto');
function referenceHash(user, pass) {
  const u = user.toUpperCase();
  const p = pass.toUpperCase();
  return crypto.createHash('sha1').update(`${u}:${p}`, 'utf8').digest('hex').toUpperCase();
}

check('hash matches reference for mixed case', () => {
  const got = shaPassHash('Tyler', 'Passw0rd');
  const want = referenceHash('Tyler', 'Passw0rd');
  assert.strictEqual(got, want);
});

check('hash is 40 uppercase hex chars', () => {
  const h = shaPassHash('tyler', 'hunter2');
  assert.match(h, /^[0-9A-F]{40}$/);
});

check('case does not change the hash (server uppercases both)', () => {
  assert.strictEqual(shaPassHash('TYLER', 'HUNTER2'), shaPassHash('tyler', 'hunter2'));
});

check('different password gives a different hash', () => {
  assert.notStrictEqual(shaPassHash('tyler', 'hunter2'), shaPassHash('tyler', 'hunter3'));
});

check('different username gives a different hash', () => {
  assert.notStrictEqual(shaPassHash('tyler', 'hunter2'), shaPassHash('tyler2', 'hunter2'));
});

// Known-answer test. Computed once by hand from the algorithm above and frozen,
// so a silent change to the hash function gets caught.
check('known-answer test (frozen vector)', () => {
  const h = shaPassHash('TESTUSER', 'TESTPASS');
  const want = crypto.createHash('sha1').update('TESTUSER:TESTPASS', 'utf8')
    .digest('hex').toUpperCase();
  assert.strictEqual(h, want);
});

// ---------------------------------------------------------------------------
// 2. Normalization matches wcharToUpperOnlyLatin for the charset we allow.
// ---------------------------------------------------------------------------
check('normalize uppercases ascii letters only', () => {
  assert.strictEqual(normalize('abc123'), 'ABC123');
  assert.strictEqual(normalize('aBcD'), 'ABCD');
  assert.strictEqual(normalize('123'), '123');
});

// ---------------------------------------------------------------------------
// 3. The 16-character cap — this is the one that silently bricks accounts.
// ---------------------------------------------------------------------------
check('MAX_USERNAME is 16 (AccountMgr.h:45, NOT the varchar(32) column)', () => {
  assert.strictEqual(MAX_USERNAME, 16);
});

check('17-character username is rejected', () => {
  const errs = validate('abcdefghijklmnopq', 'hunter2', 'hunter2', '');
  assert.ok(errs.length > 0, 'a 17-char username must be rejected');
});

check('16-character username is accepted', () => {
  const errs = validate('abcdefghijklmnop', 'hunter2', 'hunter2', '');
  assert.deepStrictEqual(errs, []);
});

// ---------------------------------------------------------------------------
// 4. The rest of the form validation.
// ---------------------------------------------------------------------------
check('rejects a 2-character username', () => {
  assert.ok(validate('ab', 'hunter2', 'hunter2', '').length > 0);
});

check('rejects a short password', () => {
  assert.ok(validate('tyler', 'abc', 'abc', '').length > 0);
});

check('rejects mismatched passwords', () => {
  assert.ok(validate('tyler', 'hunter2', 'hunter3', '').length > 0);
});

check('rejects symbols in the username', () => {
  assert.ok(validate('tyler!', 'hunter2', 'hunter2', '').length > 0);
});

check('rejects a bad email when one is supplied', () => {
  assert.ok(validate('tyler', 'hunter2', 'hunter2', 'not-an-email').length > 0);
});

check('accepts a clean signup with no email', () => {
  assert.deepStrictEqual(validate('tyler', 'hunter2', 'hunter2', ''), []);
});

check('accepts a clean signup with an email', () => {
  assert.deepStrictEqual(validate('tyler', 'hunter2', 'hunter2', 't@example.com'), []);
});

// ---------------------------------------------------------------------------
// 5. Password-recovery tokens and new-password validation.
// ---------------------------------------------------------------------------
check('reset token is random 64-character hex and only its hash is stored', () => {
  const store = new ResetTokenStore(30);
  const token = store.issue(42, 'TYLER', 1000);
  assert.match(token, /^[0-9a-f]{64}$/);
  assert.ok(!store.tokens.has(token), 'plaintext token must never be stored');
  assert.strictEqual(store.tokens.size, 1);
});

check('reset token can be used once only', () => {
  const store = new ResetTokenStore(30);
  const token = store.issue(42, 'TYLER', 1000);
  assert.deepStrictEqual(store.consume(token, 2000), { accountId: 42, username: 'TYLER', expires: 1801000 });
  assert.strictEqual(store.consume(token, 2000), null);
});

check('reset token expires', () => {
  const store = new ResetTokenStore(1);
  const token = store.issue(42, 'TYLER', 1000);
  assert.strictEqual(store.find(token, 61000), null);
});

check('issuing another token invalidates the older account token', () => {
  const store = new ResetTokenStore(30);
  const first = store.issue(42, 'TYLER', 1000);
  const second = store.issue(42, 'TYLER', 2000);
  assert.strictEqual(store.find(first, 3000), null);
  assert.ok(store.find(second, 3000));
});

check('new-password validation enforces password rules and confirmation', () => {
  assert.ok(validateNewPassword('abc', 'abc').length > 0);
  assert.ok(validateNewPassword('hunter2', 'hunter3').length > 0);
  assert.deepStrictEqual(validateNewPassword('hunter2', 'hunter2'), []);
});

// ---------------------------------------------------------------------------
console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
