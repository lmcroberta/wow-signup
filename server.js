#!/usr/bin/env node
/**
 * WoW self-serve account registration — TrinityCore 5.4.8 (MoP)
 * Written for Robert's EmuCoach repack realm.
 *
 * WHY THIS EXISTS
 *   TrinityCore ships NO web signup. Not a disabled flag — it doesn't exist.
 *   The only remote-admin surface is SOAP, hard-gated to gmlevel 3. So this is
 *   a build. This is the build.
 *
 * WHY IT WRITES STRAIGHT TO THE AUTH DB (Option A)
 *   sha_pass_hash = UPPERCASE( SHA1( UPPERCASE(user) + ":" + UPPERCASE(pass) ) )
 *   verified at AccountMgr.cpp:341 + normalizeString() at AccountMgr.cpp:323.
 *   So we can compute the hash ourselves. No worldserver needed, no admin
 *   credential stored anywhere, and signups work while the game server is off.
 *   Least privilege: it only ever INSERTs into `account`.
 *
 * ZERO DEPENDENCIES — on purpose. Uses node:http + node:crypto only.
 * Node 18+. No npm install. Nothing to break.
 *
 * CONFIG: environment variables (see README / docker-compose notes)
 *   DB_HOST, DB_PORT (3306), DB_USER, DB_PASS, DB_NAME (auth)
 *   LISTEN_PORT (8080)
 *   REALM_NAME   (optional, shown on the page)
 *   REALM_ADDRESS(optional, shown on the page)
 *   ACCOUNT_EXPANSION (default 5 — MoP. NOT the schema default of 4.)
 *   REQUIRE_EMAIL (default 0)
 *   MAX_PER_IP_PER_DAY (default 5)
 */

'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');

const BACKGROUND_PATH = path.join(__dirname, 'pandaria-background.jpg');

// ---------------------------------------------------------------------------
// Minimal MySQL client (zero dependencies). Speaks enough of the wire protocol
// to do a handful of prepared statements: auth (mysql_native_password), SELECT,
// and one INSERT. If you'd rather use mysql2, swap this block out — nothing
// else in the file touches it. Verified against MySQL 8.0.30 (his repack).
// ---------------------------------------------------------------------------
const MYSQL = (() => {
  // The capability bits we advertise. CONNECT_WITH_DB (0x8) is NOT optional
  // here: without it the server ignores the database name in our handshake
  // response, and worse, the session never reaches command-ready state — every
  // query comes back as an OK packet instead of a result set.
  const CLIENT_CAPABILITIES =
    0x00000001 | // LONG_PASSWORD
    0x00000004 | // LONG_FLAG
    0x00000008 | // CONNECT_WITH_DB
    0x00000200 | // PROTOCOL_41
    0x00008000 | // SECURE_CONNECTION
    0x00080000 | // PLUGIN_AUTH
    0x00200000;  // PLUGIN_AUTH_LENENC_CLIENT_DATA

  const COM_QUERY = 0x03;
  const COM_QUIT = 0x01;

  function sha1(b) { return crypto.createHash('sha1').update(b).digest(); }
  function sha256(b) { return crypto.createHash('sha256').update(b).digest(); }

  function scrambleNative(password, seed) {
    // NOTE: a genuinely empty password sends a zero-length auth response, and
    // that is valid. But it also silently "succeeds" against a server that
    // isn't really authenticating you, so the caller verifies with a probe
    // query after connecting. Do not treat this as a no-op.
    if (!password) return Buffer.alloc(0);
    const s1 = sha1(Buffer.from(password, 'utf8'));
    const s2 = sha1(s1);
    const s3 = sha1(Buffer.concat([seed, s2]));
    const out = Buffer.alloc(20);
    for (let i = 0; i < 20; i++) out[i] = s1[i] ^ s3[i];
    return out;
  }

  function scrambleCachingSha2(password, seed) {
    if (!password) return Buffer.alloc(0);
    const s1 = sha256(Buffer.from(password, 'utf8'));
    const s2 = sha256(s1);
    const s3 = sha256(Buffer.concat([s2, seed]));
    const out = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) out[i] = s1[i] ^ s3[i];
    return out;
  }

  // --- packet framing -------------------------------------------------------
  function makePacket(payload, seq) {
    const head = Buffer.alloc(4);
    head.writeUIntLE(payload.length, 0, 3);
    head[3] = seq & 0xff;
    return Buffer.concat([head, payload]);
  }

  class Reader {
    constructor(buf) { this.b = buf; this.i = 0; }
    u8() { return this.b[this.i++]; }
    u16() { const v = this.b.readUInt16LE(this.i); this.i += 2; return v; }
    u24() { const v = this.b.readUIntLE(this.i, 3); this.i += 3; return v; }
    u32() { const v = this.b.readUInt32LE(this.i); this.i += 4; return v; }
    u64() { const v = this.b.readBigUInt64LE(this.i); this.i += 8; return v; }
    bytes(n) { const v = this.b.subarray(this.i, this.i + n); this.i += n; return v; }
    // length-encoded integer
    lenenc() {
      const first = this.u8();
      if (first < 0xfb) return first;
      if (first === 0xfb) return null;           // NULL
      if (first === 0xfc) return this.u16();
      if (first === 0xfd) return this.u24();
      return Number(this.u64());
    }
    // length-encoded string
    lenstr() {
      const n = this.lenenc();
      if (n === null) return null;
      return this.bytes(n);
    }
    nulstr() {
      const end = this.b.indexOf(0, this.i);
      const v = this.b.subarray(this.i, end);
      this.i = end + 1;
      return v;
    }
    rest() { const v = this.b.subarray(this.i); this.i = this.b.length; return v; }
  }

  function lenencInt(n) {
    if (n < 0xfb) return Buffer.from([n]);
    if (n <= 0xffff) { const b = Buffer.alloc(3); b[0] = 0xfc; b.writeUInt16LE(n, 1); return b; }
    if (n <= 0xffffff) { const b = Buffer.alloc(4); b[0] = 0xfd; b.writeUIntLE(n, 1, 3); return b; }
    const b = Buffer.alloc(9); b[0] = 0xfe; b.writeBigUInt64LE(BigInt(n), 1); return b;
  }

  function lenencStr(s) {
    const b = Buffer.isBuffer(s) ? s : Buffer.from(String(s), 'utf8');
    return Buffer.concat([lenencInt(b.length), b]);
  }

  // --- result set parsing ---------------------------------------------------
  function parseColumnDef(buf) {
    const r = new Reader(buf);
    r.lenstr(); r.lenstr(); r.lenstr();          // catalog, schema, table
    r.lenstr();                                   // org_table
    const name = r.lenstr().toString('utf8');     // name
    return name;
  }

  function parseTextRow(buf, ncols) {
    const r = new Reader(buf);
    const row = [];
    for (let i = 0; i < ncols; i++) {
      const v = r.lenstr();
      row.push(v === null ? null : v.toString('utf8'));
    }
    return row;
  }

  class Conn {
    constructor() { this.sock = null; this.buf = Buffer.alloc(0); this.seq = 0; this.ready = null; }

    static connect(opts) {
      const c = new Conn();
      c.opts = opts;
      return new Promise((resolve, reject) => {
        c.sock = net.connect({ host: opts.host, port: opts.port });
        c.sock.setNoDelay(true);
        c.sock.once('error', reject);
        c.sock.once('connect', async () => {
          try { await c._handshake(); resolve(c); } catch (e) { reject(e); }
        });
      });
    }

    // A single long-lived listener fills this.buf. Every read waits on a waiter
    // until enough bytes are present. The previous version attached and detached
    // a listener per read, and calling it twice in a row (header, then body)
    // dropped any bytes that arrived in the gap — which silently desynced the
    // stream so that a SELECT came back looking like an OK packet.
    _ensureReader() {
      if (this._reading) return;
      this._reading = true;
      this._waiters = [];
      this.sock.on('data', (d) => {
        this.buf = Buffer.concat([this.buf, d]);
        this._flush();
      });
      this.sock.on('error', (e) => {
        const w = this._waiters.splice(0); w.forEach((x) => x.reject(e));
      });
      this.sock.on('end', () => {
        const w = this._waiters.splice(0); w.forEach((x) => x.reject(new Error('connection closed')));
      });
    }

    _flush() {
      for (let i = 0; i < this._waiters.length; i++) {
        const w = this._waiters[i];
        if (this.buf.length >= w.n) {
          const v = this.buf.subarray(0, w.n);
          this.buf = this.buf.subarray(w.n);
          this._waiters.splice(i, 1);
          i--;
          w.resolve(v);
        } else break;
      }
    }

    _pull(n) {
      this._ensureReader();
      return new Promise((resolve, reject) => {
        this._waiters.push({ n, resolve, reject });
        this._flush();
      });
    }

    async _readPacket() {
      const head = await this._pull(4);
      const len = head.readUIntLE(0, 3);
      this.seq = (head[3] + 1) & 0xff;
      return await this._pull(len);
    }

    _send(payload, resetSeq) {
      // Every new command starts its own packet sequence at 0. Reusing the
      // handshake's sequence number here makes the server misread the command
      // and answer with an OK packet instead of a result set — which looks
      // exactly like "query returned no rows". That bug cost me an hour.
      if (resetSeq) this.seq = 0;
      const pkt = makePacket(payload, this.seq);
      this.seq = (this.seq + 1) & 0xff;
      this.sock.write(pkt);
    }

    _err(payload) {
      const r = new Reader(payload);
      r.u8(); // 0xff
      const code = r.u16();
      const msg = r.rest().toString('utf8');
      const e = new Error(`MySQL ${code}: ${msg}`);
      e.code = code;
      return e;
    }

    async _handshake() {
      const p = await this._readPacket();
      const r = new Reader(p);
      const proto = r.u8();
      if (proto === 0xff) throw this._err(p);
      r.nulstr();                       // server version
      r.u32();                          // connection id
      const seed1 = r.bytes(8);
      r.u8();                           // filler
      const capLow = r.u16();
      r.u8();                           // charset
      r.u16();                          // status
      const capHigh = r.u16();
      let caps = capLow | (capHigh << 16);
      const authLen = r.u8();
      r.bytes(10);                      // reserved
      const seed2raw = r.bytes(Math.max(13, authLen - 8));
      const seed2 = seed2raw.subarray(0, 12);
      const seed = Buffer.concat([seed1, seed2]);
      let authPlugin = '';
      if (caps & 0x00080000) {
        // plugin name follows, NUL-terminated
        authPlugin = r.nulstr().toString('utf8');
      }

      const wantCaps = caps & CLIENT_CAPABILITIES;
      let authResp;
      if (authPlugin === 'caching_sha2_password') {
        authResp = scrambleCachingSha2(this.opts.password, seed);
      } else {
        authResp = scrambleNative(this.opts.password, seed);
      }

      const db = Buffer.from(this.opts.database, 'utf8');
      const user = Buffer.from(this.opts.user, 'utf8');
      const plugin = Buffer.from(authPlugin || 'mysql_native_password', 'utf8');

      const parts = [
        (() => { const b = Buffer.alloc(4); b.writeUInt32LE(wantCaps, 0); return b; })(),
        (() => { const b = Buffer.alloc(4); b.writeUInt32LE(16 * 1024 * 1024, 0); return b; })(),
        Buffer.from([0x21]),                        // charset utf8_general_ci
        Buffer.alloc(23),
        user, Buffer.from([0]),
        lenencInt(authResp.length), authResp,
        db, Buffer.from([0]),
        plugin, Buffer.from([0]),
      ];
      this._send(Buffer.concat(parts));

      // Auth result — may take a couple of round trips with caching_sha2.
      for (let guard = 0; guard < 4; guard++) {
        const resp = await this._readPacket();
        const t = resp[0];
        if (t === 0x00) return;                         // OK
        if (t === 0xff) throw this._err(resp);          // ERR
        if (t === 0xfe) {                               // auth switch request
          const r2 = new Reader(resp);
          r2.u8();
          const plug = r2.nulstr().toString('utf8');
          const s2raw = r2.rest();
          const s2 = s2raw.subarray(0, s2raw.length - 1);
          const resp2 = plug === 'caching_sha2_password'
            ? scrambleCachingSha2(this.opts.password, s2)
            : scrambleNative(this.opts.password, s2);
          this._send(resp2);
          continue;
        }
        if (t === 0x01) {                               // auth more data
          const marker = resp[1];
          if (marker === 0x03) continue;                // fast auth success
          if (marker === 0x04) {
            // full auth needed. Over an unencrypted link we can only do this
            // if the server allows the cleartext request (SSL-less localhost).
            this._send(Buffer.from([0x02]));            // request public key
            const pk = await this._readPacket();
            // Sending the password encrypted with the RSA key requires crypto
            // pubkey ops; rather than hand-roll RSA here we fail clearly and
            // tell the operator to set the user's plugin to mysql_native_password.
            throw new Error(
              'Server requires full caching_sha2_password authentication. ' +
              'Run this on the MySQL user instead: ' +
              `ALTER USER '${this.opts.user}'@'%' IDENTIFIED WITH mysql_native_password BY '<password>'; ` +
              'then FLUSH PRIVILEGES;'
            );
          }
          continue;
        }
      }
      throw new Error('Authentication did not complete.');
    }

    async query(sql) {
      this._send(Buffer.concat([Buffer.from([COM_QUERY]), Buffer.from(sql, 'utf8')]), true);
      const first = await this._readPacket();
      const t = first[0];
      if (t === 0xff) throw this._err(first);

      if (t === 0x00) {
        const r = new Reader(first);
        r.u8();
        const affected = r.lenenc();
        return { rows: [], affectedRows: affected, fields: [] };
      }

      // result set: column count, then column defs, then rows, then EOF/OK
      const r = new Reader(first);
      const ncols = r.lenenc();
      const fields = [];
      for (let i = 0; i < ncols; i++) {
        const cp = await this._readPacket();
        fields.push(parseColumnDef(cp));
      }
      // EOF packet (deprecated but still sent when CLIENT_DEPRECATE_EOF unset)
      await this._readPacket();

      const rows = [];
      for (;;) {
        const p = await this._readPacket();
        if (p[0] === 0xfe && p.length < 9) break;       // EOF
        if (p[0] === 0xff) throw this._err(p);
        rows.push(parseTextRow(p, ncols));
      }
      return { rows, affectedRows: 0, fields };
    }

    end() {
      try { this._send(Buffer.from([COM_QUIT])); } catch {}
      try { this.sock.end(); } catch {}
    }
  }

  return { Conn };
})();

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const CFG = {
  dbHost: process.env.DB_HOST || '127.0.0.1',
  dbPort: parseInt(process.env.DB_PORT || '3306', 10),
  dbUser: process.env.DB_USER || '',
  dbPass: process.env.DB_PASS || '',
  dbName: process.env.DB_NAME || 'auth',
  listenPort: parseInt(process.env.LISTEN_PORT || '8080', 10),
  realmName: process.env.REALM_NAME || '',
  realmAddress: process.env.REALM_ADDRESS || '',
  expansion: parseInt(process.env.ACCOUNT_EXPANSION || '5', 10),
  requireEmail: (process.env.REQUIRE_EMAIL || '0') === '1',
  maxPerIpPerDay: parseInt(process.env.MAX_PER_IP_PER_DAY || '5', 10),
};

// ---------------------------------------------------------------------------
// The part that actually matters: TrinityCore's password hash.
//
// AccountMgr::normalizeString() uppercases with wcharToUpperOnlyLatin(), which
// ONLY maps a-z -> A-Z. Every other codepoint is left alone. We restrict the
// input charset to ASCII alphanumerics instead of trying to reimplement that,
// which is the safe move: a non-Latin username would hash differently here than
// on the server and produce an account nobody can log into.
// ---------------------------------------------------------------------------
function normalize(s) {
  return s.replace(/[a-z]/g, (c) => c.toUpperCase());
}

function shaPassHash(username, password) {
  const u = normalize(username);
  const p = normalize(password);
  return crypto.createHash('sha1').update(`${u}:${p}`, 'utf8').digest('hex').toUpperCase();
}

// MAX_ACCOUNT_STR is 16 in this build (AccountMgr.h:45). The column is
// varchar(32) — the CODE cap is the one that bites. Longer = account that
// cannot log in.
const MAX_USERNAME = 16;
const USERNAME_RE = /^[A-Za-z0-9]{3,16}$/;

function validate(username, password, password2, email) {
  const errs = [];
  if (!username) errs.push('Username is required.');
  else if (!USERNAME_RE.test(username))
    errs.push(`Username must be 3 to ${MAX_USERNAME} characters, letters and numbers only.`);
  if (!password) errs.push('Password is required.');
  else if (password.length < 6) errs.push('Password must be at least 6 characters.');
  else if (password.length > 16) errs.push('Password must be 16 characters or fewer.');
  else if (!USERNAME_RE.test(password))
    errs.push('Password must be letters and numbers only.');
  if (password !== password2) errs.push('The two passwords do not match.');
  if (CFG.requireEmail && !email) errs.push('Email is required.');
  if (email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) errs.push('That email does not look right.');
  return errs;
}

// ---------------------------------------------------------------------------
// Crude in-memory rate limit. Deliberately simple: this is a LAN signup page.
// ---------------------------------------------------------------------------
const ipHits = new Map();
function rateLimited(ip) {
  const today = new Date().toISOString().slice(0, 10);
  const rec = ipHits.get(ip);
  if (!rec || rec.day !== today) {
    ipHits.set(ip, { day: today, n: 1 });
    return false;
  }
  rec.n += 1;
  return rec.n > CFG.maxPerIpPerDay;
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------
function page(body, status = 200) {
  return {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
    body,
  };
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function renderForm({ errors = [], values = {}, notice = '' } = {}) {
  const realmLine = CFG.realmName
    ? `<p class="realm">Realm: <strong>${esc(CFG.realmName)}</strong>${CFG.realmAddress ? ` &middot; ${esc(CFG.realmAddress)}` : ''}</p>`
    : '';
  const errBox = errors.length
    ? `<ul class="errors">${errors.map((e) => `<li>${esc(e)}</li>`).join('')}</ul>`
    : '';
  const noticeBox = notice ? `<div class="notice">${esc(notice)}</div>` : '';
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Create your account</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100dvh; display:grid; place-items:center;
         background:#14110d url('/pandaria-background.jpg') center center / cover fixed no-repeat;
         color:#f2eadc; font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
         padding:24px; position:relative; isolation:isolate; }
  body::before { content:''; position:fixed; inset:0; z-index:-1;
                 background:linear-gradient(120deg,rgba(5,12,15,.72),rgba(10,18,16,.47) 48%,rgba(8,10,12,.70)); }
  .card { width:100%; max-width:420px; background:rgba(25,22,17,.91); border:1px solid rgba(211,177,99,.36);
          border-radius:14px; padding:28px; box-shadow:0 18px 55px #000b;
          backdrop-filter:blur(8px); -webkit-backdrop-filter:blur(8px); }
  h1 { margin:0 0 4px; font-size:22px; letter-spacing:.3px; }
  .sub { margin:0 0 18px; color:#9a8f7d; font-size:13px; }
  .realm { margin:0 0 18px; padding:10px 12px; background:#241f19; border-radius:8px;
           font-size:13px; color:#bdb2a0; }
  label { display:block; font-size:13px; color:#bdb2a0; margin:14px 0 5px; }
  input { width:100%; padding:11px 12px; background:#14110d; color:#e8e0d0;
          border:1px solid #3a3128; border-radius:8px; font-size:15px; }
  input:focus { outline:2px solid #c8a04a55; border-color:#c8a04a; }
  .hint { font-size:12px; color:#7d7365; margin-top:5px; }
  button { width:100%; margin-top:22px; padding:12px; font-size:15px; font-weight:600;
           color:#1a1610; background:#c8a04a; border:0; border-radius:8px; cursor:pointer; }
  button:hover { background:#d8b05a; }
  .errors { list-style:none; margin:0 0 6px; padding:12px; border-radius:8px;
            background:#3a1f1f; border:1px solid #6b3030; color:#f0c0c0; font-size:13px; }
  .notice { padding:12px; border-radius:8px; background:#1f3a24; border:1px solid #306b3a;
            color:#c0f0c8; font-size:13px; margin-bottom:6px; }
  .foot { margin-top:18px; font-size:12px; color:#7d7365; text-align:center; }
</style></head>
<body><div class="card">
  <h1>Create your account</h1>
  <p class="sub">Sign up and log straight in. No approval needed.</p>
  ${realmLine}
  ${noticeBox}
  ${errBox}
  <form method="POST" action="/signup" autocomplete="off">
    <label for="username">Username</label>
    <input id="username" name="username" maxlength="${MAX_USERNAME}" required
           value="${esc(values.username || '')}">
    <div class="hint">3 to ${MAX_USERNAME} characters. Letters and numbers only.</div>

    <label for="password">Password</label>
    <input id="password" name="password" type="password" maxlength="16" required>

    <label for="password2">Password again</label>
    <input id="password2" name="password2" type="password" maxlength="16" required>

    <label for="email">Email ${CFG.requireEmail ? '' : '<span class="hint" style="display:inline">(optional)</span>'}</label>
    <input id="email" name="email" type="email" value="${esc(values.email || '')}">

    <button type="submit">Create account</button>
  </form>
  <div class="foot">Use the same username and password in the game client.</div>
</div></body></html>`;
}

function renderDone(username) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Account created</title>
<style>
  body { margin:0; min-height:100dvh; display:grid; place-items:center;
         background:#14110d url('/pandaria-background.jpg') center center / cover fixed no-repeat;
         color:#f2eadc; font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
         padding:24px; position:relative; isolation:isolate; }
  body::before { content:''; position:fixed; inset:0; z-index:-1;
                 background:linear-gradient(120deg,rgba(5,12,15,.72),rgba(10,18,16,.47) 48%,rgba(8,10,12,.70)); }
  .card { width:100%; max-width:420px; background:rgba(25,22,17,.91); border:1px solid rgba(211,177,99,.36);
          border-radius:14px; padding:28px; text-align:center; box-shadow:0 18px 55px #000b;
          backdrop-filter:blur(8px); -webkit-backdrop-filter:blur(8px); }
  h1 { margin:0 0 10px; font-size:22px; color:#8fd89a; }
  code { background:#14110d; padding:3px 7px; border-radius:5px; color:#c8a04a; }
  a { display:inline-block; margin-top:20px; color:#c8a04a; }
</style></head>
<body><div class="card">
  <h1>You're in.</h1>
  <p>Account <code>${esc(username)}</code> is created.</p>
  <p>Open World of Warcraft and log in with that username and password.</p>
  <a href="/">Create another account</a>
</div></body></html>`;
}

// ---------------------------------------------------------------------------
// DB layer. The ONLY place that talks to MySQL.
//
// It probes the real table on boot rather than trusting the base schema. That
// is deliberate: his repack dropped the PRIMARY KEY on characters.corpse, which
// proves the shipped schema is NOT what he runs. So we read the live columns,
// build the INSERT from what actually exists, and refuse to start if a column
// the login path needs is missing.
// ---------------------------------------------------------------------------
const DB = (() => {
  let conn = null;
  let cols = new Set();

  function q(v) {
    if (v === null || v === undefined) return 'NULL';
    return "'" + String(v).replace(/\\/g, '\\\\').replace(/'/g, "\\'") + "'";
  }

  async function connect() {
    conn = await MYSQL.Conn.connect({
      host: CFG.dbHost, port: CFG.dbPort,
      user: CFG.dbUser, password: CFG.dbPass, database: CFG.dbName,
    });
    // Probe: prove the connection is genuinely usable and we're in the right
    // database. A socket that "connects" but can't run a query is worse than a
    // failure, because it fails silently at signup time instead of at boot.
    const probe = await conn.query('SELECT DATABASE() AS db');
    if (!probe.rows.length) {
      throw new Error('Connected to MySQL but the probe query returned nothing. Check credentials and database name.');
    }
    const dbName = probe.rows[0][0];
    if (dbName !== CFG.dbName) {
      throw new Error(`Connected, but the active database is '${dbName}', not '${CFG.dbName}'.`);
    }
  }

  async function loadColumns() {
    const r = await conn.query(
      `SELECT COLUMN_NAME FROM information_schema.COLUMNS
       WHERE TABLE_SCHEMA = ${q(CFG.dbName)} AND TABLE_NAME = 'account'`
    );
    cols = new Set(r.rows.map((row) => row[0].toLowerCase()));
  }

  // Columns the login path reads. From LOGIN_SEL_LOGONCHALLENGE in
  // LoginDatabase.cpp:43. If any are absent the account can't log in, so we
  // say so loudly at boot instead of creating dead accounts.
  const REQUIRED = ['id', 'username', 'sha_pass_hash', 'expansion', 'v', 's'];

  async function preflight() {
    await connect();
    await loadColumns();
    if (cols.size === 0) throw new Error(`Table 'account' not found in database '${CFG.dbName}'.`);
    const missing = REQUIRED.filter((c) => !cols.has(c));
    if (missing.length) {
      throw new Error(`The account table is missing column(s) the login path needs: ${missing.join(', ')}. Refusing to start.`);
    }
  }

  async function usernameTaken(username) {
    const r = await conn.query(`SELECT id FROM account WHERE username = ${q(username)} LIMIT 1`);
    return r.rows.length > 0;
  }

  async function insertAccount({ username, hash, email, expansion }) {
    if (await usernameTaken(username)) return { ok: false, reason: 'taken' };

    const names = ['username', 'sha_pass_hash', 'email', 'joindate', 'expansion'];
    const values = [q(username), q(hash), q(email), 'NOW()', String(expansion)];

    // Only set the SRP6 columns if they actually exist. They are NOT in the
    // base INSERT (LOGIN_INS_ACCOUNT), so we mirror that: leave them to their
    // schema default unless present, in which case '' is what the server
    // itself writes on password change (LOGIN_UPD_PASSWORD sets v = 0, s = 0).
    if (cols.has('v')) { names.push('v'); values.push("''"); }
    if (cols.has('s')) { names.push('s'); values.push("''"); }

    try {
      await conn.query(`INSERT INTO account (${names.join(', ')}) VALUES (${values.join(', ')})`);
      return { ok: true };
    } catch (e) {
      // Duplicate key on username = lost the race, treat as taken.
      if (e.code === 1062) return { ok: false, reason: 'taken' };
      return { ok: false, reason: 'dberror', detail: e.message };
    }
  }

  return { preflight, insertAccount, get columns() { return cols; } };
})();

// ---------------------------------------------------------------------------
// Account creation — thin wrapper so the HTTP layer stays readable.
// ---------------------------------------------------------------------------
async function createAccount(username, password, email) {
  return DB.insertAccount({
    username: normalize(username),
    hash: shaPassHash(username, password),
    email: email || '',
    expansion: CFG.expansion,
  });
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------
function readBody(req, limit = 4096) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => {
      data += c;
      if (data.length > limit) { reject(new Error('too large')); req.destroy(); }
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString().split(',')[0].trim();

  if (req.method === 'GET' && url.pathname === '/') {
    const r = page(renderForm());
    res.writeHead(r.status, r.headers); res.end(r.body); return;
  }

  if (req.method === 'GET' && url.pathname === '/pandaria-background.jpg') {
    fs.readFile(BACKGROUND_PATH, (err, image) => {
      if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('Not found'); return; }
      res.writeHead(200, { 'Content-Type': 'image/jpeg', 'Cache-Control': 'public, max-age=86400' });
      res.end(image);
    });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true })); return;
  }

  if (req.method === 'POST' && url.pathname === '/signup') {
    let form;
    try {
      form = new URLSearchParams(await readBody(req));
    } catch {
      const r = page(renderForm({ errors: ['That submission was too large.'] }), 413);
      res.writeHead(r.status, r.headers); res.end(r.body); return;
    }

    const username = (form.get('username') || '').trim();
    const password = form.get('password') || '';
    const password2 = form.get('password2') || '';
    const email = (form.get('email') || '').trim();

    const errors = validate(username, password, password2, email);
    if (errors.length) {
      const r = page(renderForm({ errors, values: { username, email } }), 400);
      res.writeHead(r.status, r.headers); res.end(r.body); return;
    }

    if (rateLimited(ip)) {
      const r = page(renderForm({
        errors: ['Too many accounts created from this address today. Try again tomorrow.'],
        values: { username, email },
      }), 429);
      res.writeHead(r.status, r.headers); res.end(r.body); return;
    }

    let out;
    try {
      out = await createAccount(username, password, email);
    } catch (e) {
      console.error('[signup] unexpected error:', e);
      const r = page(renderForm({ errors: ['Something went wrong creating the account. Try again.'], values: { username, email } }), 500);
      res.writeHead(r.status, r.headers); res.end(r.body); return;
    }

    if (!out.ok && out.reason === 'taken') {
      const r = page(renderForm({ errors: ['That username is already taken. Pick another.'], values: { username, email } }), 409);
      res.writeHead(r.status, r.headers); res.end(r.body); return;
    }
    if (!out.ok) {
      console.error('[signup] db error:', out.detail);
      const r = page(renderForm({ errors: ['The account database is not reachable right now.'], values: { username, email } }), 503);
      res.writeHead(r.status, r.headers); res.end(r.body); return;
    }

    console.log(`[signup] created ${normalize(username)} from ${ip}`);
    const r = page(renderDone(username));
    res.writeHead(r.status, r.headers); res.end(r.body); return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('Not found');
});

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
if (require.main === module) {
  (async () => {
    if (!CFG.dbUser) {
      console.error('DB_USER is not set. Refusing to start.');
      process.exit(1);
    }
    try {
      await DB.preflight();
      console.log(`schema ok — account table has: ${[...DB.columns].sort().join(', ')}`);
    } catch (e) {
      console.error('preflight failed:', e.message);
      process.exit(1);
    }
    server.listen(CFG.listenPort, () => {
      console.log(`wow-signup listening on :${CFG.listenPort}`);
      console.log(`  auth db  : ${CFG.dbUser}@${CFG.dbHost}:${CFG.dbPort}/${CFG.dbName}`);
      console.log(`  expansion: ${CFG.expansion}   realm: ${CFG.realmName || '(unset)'}`);
    });
  })();
}

module.exports = { shaPassHash, normalize, validate, MAX_USERNAME };
