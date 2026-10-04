# WoW self-serve registration page

**Status: BUILT AND TESTED. Nothing deployed, nothing on Robert's machines touched.**

Written Oct 1, 2026 for Robert's EmuCoach TrinityCore 5.4.8 (MoP) realm, because Tyler
wants people to be able to sign up without an admin creating accounts by hand.

---

## What this is

A small web page that lets someone create their own game account. Type a username and
password, click Create, log into the game. No admin approval, no waiting on Robert.

## Why it had to be built (and isn't a setting somewhere)

TrinityCore **ships no web signup at all**. Not a disabled feature, not a config flag —
it does not exist in the codebase. The only remote-admin surface the project ships is
SOAP, and it is hard-gated to `SEC_ADMINISTRATOR` (gmlevel 3) at `TCSoap.cpp:105`, plus
`Ra.MinLevel` 3 at `RASession.cpp:139`. So this was always going to be a build.

## How it works (the important part)

TrinityCore stores passwords as a SHA1 hash it can compute from just the username and
password:

```
sha_pass_hash = UPPERCASE( SHA1( UPPERCASE(username) + ":" + UPPERCASE(password) ) )
```

Verified at `AccountMgr.cpp:341` (`CalculateShaPassHash`) with `normalizeString()` at
`AccountMgr.cpp:323`. 40 hex characters.

Because the hash is reproducible in any language, this page computes it itself and
writes the account row **directly into the auth database**. That means:

- **No worldserver needed.** Signups work while the game server is off.
- **No admin credential stored anywhere.** Least privilege — it only INSERTs into `account`.
- **It can live on any always-on box** that can reach the auth DB. This is what solves
  the "what if the WoW PC is asleep" problem.

This was tested end to end: a signup succeeded with **no worldserver process running at
all**, and the stored hash matched exactly what the server computes at login.

## The landmines it already handles

These are real, verified against the 5.4.8 source, and each one would have been a
silent, confusing failure:

| Trap | Why it bites | What this does |
|---|---|---|
| `account.expansion` schema default is **4** | MoP needs **5**. Wrong value = account created but can't log in | Sets `expansion` explicitly (configurable, defaults to 5) |
| **`MAX_ACCOUNT_STR` is 16**, not the column's 32 | A 17-char name creates an account nobody can ever log into | Rejects anything over 16, at the form and in code |
| Uppercasing is **Latin-only** (`wcharToUpperOnlyLatin`) | Non-Latin chars hash differently than a naive `.upper()` would | Restricts username/password to A-Z, a-z, 0-9 |
| `v` / `s` are `NOT NULL DEFAULT ''` | NULL in either breaks login | Sets `''` when the columns exist; omitted when they don't |
| `realmlist.name` is **UNIQUE** | A page that lets people type a realm name collides on the 2nd signup | Realm name is read-only, display only |

The signup page also shows a live realm indicator. It checks the WorldServer game port directly:
**green Online** when that port answers, **yellow Starting up** after AuthServer appears while
WorldServer is still loading, and **red Offline** otherwise. A stopped or crashed WorldServer is
never mislabeled as healthy just because the web page or database is still running.

The page also **probes the live `account` table on boot** and refuses to start if a column
the login path needs is missing. That is deliberate: Robert's repack dropped the PRIMARY
KEY on `characters.corpse`, which proves the shipped schema is **not** what he runs. This
does not assume the base schema is correct.

## Files

- `server.js` — the whole thing. Zero dependencies. Node 18+.
- `selftest.js` — 22 tests, no DB or email needed. Run `node selftest.js`.
- `check-db.js` — read-only diagnostic. Tells you if the page can reach the DB.
- `Dockerfile` — for a TrueNAS custom-app install. Zero dependencies means there is
  no `npm install` step; it just copies the three files and runs `node server.js`
  as the unprivileged `node` user. Every setting comes in as an environment variable.

## Running it

Environment variables:

| Variable | Default | Notes |
|---|---|---|
| `DB_HOST` | `127.0.0.1` | Where the auth DB lives |
| `DB_PORT` | `3306` | |
| `DB_USER` | *(required)* | Only needs INSERT + SELECT on `account` |
| `DB_PASS` | `''` | |
| `DB_NAME` | `auth` | |
| `LISTEN_PORT` | `8080` | |
| `REALM_NAME` | *(blank)* | Shown on the page. Display only |
| `ACCOUNT_EXPANSION` | `5` | MoP. Do not lower this |
| `REQUIRE_EMAIL` | `0` | Set to `1` to make email mandatory |
| `MAX_PER_IP_PER_DAY` | `5` | Signup rate limit |
| `SMTP_HOST` | `smtp.gmail.com` | Gmail SMTP server |
| `SMTP_PORT` | `587` | Gmail STARTTLS port |
| `SMTP_USER` | *(required for recovery)* | Full Gmail address used to send reset messages |
| `SMTP_PASS` | *(required for recovery)* | Google app password, supplied as a secret; spaces are ignored |
| `MAIL_FROM` | `SMTP_USER` | Sender address shown on reset messages |
| `PUBLIC_BASE_URL` | *(required for recovery)* | Public site root, for example `https://mop.example.com` |
| `RESET_TOKEN_TTL_MINUTES` | `30` | Reset-link lifetime |
| `RECOVERY_MAX_PER_IP_PER_HOUR` | `5` | Recovery request rate limit |
| `REALM_STATUS_HOST` | `DB_HOST` | WoW server address checked by the status badge |
| `REALM_GAME_PORT` | `8085` | WorldServer game port; open means Online |
| `REALM_AUTH_PORT` | `3724` | AuthServer port; used to recognize startup |
| `REALM_STATUS_TIMEOUT_MS` | `1200` | Timeout for each TCP check |
| `REALM_STATUS_POLL_MS` | `5000` | Server-side check interval |
| `REALM_STARTING_WINDOW_MS` | `600000` | Maximum Starting up window after AuthServer appears |

```bash
node selftest.js      # prove the hash is right, no DB needed
node check-db.js      # prove it can reach the DB
node server.js        # run it
```

## Known limitations — stated plainly, not buried

1. **The auth DB is on the WoW PC.** If the page is hosted on Nasty (always on) and the
   WoW PC is off, the page has nothing to write to. Tested working *without* the game
   server, but it still needs the **database** reachable. If Robert wants signups to work
   with the WoW PC fully powered down, the DB itself has to move — which is the separate
   MariaDB migration he already wants to do.
2. **MySQL user auth.** If his MySQL account uses `caching_sha2_password` (MySQL 8
   default), the bundled client will tell him to switch that user to
   `mysql_native_password`. This is a one-line `ALTER USER`.
3. **Recovery requires a Gmail app password.** Turn on 2-Step Verification for the
   sending Google account, create an app password, and enter that value as `SMTP_PASS`.
   Never use or store the normal Google account password in this app.
4. **The MySQL user needs UPDATE for recovery.** Signup used only SELECT + INSERT. Password
   reset additionally needs `UPDATE (sha_pass_hash, v, s)` on `auth.account`. Grant it
   locally on ROSCOEELVIS as a privileged MySQL user; the remote wowadmin user cannot GRANT.
5. **Reset links live in memory.** Only SHA-256 hashes of the random tokens are retained,
   but restarting or redeploying the app invalidates every outstanding reset link. This
   deliberately avoids altering the EmuCoach account schema or adding a storage mount.
6. **No email verification.** Anyone who can reach the page can make an account. Recovery
   requests use a generic response and are rate-limited so account details are not exposed.
7. **TLS terminates at Cloudflare.** The app itself serves HTTP behind the tunnel.
8. **The client is hand-rolled.** It speaks the MySQL and Gmail SMTP operations this app
   needs. It is tested, but it is not a general-purpose library.

## Still needed from Robert before this can be installed

1. `SHOW CREATE TABLE account;` — confirms `expansion` and the `v`/`s` columns exist on
   *his* repack. The page probes this itself at boot, so this is belt-and-braces.
2. Where it runs — recommendation is a small container on Nasty.
3. LAN-only or internet-facing.
4. The MySQL user/password for it to use (typed by him, not shared with me).

## The bugs found while building this

Worth recording, because two of them were subtle and one would have been a nightmare:

1. **Missing `CLIENT_CONNECT_WITH_DB` capability.** Without that flag the server ignores
   the database name *and* never reaches command-ready state, so every query came back as
   an OK packet instead of a result set — which looks exactly like "query returned zero
   rows". Cost an hour.
2. **Dropped bytes in the socket reader.** The read loop attached and detached a listener
   per read; calling it twice in a row (header, then body) silently discarded anything
   arriving in the gap. This is what actually produced the phantom empty result sets.
3. **Packet sequence not reset per command.** Each new command must start its own packet
   sequence at 0. Reusing the handshake's sequence made the server misread commands.

None of these are theoretical — all three were reproduced live against a real MySQL
server before being fixed, and the fixes are verified by the end-to-end test above.
