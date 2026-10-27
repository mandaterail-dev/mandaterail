# T11: reconcile timer + basic monitoring

## Roles (R20-P3-4, R21-P3-2, R21-P3-3)
- `mr_reconcile` and `mr_monitor` are dedicated LOGIN roles, managed by `deploy/sql/t11-mr-reconcile-role.sql`.
- The SQL is idempotent and runs in one transaction; re-run it (as postgres, after migrations) on every deploy. Each run:
  - re-applies `NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS` and the connection limit (4 / 2), and resets per-role settings;
  - revokes every role membership in either direction and every table/sequence/function privilege in `public`, then grants exactly the set below;
  - sets the owner of `mr_spend_transition` to the owner of `mr_spend_audit` (mr_owner on the host);
  - RAISEs (rolling everything back) if either role owns `mr_spend_audit`, is a member of its owner or of `mr_owner`, has an unsafe flag, keeps a membership, or can write `mr_spend` / `mr_spend_audit` directly (table or column level), or if mr_monitor can execute the function.
  - Passwords are optional `-v pw=` / `-v mon_pw=`; omit them to keep the current ones.
- `mr_reconcile`: SELECT on `mr_spend`, `mr_spend_audit`, `mr_schema`; EXECUTE on `mr_spend_transition(...)`. **No direct UPDATE on mr_spend and no INSERT on mr_spend_audit.**
- `mr_spend_transition` (schema v5) is `SECURITY DEFINER` with `search_path = pg_catalog, pg_temp` and schema-qualified names. It only moves `status` (+ `updated_ms`) from pending/ambiguous to settled/released, optionally only if `tx_id` is unchanged, requires actor/action/reason, and writes the audit row in the same call. EXECUTE is revoked from PUBLIC. So mr_reconcile can no longer change payer/amount or forge audit rows without a matching status change.
- `mr_monitor`: SELECT only (`mr_spend`, `mr_spend_audit`, `mr_schema`); no EXECUTE on the function.
- **mr_reconcile must never own `mr_spend_audit` and must never be a member of its owner (`mr_owner`).** A table owner can `ALTER TABLE ... DISABLE TRIGGER`, which bypasses the append-only guard (v4). Ownership stays with `mr_owner`, used only for migrations.
- The spend CLI enforces this. `reconcile` and `release` refuse to run when the connected role owns the table (directly or through membership) or is a superuser (`auditOwnerRisk`). `MR_TEST_ALLOW_AUDIT_OWNER=1` relaxes the check for tests only, and it is ignored on MainNet.
- `--operator` is still untrusted free text. The access control is who can read `/etc/mandaterail/state-reconcile.env`, which is root 0600.

## Env
- `/etc/mandaterail/state-reconcile.env` (root:root 0600) holds DATABASE_URL (mr_reconcile), NETWORK and INDEXER_URL. See `deploy/state-reconcile.env.example`.
- `/etc/mandaterail/state-monitor.env` (root:root 0600) holds DATABASE_URL (mr_monitor), NETWORK, MONITOR_HEALTH_URLS and the optional pager settings. See `deploy/state-monitor.env.example`.
- systemd reads the file and injects it. The units set `STATE_ENV_FILE=/dev/null` so the app user never opens the root-only file.

## Timers
- `mandaterail-reconcile.timer` runs every 5 min. It calls `spend reconcile --store demo-api` and logs one JSON line to the journal (`journalctl -u mandaterail-reconcile`).
- `mandaterail-monitor.timer` runs every 5 min. It calls `spend monitor --older-than-min 30`, which GETs the 3 `/health` URLs and counts pending/ambiguous `mr_spend` rows older than 30 min.
  - Health results are keyed by URL (origin + path; no userinfo or query).
  - When everything is fine it prints a JSON line on stdout and exits 0.
  - On any alert (failed health check OR stale rows) it prints `ALERT {...}` on stderr and exits 2, so the unit shows as failed (R21-P3-1).
  - An empty or missing `MONITOR_HEALTH_URLS` is a config error (exit 1), never "healthy".
  - `journalctl -u mandaterail-monitor -g ALERT`
- Pager (R21-P3-1): if `MONITOR_PAGER_WEBHOOK_URL` is set (https; http only for loopback), every alert is POSTed there. `MONITOR_PAGER_FORMAT` = `json` (default, `{"text","alert"}`), `slack` (`{"text"}`) or `ntfy` (text/plain + Title/Priority/Tags). The URL is never printed; a failed POST logs `pager POST failed` and the run still exits 2.
- On the TestNet host the pager is **unset** until the owner picks a destination; each run logs `no pager configured`. A pager is a MainNet blocker.

## Indexer trust (R20-P3-2 / R20-P3-3)
- A 404 from the indexer counts toward "can never confirm" only after `/v2/blocks/0` returns the profile's genesis id and hash.
- `marginRounds` must be a non-negative integer.
- Each indexer request has a 10 s timeout.
- `release --force` is refused on MainNet. On TestNet it needs an explicit NETWORK and prints a loud WARNING to stderr.

## Indexer hardening (R21-P3-4 / R21-P3-5)
- The genesis check also guards the 200 ("settled") path: a wrong-network indexer can't mark a row settled.
- Only a genesis MATCH is cached; a failed, mismatched or unreadable check is retried next time.
- Null / malformed bodies (tx, genesis, health) give `unknown` / no proof. The confirmed round and the health round must be JSON integers.
- The no-proof error depends on NETWORK: MainNet says there is no override; TestNet mentions `--force`; with no explicit NETWORK it says --force needs NETWORK=testnet.

## Run-22 changes (schema v6)
- **R22-P3-1 settle/release split.** v6 drops `mr_spend_transition` and adds two SECURITY DEFINER functions (owner = audit table owner, `search_path = pg_catalog, pg_temp`, EXECUTE revoked from PUBLIC):
  - `mr_spend_settle` (EXECUTE: `mr_reconcile` only): pending/ambiguous -> settled (`chain-reconcile`), pending -> ambiguous (`chain-reconcile-expired`).
  - `mr_spend_release` (EXECUTE: `mr_release` only): pending/ambiguous -> released, actions `manual-release` (needs a pinned txId and a recorded proof) or `manual-release-forced`; operator label + 8-char reason required.
  - Neither takes a timestamp or an actor: `at_ms`/`updated_ms` come from `clock_timestamp()`, the audit actor is `session_user` followed by `(label, untrusted: <operator>)`.
  - Reconcile therefore **never releases**. A row the chain says can no longer confirm is marked ambiguous and reported as `needsRelease`; the monitor alerts on it (stale ambiguous), and an operator releases it with proof: `STATE_ENV_FILE=/etc/mandaterail/state-release.env pnpm --filter @mandaterail/storage spend -- release --id <id> --operator <name> --reason "..."`.
- **R22-P3-2 / R66-P3-1.** The role SQL revokes TEMPORARY on the database from PUBLIC and from the table owner (R66-P3-1: the owner no longer gets it back). It RAISEs if PUBLIC or any service role still has it.
- **R66-P3-1.** The table owner has no EXECUTE on `mr_v16_audit` and no UPDATE on `mr_pause_state`. The tamper cooldown base changes only through `SELECT mr_set_tamper_cooldown_base(<seconds>)` (owned by `mr_pause_writer`). The change must be the only one in the row, is refused while paused, and is written to `mr_config_audit`. The MainNet 6 h floor CHECK still applies.
- **R67-P3-1.** The DDL guard no longer matches GRANT text. On every GRANT/REVOKE outside the superuser window it recomputes `mr_v16_acl_fp()` (function, table and column ACLs plus owners of every protected object) and refuses the statement if the result differs from `mr_v16_acl_pin`, which this file writes at the end of its own window. Quoted names, DO/EXECUTE string concat and REVOKEs are therefore refused too; schema-wide grants stay refused.
- **R69-P3-2.** `ALTER DEFAULT PRIVILEGES` is refused outside the superuser window (owner and superuser), and `pg_default_acl` (every role, every schema) is part of the ACL drift hash (none expected). `mr_v16_acl_pin` has a DML guard (`mr_v16_acl_pin_guard`, row + TRUNCATE): only a superuser inside the window writes it. The monitor pages a missing pin, a pin that differs from `mr_v16_acl_fp()`, and a missing or disabled pin guard. Residual: a superuser in replica mode is still the trust root; the fingerprint page catches a rewritten pin.
- **R70-P3-2.** The value of `mr_v16_acl_fp()` for a host-shaped migrate + role SQL is pinned in `deploy/integrity-manifest.json` (`aclFp`, so in `INTEGRITY_MANIFEST_SHA256`). The monitor pages when the live fingerprint or the `mr_v16_acl_pin` row differs from it. A superuser (replica mode or a window) who changes a protected ACL and repins clears the R69 pin page but not this one; only a new release manifest (and an internal reviewer run) can move it. The superuser is still the trust root for everything the manifest does not pin.
- **R22-P3-3.** If the monitor itself fails (DB unreachable, unreadable env, ...), it prints `ALERT ... monitor self-failure: <error code>`, pages (if configured) and exits 2. Config errors still exit 1.
- **R22-P3-4.** Missing roles are created NOLOGIN; any of mr_reconcile/mr_monitor/mr_release left LOGIN without a password RAISEs and rolls back (pass `-v pw= -v mon_pw= -v rel_pw=` on first run). `MONITOR_HEALTH_URLS` entries must hold no secrets (they are logged and paged); URLs with `user:pass@` are rejected, and two URLs with the same origin+path are a config error.


## R23 (schema v7)

- **Rollout order (R23-P3-2), every deploy that migrates:**
  1. `systemctl disable --now mandaterail-reconcile.timer mandaterail-monitor.timer`
  2. backup (`systemctl start mandaterail-pgbackup`)
  3. migrate from the NEW release (`state-migrate.env`, must contain `NETWORK`; the first v7 run writes the `mr_network` marker)
  4. run the role SQL (`deploy/sql/t11-mr-reconcile-role.sql`, as postgres)
  5. deploy: relink `current`, restart the 3 services
  6. re-copy units, `systemctl enable --now` both timers, run each once by hand
  Between 3 and 5 the old app runs against the new schema; its direct status
  UPDATEs are refused by `mr_spend_guard` (fail closed: rows stay pending and
  counted). Keep that window short.
- **Settle (R23-P3-3):** `mr_spend_settle` requires the row's pinned, non-null txId; reconcile skips rows without one (`unknown`).
- **Release (R23-P2-1):** typed, DB-checked proof; forced release refused by the DB on a mainnet marker; credential off-host. See `release-two-person.md`.
- **App roles (R23-P3-1):** `mr_demo_api` changes status only through `mr_spend_app_finalize` (pending -> settled/ambiguous, or released while no txId is pinned; releases audited). Column UPDATE only on `tx_id, last_valid, updated_ms`. `mr_console` / `mr_bridge` have no spend rights. The `mr_spend_guard` trigger refuses any status change, identity-column change, re-pin, DELETE or TRUNCATE outside the SECURITY DEFINER functions (session flag AND current_user = table owner; the flag alone can be set by anyone).
- **Monitor (R23-P3-4):** alerts when a `needsRelease` row (ambiguous, last audit action `chain-reconcile-expired`) was flagged more than `MONITOR_NEEDS_RELEASE_MAX_MIN` minutes ago (default 60).

## R24 (schema v8)

- **Owner NOLOGIN (R24-P3-1).** The role SQL makes the table owner (`mr_owner`) NOLOGIN and keeps a LOGIN
  admin `mr_admin` (NOINHERIT; member of `mr_owner` with SET only, no INHERIT, no ADMIN). `state-migrate.env`:
  `MIGRATE_DATABASE_URL` = mr_admin and `MIGRATE_SET_ROLE=mr_owner`. Migrate/import do `SET ROLE mr_owner`, so
  every object stays owned by the owner, and migrate refuses if `mr_schema` is owned by anyone else. The first
  run needs `-v admin_pw=...`. mr_admin is a DBA credential: it can do anything the owner can (DISABLE TRIGGER
  included) after SET ROLE. Keep it in the root-only env file and nowhere else.
- **Deploy evidence (R24-P3-1).** The role SQL RAISEs (and rolls back) unless all six mr_* triggers exist with
  `tgenabled = O`, the marker is set, the owner is NOLOGIN, only mr_admin is a member of it, and app roles are
  NOINHERIT. It prints the trigger table, the marker, the schema version and the owner memberships. Save its
  output as `role-sql-<sha>.txt` on every deploy.
- **App inserts (R24-P3-2).** A non-owner INSERT into `mr_spend` must be `pending`, with NULL `tx_id`/`last_valid`
  and `created_ms` within ±5 min of the DB clock. `mr_spend_app_finalize(..., 'released', p_tx_id)` ignores `p_tx_id`.
  Only the owner (the JSON import, through mr_admin + SET ROLE) can insert `settled` rows.
- **Marker (R24-P3-3).** Before migrate writes `mr_network`, `verifyAlgodMatchesProfile` checks the algod genesis
  and the USDC ASA (`ALGOD_URL`/`ALGOD_TOKEN` optional; default public algonode). `NETWORK=mainnet` also needs
  `ALLOW_MAINNET=1`. An existing marker is never rewritten.
- **App roles NOINHERIT (R24-P3-4).** Re-applied on every run and verified.
- **Release (R24-P2-1).** Two observations; see `release-two-person.md` and `release-custody.md`.
- **Rollout order** is unchanged from R23. The v7 `mr_spend_release` signature is dropped, so v7 code can't release
  on v8 (it fails closed). Rollback = restore the pre-deploy backup.

## R25 (schema v9)

- **Deploy window for mr_admin (R25-P3-1).** mr_admin is a member of the owner ONLY while a deploy runs.
  The role SQL no longer grants that membership (it still revokes any other membership and RAISEs if the
  owner membership has INHERIT or ADMIN). `deploy/mr-admin-window.sh -- <command>` runs
  `deploy/sql/r25-admin-window.sql -v window=open` (GRANT ... WITH SET TRUE, INHERIT FALSE, ADMIN FALSE),
  then the command, then `window=close` from an EXIT trap: the REVOKE runs on success, on error and on
  INT/TERM, and the close checks that mr_admin is no longer a member. The command's exit code is kept; a
  failed close prints `ALERT` and exits 3. `MR_PSQL` overrides how psql reaches the DB (default
  `sudo -u postgres psql -p 5433 -d mandaterail`). Outside the window, `SET ROLE mr_owner` as mr_admin is
  "permission denied", so the mr_admin password alone is not enough to change the database.
- **Rollout order (R25), every deploy:**
  1. timers off (`systemctl disable --now mandaterail-reconcile.timer mandaterail-monitor.timer`)
  2. backup (`systemctl start mandaterail-pgbackup`)
  3. stage + `pnpm install --frozen-lockfile` in `releases/<sha>`
  4. `deploy/mr-admin-window.sh -- sh -c '<migrate from the NEW release> && <role SQL with -a > /root/role-sql-<sha>.txt>'`
  5. relink `current`, restart the 3 services
  6. re-copy units, timers on, run each once by hand (the monitor run must show the integrity checks passing)
- **Monitor integrity (R25-P3-1).** Every monitor run (as the read-only mr_monitor) reads `pg_trigger` for all
  `mr_*` tables, the `mr_network` marker and mr_admin's owner membership. It alerts (pager + exit 2) when any
  of the six expected triggers is missing, any `mr_*` trigger has `tgenabled` other than `O` (D = disabled,
  R/A = replica/always both count as wrong), the marker is missing or doesn't match `NETWORK`'s profile (name +
  genesis hash), or mr_admin is still a member of the owner outside a deploy. `NETWORK` is now required in
  `state-monitor.env`. If the integrity query itself fails, that's a monitor self-failure alert.
- **Import (R25-P3-2).** `import-json` runs the whole import in one transaction on one client:
  `BEGIN; SET LOCAL ROLE <MIGRATE_SET_ROLE>` is awaited, `current_user` is re-checked, and any failure aborts
  (rollback, exit 1). The old per-connection `SET ROLE` without await or error handling is gone.
- **Provider allowlist (R25-P2-1, partial).** See `release-custody.md`, "Provider allowlist".

## R26 (internal reviewer run 26)
- **Deploy window** (`deploy/mr-admin-window.sh`): a holder session takes advisory lock (26026, 1) for the whole window, so a second window refuses (exit 1) and touches nothing. Open refuses if *any* membership in the owner already exists (a leftover); `r25-admin-window.sql -v window=open` also refuses without a lock holder. On SIGINT/SIGTERM the wrapped command's own exit code is kept. If the script is SIGKILLed or crashes, the lock goes away within ~1 s while the membership stays; the monitor then reports `deploy window left open`. Fix: re-run the role SQL (it revokes every owner membership), or `-v window=close`.
- **Role SQL** revokes every membership in the owner (any role, whoever granted it, R26-P3-3) and prints `owner_members`, the prosrc md5 of every mr_* function and the provider-allowlist md5. Inside a window run it as the LAST step.
- **Monitor** alerts (page + exit 2) on: any member of the owner; a membership with no window-lock holder; drift of `mr_network_provider` against the network profiles (md5 of sorted `network|host|operator`), of any mr_* function body (prosrc md5, plus missing / unexpected functions) and of the ACLs (aclexplode of mr_* tables, columns, sequences and functions, owner written OWNER) against `deploy/integrity-manifest.json`. The manifest is regenerated with `MR_UPDATE_INTEGRITY_MANIFEST=1` on `src/r26-hardening.test.ts`, and that test fails whenever a fresh migrate + role SQL doesn't match it. `MONITOR_INTEGRITY_MANIFEST` overrides the path.
- **Provider hosts** (R26-P3-4): canonical = lower case, no trailing dot. Hex / decimal / octal / mixed IP forms (any numeric last label), IPv6, `.localhost`, `.invalid`, `.local`, `.internal`, `.home.arpa` are refused by `isForbiddenProviderHost` (TS) and `mr_provider_host_refused` (DB: table CHECK + `mr_spend_release`). Schema v10.
- **Release prover**: the allowlist is the network profile's only (a caller `allowlist` option throws). With the real fetch, each provider host is resolved once per proof; any private / loopback / link-local / CGNAT / ULA / mapped answer refuses the proof, and that observation's requests connect to the pinned IP (TLS still verifies the host name). `release --force` (TestNet only) never builds a proof, so a set PROOF2_URL can't break it.
- Rollout order unchanged: stage+install -> timers off -> backup -> window { migrate -> role SQL } -> relink + units + restart -> timers on.

## Run 27 (R27-P3-1 .. P3-5)
- **Pinned manifest (R27-P3-1).** `INTEGRITY_MANIFEST_MD5` in `packages/storage/src/monitor.ts` is the md5 of
  `deploy/integrity-manifest.json`; `r27-integrity.test.ts` fails unless they match. To change the schema / grants:
  run `MR_UPDATE_INTEGRITY_MANIFEST=1` with `r26-hardening.test.ts`, then update the constant. A missing, malformed or
  mismatching manifest pages and exits 2. `MONITOR_INTEGRITY_MANIFEST` is refused when `NETWORK=mainnet` or
  `NODE_ENV=production` (page + exit 2); elsewhere it still has to hash to the pinned md5.
- **Window lock holder (R27-P3-2).** Only a `postgres` session with `application_name = mr-admin-window` may hold advisory
  lock (26026,1). The monitor alerts on any other holder, and on a valid holder older than 30 min. To read other roles'
  sessions, `mr_monitor` is a member of `pg_read_all_stats` (INHERIT, no SET / ADMIN; read-only statistics views), granted and
  verified by the role SQL. `r25-admin-window.sql` refuses to open if any holder isn't the opener's own `mr-admin-window` session.
- **More drift (R27-P3-3).** The manifest also pins constraint definitions (`pg_get_constraintdef`), owners of every mr_*
  relation and function (the audit-table owner written OWNER), trigger definitions (+ function md5), and the flags and
  memberships of the roles the role SQL manages (R28-P3-3: limits + settings now pinned too; only app roles' LOGIN is host-specific).
- **IP checks (R27-P3-4).** `isNonPublicIp` uses ipaddr.js (MIT): anything not plain global unicast is refused, including
  6to4 2002::/16, Teredo 2001::/32, NAT64, ORCHID, IPv4-mapped / -compatible, and documentation ranges. A custom `fetchImpl` is refused
  unless `unsafeTestCustomFetch: true` (tests only, refused on mainnet, and refused with the real fetch).
- **Reconcile (R27-P3-5).** `indexerTxCheck` applies the same allowlist, forbidden-host check and DNS pinning (resolved once
  per reconcile run). `INDEXER_URL` must be on the network profile's provider allowlist.

## Run 28 (R28-P3-1 .. P3-3)
- **No stats role for the monitor (R28-P3-2).** `pg_read_all_stats` is revoked from `mr_monitor` (it has no role
  memberships at all; the role SQL verifies it). The monitor reads the deploy-window lock holders through
  `public.mr_window_lock_holders()`: created by the role SQL, owned by the superuser that runs it (`postgres` on the host),
  `SECURITY DEFINER`, `search_path = pg_catalog, pg_temp`, returning only `pid, usename, application_name, backend_start`
  of sessions holding (26026,1) in this database. EXECUTE is revoked from PUBLIC and granted to `mr_monitor` only. Its body,
  owner (written SUPERUSER in the manifest) and ACL are pinned. If `mr_monitor` loses EXECUTE, the integrity query fails
  and the monitor pages (fail closed).
- **Release pin (R28-P3-1, R29-P3-1, R29 optional).** Deploy order on the host: extract `git archive <commit>` into
  `releases/<sha>`, `pnpm install --frozen-lockfile` as `mandaterail`, then `chown -R root:root releases/<sha>` and
  `chmod -R go-w releases/<sha>` (root-owned and read-only for the app user, node_modules included; `/opt/mandaterail`,
  `releases/` and the `current` link are root-owned too). Then, as root on the host:
  `spend release-pin --dir releases/<sha> --commit <40-hex> --tree-sha256 <hash computed on the deploying machine from
  git archive>` prints `commit=`, `tree_sha256=` (every file except `node_modules` / `.git`; refused if it differs from
  the git-archive value), `deps_sha256=` (every `node_modules` tree, nested ones too, symlinks by target) and
  `manifest_sha256=` (must equal `INTEGRITY_MANIFEST_SHA256`; was md5 until 94f799e). The deploy writes it to
  `/etc/mandaterail/release-pin` (root:root 0644). Every monitor run opens the pin with `O_NOFOLLOW` and alerts (page +
  exit 2) if it is missing / a symlink / malformed (the old md5 format included) / not root-owned / group- or
  other-writable, if the running release isn't the pinned commit, if the manifest sha256 differs from the pin or the
  code pin, if the tree or the installed dependencies no longer hash to the pin, or if any path in the release (or an
  ancestor directory, sticky world-writable ones excepted) is not root-owned or is group/other writable. The monitor
  still runs as `mandaterail`, but from a root-owned read-only tree, so that user can't change the checker, its
  dependencies or the manifest. `MONITOR_RELEASE_PIN` (tests) is refused on mainnet / production.
  **Limits (no signing key):** whoever can write root-owned files on the host can rewrite the pin as well as the code;
  the commit + tree hash can be re-derived from git off the host (internal reviewer records the pin each run). The deps hash is
  computed on the host after install, so it pins "what was installed at deploy", not an off-host reference.
- **Role settings + limits (R28-P3-3).** Every managed role (mr_reconcile, mr_monitor, mr_release, mr_admin, mr_demo_api,
  mr_console, mr_bridge) and the table owner must have no settings, global (`rolconfig`) or per database
  (`pg_db_role_setting`); the role SQL clears them (`RESET ALL`, and `IN DATABASE ... RESET ALL` for each) and verifies.
  Connection limits are pinned: app roles 40, owner 40, mr_reconcile 4, mr_monitor / mr_release / mr_admin 2. Any
  setting or limit change is role drift. Only the app roles' LOGIN stays host-specific.
- **Database-wide settings (R29-P3-2).** `ALTER DATABASE <db> SET`, `ALTER ROLE ALL IN DATABASE <db> SET` (setrole 0,
  this database) and `ALTER ROLE ALL SET` (setrole 0, setdatabase 0) must be empty. The role SQL pins its own session
  (`SET LOCAL search_path / statement_timeout / lock_timeout`), resets them (printing key names only) and verifies; any
  such row is role drift for the monitor.
