-- T11 / R21-P3-2 / R21-P3-3 / R22-P3-1/2/4: non-owner service roles for the
-- reconcile, release and monitor paths. IDEMPOTENT: re-run after every deploy.
-- Run as a superuser (postgres) against the mandaterail DB, AFTER migrations (v7+):
--   sudo -u postgres psql -p 5433 -d mandaterail -v ON_ERROR_STOP=1 \
--        [-v pw=<reconcile pw>] [-v mon_pw=<monitor pw>] [-v rel_pw=<release pw>] [-v admin_pw=<migrate admin pw>] -f t11-mr-reconcile-role.sql
-- R24 (v8+): makes the table owner NOLOGIN, (re)creates the LOGIN migrate admin mr_admin
-- (NOINHERIT, SET ROLE to the owner only), sets NOINHERIT on the app roles, and
-- RAISEs unless every mr_* trigger is enabled (tgenabled = O) and the marker is set.
-- Passwords come in via -v so they never land in this file or in git; omit
-- them on a re-run to keep the current passwords. R22-P3-4: a role that ends
-- up LOGIN without a password (e.g. first run without -v) RAISEs and the whole
-- run rolls back.
--
-- mr_reconcile: SELECT on mr_spend / mr_spend_audit / mr_schema, EXECUTE on
--   mr_spend_settle only (pending/ambiguous -> settled, pending -> ambiguous).
--   It can NEVER release a reservation (R22-P3-1).
-- mr_release:   SELECT on the same tables, EXECUTE on mr_spend_release only
--   (operator release with a recorded chain proof or a FORCED reason). Used by
--   `spend release` via /etc/mandaterail/state-release.env; not used by timers.
-- mr_monitor:   read-only (SELECT on mr_spend, mr_schema, mr_spend_audit, mr_network, mr_network_provider)
--   + EXECUTE on mr_window_lock_holders() (R28-P3-2); no role memberships.
-- R25-P3-1: mr_admin is a member of the owner ONLY during deploys (deploy/mr-admin-window.sh).
-- R23-P3-1 app roles (LOGIN/password untouched; created NOLOGIN only if missing):
--   mr_demo_api: SELECT/INSERT mr_spend, UPDATE (tx_id, last_valid, updated_ms) only,
--                EXECUTE mr_spend_app_finalize; SELECT/INSERT mr_receipts.
--   mr_console:  SELECT/INSERT/UPDATE mr_mandates.   mr_bridge: SELECT/INSERT/UPDATE/DELETE mr_queue.
--   All: SELECT mr_schema. No app role can write mr_spend_audit or call settle/release.
-- R23: the mr_release password should NOT be stored on the host
-- (docs/ops/release-two-person.md); pass rel_pw only when rotating it.
-- The final SELECTs print the evidence: role flags, every grant of every
-- service/app role, and each mr_* function's owner, ACL and search_path.
-- Both definer functions set the audit timestamp (clock_timestamp) and the
-- actor (session_user) themselves and accept only whitelisted actions.
-- No service role may own mr_spend_audit or be a member of its owner (a table
-- owner can ALTER TABLE ... DISABLE TRIGGER). The last block RAISEs if so.
-- R22-P3-2: TEMPORARY on this database is revoked from PUBLIC; R66-P3-1: and from the
-- table owner (mr_owner); no role needs temp tables.
-- R63-P2-1: this superuser run may alter the protected v16 objects (mr_v16_ddl_guard event trigger, below)
SET mr.ddl_window = 'open';
\set ON_ERROR_STOP on
-- One transaction: a failed verification rolls back every change above it.
BEGIN;
-- R29-P3-2: do not inherit search_path / timeouts from ALTER DATABASE or ALTER ROLE ALL settings (reset below).
SET LOCAL search_path = pg_catalog, public;
SET LOCAL statement_timeout = 0;
SET LOCAL lock_timeout = 0;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'mr_spend_app_finalize') OR NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'mr_network')
     OR NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'mr_network_provider') OR NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'mr_provider_host_refused') THEN
    RAISE EXCEPTION 'mr_spend_app_finalize / mr_network / mr_network_provider / mr_provider_host_refused not found; run migrations (schema v10) first';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM mr_schema WHERE version = 10) THEN
    RAISE EXCEPTION 'schema v10 not applied; run migrations first';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'mr_spend_release') OR NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'mr_spend_settle') THEN
    RAISE EXCEPTION 'mr_spend_settle / mr_spend_release not found; run migrations (schema v7) first';
  END IF;
  -- R22-P3-4: create missing roles NOLOGIN; LOGIN is granted below only together with a password check.
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mr_reconcile') THEN CREATE ROLE mr_reconcile NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mr_monitor') THEN CREATE ROLE mr_monitor NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mr_release') THEN CREATE ROLE mr_release NOLOGIN; END IF;
  -- R23-P3-1: app roles. Created NOLOGIN if missing (fresh/test DBs); on the
  -- host they already exist and their LOGIN / password are left untouched.
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mr_demo_api') THEN CREATE ROLE mr_demo_api NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mr_console') THEN CREATE ROLE mr_console NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mr_bridge') THEN CREATE ROLE mr_bridge NOLOGIN; END IF;
END $$;
-- R28-P3-3: app roles' connection limit is pinned (40) and their settings are cleared (no search_path etc.).
ALTER ROLE mr_demo_api WITH NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 40; -- R24-P3-4 NOINHERIT
ALTER ROLE mr_console  WITH NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 40; -- R24-P3-4 NOINHERIT
ALTER ROLE mr_bridge   WITH NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 40; -- R24-P3-4 NOINHERIT
ALTER ROLE mr_demo_api RESET ALL;
ALTER ROLE mr_console RESET ALL;
ALTER ROLE mr_bridge RESET ALL;

-- R21-P3-3: always (re)apply the safety flags, not only on first create.
ALTER ROLE mr_reconcile WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 4;
ALTER ROLE mr_monitor   WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2;
ALTER ROLE mr_release   WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2;
ALTER ROLE mr_reconcile RESET ALL;
ALTER ROLE mr_monitor RESET ALL;
ALTER ROLE mr_release RESET ALL;
\if :{?pw}
ALTER ROLE mr_reconcile WITH PASSWORD :'pw';
\endif
\if :{?mon_pw}
ALTER ROLE mr_monitor WITH PASSWORD :'mon_pw';
\endif
\if :{?rel_pw}
ALTER ROLE mr_release WITH PASSWORD :'rel_pw';
\endif

-- R24-P3-1: the table owner is NOLOGIN; migrations run as the LOGIN admin
-- role mr_admin, which is NOINHERIT and may only SET ROLE to the owner
-- (MIGRATE_SET_ROLE=mr_owner in state-migrate.env). Applied when the owner is a
-- non-superuser (the host); skipped with a NOTICE when a superuser owns the
-- tables (throwaway test clusters).
-- (A service role owning the table is not touched here; the verification below RAISEs on it.)
SELECT NOT r.rolsuper AND r.rolname NOT IN ('mr_reconcile', 'mr_monitor', 'mr_release', 'mr_demo_api', 'mr_console', 'mr_bridge', 'mr_admin', 'mr_pause_writer') AS owner_is_plain
  FROM pg_tables t JOIN pg_roles r ON r.rolname = t.tableowner
 WHERE t.schemaname = 'public' AND t.tablename = 'mr_spend_audit' \gset
\if :owner_is_plain
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mr_admin') THEN CREATE ROLE mr_admin NOLOGIN; END IF;
END $$;
ALTER ROLE mr_admin WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2;
ALTER ROLE mr_admin RESET ALL;
\if :{?admin_pw}
ALTER ROLE mr_admin WITH PASSWORD :'admin_pw';
\endif
DO $$ DECLARE o text; r record; BEGIN
  SELECT tableowner INTO o FROM pg_tables WHERE schemaname = 'public' AND tablename = 'mr_spend_audit';
  -- mr_admin: member of the owner only (SET, no INHERIT); nothing else.
  FOR r IN SELECT g.rolname AS grp, gr.rolname AS grantor FROM pg_auth_members am JOIN pg_roles g ON g.oid = am.roleid
             JOIN pg_roles gr ON gr.oid = am.grantor JOIN pg_roles m ON m.oid = am.member
            WHERE m.rolname = 'mr_admin' AND g.rolname <> o LOOP
    EXECUTE format('REVOKE %I FROM mr_admin GRANTED BY %I CASCADE', r.grp, r.grantor);
  END LOOP;
  -- R25-P3-1: the owner membership is NOT granted here. It exists only inside a
  -- deploy window (deploy/mr-admin-window.sh: GRANT at the start, REVOKE at the
  -- end, even on error). If present it must be SET-only (checked below).
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO mr_admin', current_database());
  EXECUTE format('ALTER ROLE %I WITH NOLOGIN', o);
  -- R28-P3-3: the owner's connection limit is pinned (40) and its settings are cleared.
  EXECUTE format('ALTER ROLE %I CONNECTION LIMIT 40', o);
  EXECUTE format('ALTER ROLE %I RESET ALL', o);
END $$;
-- R26-P3-3: revoke EVERY membership in the owner (a leftover v8 standing grant to
-- mr_admin, a window left open by a crash, or any other role), whoever granted it.
-- Inside a deploy window this also ends mr_admin's membership early, so run the
-- role SQL as the LAST step of the window (the close then finds nothing to revoke).
DO $$ DECLARE o text; r record; BEGIN
  SELECT tableowner INTO o FROM pg_tables WHERE schemaname = 'public' AND tablename = 'mr_spend_audit';
  FOR r IN SELECT m.rolname AS mem, gr.rolname AS grantor FROM pg_auth_members am JOIN pg_roles g ON g.oid = am.roleid
             JOIN pg_roles m ON m.oid = am.member JOIN pg_roles gr ON gr.oid = am.grantor WHERE g.rolname = o LOOP
    RAISE NOTICE 'R26-P3-3: revoking leftover membership of % in % (granted by %)', r.mem, o, r.grantor;
    EXECUTE format('REVOKE %I FROM %I GRANTED BY %I CASCADE', o, r.mem, r.grantor);
  END LOOP;
  IF EXISTS (SELECT 1 FROM pg_auth_members WHERE roleid = (SELECT oid FROM pg_roles WHERE rolname = o)) THEN
    RAISE EXCEPTION 'R26-P3-3: % still has members after the revoke', o;
  END IF;
END $$;
\else
DO $$ BEGIN RAISE NOTICE 'R24-P3-1: tables are owned by a superuser (test cluster); owner NOLOGIN / mr_admin skipped'; END $$;
\endif

-- R22-P3-4: a LOGIN role without a password is an error (rolls back everything).
DO $$ DECLARE r text; BEGIN
  FOR r IN SELECT rolname FROM pg_authid WHERE rolname IN ('mr_reconcile', 'mr_monitor', 'mr_release', 'mr_admin') AND rolcanlogin AND rolpassword IS NULL ORDER BY rolname LOOP
    RAISE EXCEPTION '% would be LOGIN with no password; pass -v pw= / mon_pw= / rel_pw= / admin_pw= on the first run', r;
  END LOOP;
END $$;

-- Revoke every role membership in either direction (member of X, or X member of us).
DO $$ DECLARE r record; BEGIN
  FOR r IN
    SELECT g.rolname AS grp, m.rolname AS mem, gr.rolname AS grantor
      FROM pg_auth_members am
      JOIN pg_roles g ON g.oid = am.roleid
      JOIN pg_roles m ON m.oid = am.member
      JOIN pg_roles gr ON gr.oid = am.grantor
     WHERE m.rolname IN ('mr_reconcile', 'mr_monitor', 'mr_release', 'mr_demo_api', 'mr_console', 'mr_bridge') OR g.rolname IN ('mr_reconcile', 'mr_monitor', 'mr_release', 'mr_demo_api', 'mr_console', 'mr_bridge')
  LOOP
    EXECUTE format('REVOKE %I FROM %I GRANTED BY %I CASCADE', r.grp, r.mem, r.grantor);
  END LOOP;
END $$;

-- Start from zero privileges in the schema, then grant exactly what is needed.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM mr_reconcile, mr_monitor, mr_release, mr_demo_api, mr_console, mr_bridge;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM mr_reconcile, mr_monitor, mr_release, mr_demo_api, mr_console, mr_bridge;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM mr_reconcile, mr_monitor, mr_release, mr_demo_api, mr_console, mr_bridge;
REVOKE CREATE ON SCHEMA public FROM mr_reconcile, mr_monitor, mr_release, mr_demo_api, mr_console, mr_bridge;
DO $$ DECLARE o text; BEGIN
  SELECT tableowner INTO o FROM pg_tables WHERE schemaname = 'public' AND tablename = 'mr_spend_audit';
  IF o IS NULL THEN RAISE EXCEPTION 'mr_spend_audit not found; run migrations first'; END IF;
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO mr_reconcile, mr_monitor, mr_release, mr_demo_api, mr_console, mr_bridge', current_database());
  EXECUTE format('REVOKE CREATE, TEMPORARY ON DATABASE %I FROM mr_reconcile, mr_monitor, mr_release, mr_demo_api, mr_console, mr_bridge', current_database());
  -- R22-P3-2: the per-role revoke is meaningless while PUBLIC holds TEMPORARY.
  EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
  -- R66-P3-1: and from the table owner too (it needs no temp objects; a temp schema is a shadowing surface)
  EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM %I', current_database(), o);
END $$;
GRANT USAGE ON SCHEMA public TO mr_reconcile, mr_monitor, mr_release, mr_demo_api, mr_console, mr_bridge;
GRANT SELECT ON mr_schema, mr_spend, mr_spend_audit, mr_network, mr_network_provider TO mr_reconcile, mr_monitor, mr_release;

-- R23-P3-1: app roles get the minimum their STATE_BACKEND=redis+postgres code
-- uses (challenges + rate limits live in Redis). No app role can UPDATE
-- mr_spend.status, write mr_spend_audit, or call settle/release; the
-- mr_spend_guard trigger also refuses any status change made outside the
-- SECURITY DEFINER functions.
GRANT SELECT ON mr_schema TO mr_demo_api, mr_console, mr_bridge;
GRANT SELECT, INSERT, UPDATE, DELETE ON mr_queue TO mr_bridge;
GRANT USAGE ON SEQUENCE mr_queue_seq_seq TO mr_bridge;
GRANT SELECT, INSERT, UPDATE ON mr_mandates TO mr_console;
GRANT USAGE ON SEQUENCE mr_mandates_seq_seq TO mr_console;
GRANT SELECT, INSERT ON mr_receipts TO mr_demo_api;
GRANT USAGE ON SEQUENCE mr_receipts_seq_seq TO mr_demo_api;
GRANT SELECT, INSERT ON mr_spend TO mr_demo_api;
GRANT UPDATE (tx_id, last_valid, updated_ms) ON mr_spend TO mr_demo_api;

-- Definer functions belong to the audit table's owner (mr_owner on the host).
REVOKE ALL ON FUNCTION mr_spend_settle(text, text, text[], text, text, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION mr_spend_release(text, text, text, text, text, text, bigint, integer, text, text, text, bigint, integer, text, text, text, bigint, integer) FROM PUBLIC;
DO $$ DECLARE o text; BEGIN
  SELECT tableowner INTO o FROM pg_tables WHERE schemaname = 'public' AND tablename = 'mr_spend_audit';
  EXECUTE format('ALTER FUNCTION mr_spend_settle(text, text, text[], text, text, text, text, text) OWNER TO %I', o);
  EXECUTE format('ALTER FUNCTION mr_spend_release(text, text, text, text, text, text, bigint, integer, text, text, text, bigint, integer, text, text, text, bigint, integer) OWNER TO %I', o);
END $$;
GRANT EXECUTE ON FUNCTION mr_spend_settle(text, text, text[], text, text, text, text, text) TO mr_reconcile;
GRANT EXECUTE ON FUNCTION mr_spend_release(text, text, text, text, text, text, bigint, integer, text, text, text, bigint, integer, text, text, text, bigint, integer) TO mr_release;
REVOKE ALL ON FUNCTION mr_spend_app_finalize(text, text, text, text) FROM PUBLIC;
DO $$ DECLARE o text; BEGIN
  SELECT tableowner INTO o FROM pg_tables WHERE schemaname = 'public' AND tablename = 'mr_spend_audit';
  EXECUTE format('ALTER FUNCTION mr_spend_app_finalize(text, text, text, text) OWNER TO %I', o);
END $$;
GRANT EXECUTE ON FUNCTION mr_spend_app_finalize(text, text, text, text) TO mr_demo_api;

-- v11 (attested-release-signer, docs/ops/attested-release-signer.md §3): the app may write the
-- app-derived signed_txn / submit fields once (mr_spend_signed_guard enforces write-once);
-- mr_release may only call the attested release; the verifier, JCS and revoke are owner-only.
DO $$ DECLARE o text; f text; BEGIN
  IF to_regprocedure('mr_spend_release_attested(text, text, bytea, bytea, text, text)') IS NULL THEN
    RAISE NOTICE 'v11 not applied; attested-release grants skipped'; RETURN;
  END IF;
  SELECT tableowner INTO o FROM pg_tables WHERE schemaname = 'public' AND tablename = 'mr_spend_audit';
  FOREACH f IN ARRAY ARRAY['mr_spend_release_attested(text, text, bytea, bytea, text, text)', 'mr_signer_revoke(text, text)',
                           'mr_jcs(jsonb)', 'mr_signer_tables_guard()', 'mr_spend_signed_guard()', 'mr_spend_pending_signed_to_ambiguous(text, bigint)'] LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    EXECUTE format('ALTER FUNCTION %s OWNER TO %I', f, o);
  END LOOP;
  EXECUTE 'GRANT EXECUTE ON FUNCTION mr_spend_release_attested(text, text, bytea, bytea, text, text) TO mr_release';
  EXECUTE 'GRANT EXECUTE ON FUNCTION mr_spend_pending_signed_to_ambiguous(text, bigint) TO mr_reconcile';
  EXECUTE format('GRANT EXECUTE ON FUNCTION mr_crypto.mr_ed25519_verify(bytea, bytea, bytea) TO %I', o);
  EXECUTE 'GRANT SELECT ON mr_signer_key, mr_signer_operator, mr_release_nonce TO mr_release, mr_monitor';
  EXECUTE 'GRANT UPDATE (signed_txn, signed_txn_kind, first_valid, group_id, sender, submit_round, submit_at) ON mr_spend TO mr_demo_api';
END $$;

-- v12 (attested-release-cosign, §15): mr_release calls only the two entry points; the v11 verifier is internal.
DO $$ DECLARE o text; f text; BEGIN
  IF to_regprocedure('mr_spend_release_attested(text, text, bytea, bytea, bytea, bytea, text, text)') IS NULL THEN
    RAISE NOTICE 'v12 not applied; co-sign grants skipped'; RETURN;
  END IF;
  SELECT tableowner INTO o FROM pg_tables WHERE schemaname = 'public' AND tablename = 'mr_spend_audit';
  FOREACH f IN ARRAY ARRAY['mr_spend_release_attested(text, text, bytea, bytea, bytea, bytea, text, text)',
                           'mr_spend_release_attested_v11(text, text, bytea, bytea, text, text)', 'mr_v12_guard()'] LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    EXECUTE format('ALTER FUNCTION %s OWNER TO %I', f, o);
  END LOOP;
  EXECUTE 'REVOKE ALL ON FUNCTION mr_spend_release_attested_v11(text, text, bytea, bytea, text, text) FROM mr_release';
  EXECUTE 'GRANT EXECUTE ON FUNCTION mr_spend_release_attested(text, text, bytea, bytea, bytea, bytea, text, text) TO mr_release';
  EXECUTE 'GRANT SELECT ON mr_cosigner_key, mr_release_quorum, mr_release_cosign TO mr_release, mr_monitor';
END $$;

-- v16 (automatic resume + DB caps, §23): detectors may record a tamper pause; only the 2-of-2 resume lifts it;
-- caps / cooldown base are owner-only (redeploy) and audited. No role can unpause by hand.
-- R62-P2-1: mr_tamper_pause / mr_tamper_resume are owned by the NOLOGIN, member-less role mr_pause_writer; the guard
-- trigger authorizes pause-state / pause-log / nonce writes on current_user = mr_pause_writer (no GUC). The table owner
-- can neither SET ROLE to it nor replace the two functions.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mr_pause_writer') THEN CREATE ROLE mr_pause_writer NOLOGIN; END IF;
END $$;
ALTER ROLE mr_pause_writer WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 0;
DO $$ DECLARE m record; BEGIN
  FOR m IN SELECT r.rolname FROM pg_auth_members am JOIN pg_roles r ON r.oid = am.member WHERE am.roleid = 'mr_pause_writer'::regrole AND NOT r.rolsuper LOOP
    EXECUTE format('REVOKE mr_pause_writer FROM %I CASCADE', m.rolname);
  END LOOP;
  FOR m IN SELECT r.rolname FROM pg_auth_members am JOIN pg_roles r ON r.oid = am.roleid WHERE am.member = 'mr_pause_writer'::regrole LOOP
    EXECUTE format('REVOKE %I FROM mr_pause_writer CASCADE', m.rolname);
  END LOOP;
END $$;
DO $$ DECLARE o text; f text; BEGIN
  IF to_regprocedure('mr_tamper_resume(bytea, bytea, bytea, bytea)') IS NULL THEN
    RAISE NOTICE 'v16 not applied; resume grants skipped'; RETURN;
  END IF;
  SELECT tableowner INTO o FROM pg_tables WHERE schemaname = 'public' AND tablename = 'mr_spend_audit';
  -- R63-P2-1: mr_pause_writer (NOLOGIN, member-less) owns the pause tables, the two pause functions and every helper
  -- they run (guard / parse / cooldown / mr_jcs). The app owner (also inside a deploy window) can't ALTER, DISABLE
  -- TRIGGER on, replace or drop any of them. It keeps only what it needs:
  -- SELECT, EXECUTE on mr_jcs (its v11/v12 functions call it) and on mr_set_tamper_cooldown_base (R66-P3-1).
  -- R64-P2-1: also the caps / audit tables, the caps-enforcing 8-arg release wrapper, the co-sign check it calls
  -- (_v12) and the table _v12 writes (mr_release_cosign), so the app owner can't DISABLE TRIGGER / UPDATE caps /
  -- wipe the audit / replace the wrapper. A caps change is a superuser migration (SET ROLE mr_pause_writer, window open).
  FOREACH f IN ARRAY ARRAY['mr_tamper_pause(text)', 'mr_tamper_resume(bytea, bytea, bytea, bytea)', 'mr_v16_guard()', 'mr_v16_parse(bytea, text, text[])',
                           'mr_v16_cooldown(integer, integer)', 'mr_jcs(jsonb)', 'mr_v16_audit(text, text, jsonb, jsonb)',
                           'mr_spend_release_attested(text, text, bytea, bytea, bytea, bytea, text, text)',
                           'mr_spend_release_attested(text, text, bytea, bytea, text, text)', 'mr_v16_nonce_ledger()',
                           'mr_spend_release_attested_v12(text, text, bytea, bytea, bytea, bytea, text, text)', 'mr_set_tamper_cooldown_base(integer)'] LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    EXECUTE format('ALTER FUNCTION %s OWNER TO mr_pause_writer', f);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO mr_pause_writer', f); -- its owner's own grant (kept on re-runs)
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I', f, o); -- R66-P3-1: re-granted below only where needed
  END LOOP;
  FOREACH f IN ARRAY ARRAY['mr_pause_state', 'mr_resume_nonce', 'mr_pause_log', 'mr_release_caps', 'mr_config_audit', 'mr_release_cosign', 'mr_release_ledger'] LOOP
    EXECUTE format('ALTER TABLE %I OWNER TO mr_pause_writer', f);
    EXECUTE format('REVOKE ALL ON %I FROM %I', f, o);
    EXECUTE format('GRANT SELECT ON %I TO %I', f, o);
  END LOOP;
  -- R66-P3-1: no UPDATE (base_cooldown_s) and no EXECUTE on mr_v16_audit for the owner; the cooldown base changes only
  -- through the writer-owned setter (alone, unpaused, audited by the guard as mr_pause_writer)
  EXECUTE format('GRANT EXECUTE ON FUNCTION mr_jcs(jsonb), mr_v16_cooldown(integer, integer), mr_set_tamper_cooldown_base(integer) TO %I', o);
  -- R64-P2-1: what the wrapper (caps, rolling sum, lock) and _v12 (keys, quorum, providers, then _v11) read as mr_pause_writer
  EXECUTE 'GRANT SELECT ON mr_spend, mr_release_nonce, mr_network_provider, mr_release_quorum, mr_signer_operator TO mr_pause_writer';
  -- _v12 row-locks the co-signer key (SELECT ... FOR SHARE needs an UPDATE grant); mr_v12_guard still refuses any UPDATE by a non-owner
  EXECUTE 'GRANT UPDATE (revoked_at) ON mr_cosigner_key TO mr_pause_writer'; -- LOCK ... SHARE ROW EXCLUSIVE (the nonce guard still refuses its writes)
  EXECUTE 'GRANT EXECUTE ON FUNCTION mr_spend_release_attested_v11(text, text, bytea, bytea, text, text) TO mr_pause_writer';
  EXECUTE 'GRANT SELECT ON mr_network, mr_signer_key, mr_cosigner_key TO mr_pause_writer';
  EXECUTE 'GRANT EXECUTE ON FUNCTION mr_v16_parse(bytea, text, text[]), mr_v16_cooldown(integer, integer), mr_jcs(jsonb) TO mr_pause_writer';
  EXECUTE 'GRANT USAGE ON SCHEMA mr_crypto TO mr_pause_writer';
  EXECUTE 'GRANT EXECUTE ON FUNCTION mr_crypto.mr_ed25519_verify(bytea, bytea, bytea) TO mr_pause_writer';
  EXECUTE 'REVOKE ALL ON FUNCTION mr_spend_release_attested_v12(text, text, bytea, bytea, bytea, bytea, text, text) FROM mr_release';
  EXECUTE 'GRANT EXECUTE ON FUNCTION mr_tamper_pause(text) TO mr_release, mr_reconcile, mr_monitor';
  EXECUTE 'GRANT EXECUTE ON FUNCTION mr_tamper_resume(bytea, bytea, bytea, bytea) TO mr_release';
  EXECUTE 'GRANT EXECUTE ON FUNCTION mr_v16_cooldown(integer, integer) TO mr_release, mr_reconcile, mr_monitor'; -- pure interval math, read-only status
  EXECUTE 'GRANT SELECT ON mr_pause_state, mr_release_caps, mr_config_audit, mr_pause_log, mr_resume_nonce, mr_release_ledger TO mr_release, mr_monitor';
  -- R65-P3: the 6-arg TestNet entry (quorum 1) is a definer wrapper of the 8-arg one: same owner, so it can call it
  EXECUTE 'GRANT EXECUTE ON FUNCTION mr_spend_release_attested(text, text, bytea, bytea, text, text) TO mr_release';
  EXECUTE 'GRANT SELECT ON mr_signer_key, mr_cosigner_key TO mr_monitor';
END $$;

-- R63-P2-1 (belt and braces): a superuser-owned event trigger refuses DDL on the protected v16 objects (ALTER /
-- DISABLE TRIGGER / CREATE OR REPLACE / DROP / re-own) from anyone but a superuser run of this file. The monitor pages
-- if it is missing or disabled, and re-verifies every stored resume signature against the pinned keys, so even a
-- superuser forging an unpause (session_replication_role, DISABLE TRIGGER) is paged, not silent.
-- R67-P3-1: GRANT/REVOKE are checked against the ACL itself, not the statement text (a quoted name or a DO/EXECUTE
-- string concat evaded the text match). mr_v16_acl_fp() fingerprints the function, table and column ACLs of every
-- protected object (R71-P3-2: NULL = '-' (default privileges) and '{}' (empty ACL) stay distinct; R70-P3-2: aclitems sorted, so a re-run that reorders the same grants keeps the value); this file pins it in mr_v16_acl_pin (superuser-owned) at the end of its window, and the guard
-- refuses (rolls back) any GRANT/REVOKE outside the window that leaves the fingerprint different from the pin.
CREATE OR REPLACE FUNCTION public.mr_v16_acl_fp() RETURNS text LANGUAGE sql STABLE SET search_path = pg_catalog AS $fp$
  WITH n(names) AS (SELECT ARRAY['mr_pause_state','mr_resume_nonce','mr_pause_log','mr_tamper_pause','mr_tamper_resume','mr_v16_guard',
    'mr_v16_parse','mr_v16_cooldown','mr_jcs','mr_release_caps','mr_config_audit','mr_release_cosign','mr_v16_audit',
    'mr_spend_release_attested','mr_spend_release_attested_v12','mr_release_ledger','mr_release_nonce','mr_v16_nonce_ledger',
    'mr_spend_release_attested_v11','mr_signer_tables_guard','mr_set_tamper_cooldown_base','mr_v16_acl_pin','mr_v16_acl_fp','mr_v16_acl_pin_guard']::name[])
  SELECT md5(coalesce(string_agg(x, E'\n' ORDER BY x COLLATE "C"), '')) FROM (
    SELECT 'f:' || p.oid::regprocedure::text || '=' || CASE WHEN p.proacl IS NULL THEN '-' ELSE '{' || coalesce((SELECT string_agg(i::text, ',' ORDER BY i::text COLLATE "C") FROM unnest(p.proacl) i), '') || '}' END || '@' || pg_get_userbyid(p.proowner) AS x
      FROM pg_proc p, n WHERE p.pronamespace = 'public'::regnamespace AND p.proname = ANY(n.names)
    UNION ALL
    SELECT 'r:' || c.relname || '=' || CASE WHEN c.relacl IS NULL THEN '-' ELSE '{' || coalesce((SELECT string_agg(i::text, ',' ORDER BY i::text COLLATE "C") FROM unnest(c.relacl) i), '') || '}' END || '@' || pg_get_userbyid(c.relowner)
      FROM pg_class c, n WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p', 'v', 'S') AND c.relname = ANY(n.names)
    UNION ALL
    SELECT 'a:' || c.relname || '.' || a.attname || '=' || '{' || coalesce((SELECT string_agg(i::text, ',' ORDER BY i::text COLLATE "C") FROM unnest(a.attacl) i), '') || '}'
      FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid, n
     WHERE c.relnamespace = 'public'::regnamespace AND c.relname = ANY(n.names) AND a.attacl IS NOT NULL AND NOT a.attisdropped
  ) q
$fp$;
GRANT EXECUTE ON FUNCTION public.mr_v16_acl_fp() TO PUBLIC; -- the event trigger runs as the invoker; catalogs are world-readable anyway
CREATE TABLE IF NOT EXISTS public.mr_v16_acl_pin (id boolean PRIMARY KEY DEFAULT true CHECK (id), fp text NOT NULL, pinned_at timestamptz NOT NULL DEFAULT now());
REVOKE ALL ON public.mr_v16_acl_pin FROM PUBLIC;
GRANT SELECT ON public.mr_v16_acl_pin TO PUBLIC; -- not secret; superuser-owned, so only a superuser run of this file writes it
-- R69-P3-2: DML guard on the pin: only a superuser run inside this file's window may write it (a superuser outside
-- the window, or anyone who got a grant, is refused); TRUNCATE too. The monitor pages a missing / disabled guard,
-- a missing pin, and a pin that differs from mr_v16_acl_fp().
CREATE OR REPLACE FUNCTION public.mr_v16_acl_pin_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $pg$
BEGIN
  IF NOT (current_setting('is_superuser') = 'on' AND coalesce(current_setting('mr.ddl_window', true), '') = 'open') THEN
    RAISE EXCEPTION 'mr_v16_acl_pin_guard: % on mr_v16_acl_pin refused outside the superuser deploy window', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END $pg$;
REVOKE ALL ON FUNCTION public.mr_v16_acl_pin_guard() FROM PUBLIC;
DROP TRIGGER IF EXISTS mr_v16_acl_pin_guard ON public.mr_v16_acl_pin;
DROP TRIGGER IF EXISTS mr_v16_acl_pin_guard_t ON public.mr_v16_acl_pin;
CREATE TRIGGER mr_v16_acl_pin_guard BEFORE INSERT OR UPDATE OR DELETE ON public.mr_v16_acl_pin FOR EACH ROW EXECUTE FUNCTION public.mr_v16_acl_pin_guard();
CREATE TRIGGER mr_v16_acl_pin_guard_t BEFORE TRUNCATE ON public.mr_v16_acl_pin FOR EACH STATEMENT EXECUTE FUNCTION public.mr_v16_acl_pin_guard();
-- (plain ENABLE, like every mr_* trigger: a superuser in replica mode is the known trust root; the monitor pages a
-- pin that no longer matches mr_v16_acl_fp())

CREATE OR REPLACE FUNCTION mr_v16_ddl_guard() RETURNS event_trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $fn$
DECLARE r record; open boolean := current_setting('is_superuser') = 'on' AND coalesce(current_setting('mr.ddl_window', true), '') = 'open';
  pin text; fp text;
  pat CONSTANT text := '(^|[ .])(mr_pause_state|mr_resume_nonce|mr_pause_log|mr_tamper_pause|mr_tamper_resume|mr_v16_guard|mr_v16_parse|mr_v16_cooldown|mr_jcs'
                       '|mr_release_caps|mr_config_audit|mr_release_cosign|mr_v16_audit|mr_spend_release_attested|mr_spend_release_attested_v12'
                       '|mr_release_ledger|mr_release_nonce|mr_v16_nonce_ledger|mr_spend_release_attested_v11|mr_signer_tables_guard'
                       '|mr_set_tamper_cooldown_base|mr_v16_acl_pin|mr_v16_acl_fp|mr_v16_acl_pin_guard)([ (]|$)'; -- R64/R65-P2-1, R66-P3-1, R67-P3-1, R69-P3-2
BEGIN
  IF open THEN RETURN; END IF;
  IF TG_EVENT = 'sql_drop' THEN
    FOR r IN SELECT object_identity FROM pg_event_trigger_dropped_objects() LOOP
      IF r.object_identity ~ pat THEN RAISE EXCEPTION 'mr_v16_ddl_guard: % of % refused (protected pause object)', TG_TAG, r.object_identity USING ERRCODE = 'insufficient_privilege'; END IF;
    END LOOP;
  ELSE
    -- R69-P3-2: default privileges would grant on FUTURE objects (e.g. mr_release=X on owner-created functions):
    -- refused for everyone, superuser included, outside the window
    IF TG_TAG = 'ALTER DEFAULT PRIVILEGES' THEN
      RAISE EXCEPTION 'mr_v16_ddl_guard: ALTER DEFAULT PRIVILEGES refused outside the superuser deploy window' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF TG_TAG IN ('GRANT', 'REVOKE') THEN
      -- R67-P3-1: the authority is the ACL, not the text: any GRANT/REVOKE that changes a protected object's ACL is
      -- refused (the statement rolls back), however it was spelled (quoted names, DO/EXECUTE concat, IN SCHEMA)
      SELECT p.fp INTO pin FROM public.mr_v16_acl_pin p WHERE p.id;
      fp := public.mr_v16_acl_fp();
      IF pin IS NULL OR fp IS DISTINCT FROM pin THEN
        RAISE EXCEPTION 'mr_v16_ddl_guard: % changes the ACL of a protected pause object (or the ACL pin is missing); refused', TG_TAG USING ERRCODE = 'insufficient_privilege';
      END IF;
      -- run 66 belt and braces: a schema-wide grant is refused even if it touched nothing protected
      IF current_query() ~* '\mIN\s+SCHEMA\M' THEN
        RAISE EXCEPTION 'mr_v16_ddl_guard: schema-wide GRANT/REVOKE refused' USING ERRCODE = 'insufficient_privilege';
      END IF;
    END IF;
    FOR r IN SELECT object_identity FROM pg_event_trigger_ddl_commands() LOOP
      IF r.object_identity ~ pat THEN RAISE EXCEPTION 'mr_v16_ddl_guard: % on % refused (protected pause object)', TG_TAG, r.object_identity USING ERRCODE = 'insufficient_privilege'; END IF;
    END LOOP;
  END IF;
END $fn$;
REVOKE ALL ON FUNCTION mr_v16_ddl_guard() FROM PUBLIC;
DROP EVENT TRIGGER IF EXISTS mr_v16_ddl_guard;
DROP EVENT TRIGGER IF EXISTS mr_v16_ddl_guard_drop;
CREATE EVENT TRIGGER mr_v16_ddl_guard ON ddl_command_end EXECUTE FUNCTION mr_v16_ddl_guard();
CREATE EVENT TRIGGER mr_v16_ddl_guard_drop ON sql_drop EXECUTE FUNCTION mr_v16_ddl_guard();

-- R28-P3-3: no per-database settings (ALTER ROLE ... IN DATABASE ... SET) on any managed role or the owner.
DO $$ DECLARE o text; r record; BEGIN
  SELECT tableowner INTO o FROM pg_tables WHERE schemaname = 'public' AND tablename = 'mr_spend_audit';
  FOR r IN SELECT g.rolname AS rol, d.datname AS db FROM pg_db_role_setting s JOIN pg_roles g ON g.oid = s.setrole JOIN pg_database d ON d.oid = s.setdatabase
            WHERE g.rolname IN ('mr_reconcile', 'mr_monitor', 'mr_release', 'mr_demo_api', 'mr_console', 'mr_bridge', 'mr_admin', 'mr_pause_writer')
               OR (g.rolname = o AND NOT g.rolsuper) LOOP
    RAISE NOTICE 'R28-P3-3: clearing per-database settings of % in %', r.rol, r.db;
    EXECUTE format('ALTER ROLE %I IN DATABASE %I RESET ALL', r.rol, r.db);
  END LOOP;
END $$;

-- R29-P3-2: no database-wide settings (ALTER DATABASE <this db> SET / ALTER ROLE ALL IN
-- DATABASE <this db> SET: setrole 0, setdatabase this db) and no cluster-wide ones
-- (ALTER ROLE ALL SET: setrole 0, setdatabase 0). Values are not printed, only key names.
DO $$ DECLARE r record; BEGIN
  FOR r IN SELECT s.setdatabase, (SELECT string_agg(split_part(c, '=', 1), ',') FROM unnest(s.setconfig) c) AS keys
             FROM pg_db_role_setting s
            WHERE s.setrole = 0 AND (s.setdatabase = 0 OR s.setdatabase = (SELECT oid FROM pg_database WHERE datname = current_database())) LOOP
    IF r.setdatabase = 0 THEN
      RAISE NOTICE 'R29-P3-2: clearing ALTER ROLE ALL settings (keys: %)', r.keys;
      ALTER ROLE ALL RESET ALL;
    ELSE
      RAISE NOTICE 'R29-P3-2: clearing ALTER DATABASE % settings (keys: %)', current_database(), r.keys;
      EXECUTE format('ALTER DATABASE %I RESET ALL', current_database());
    END IF;
  END LOOP;
END $$;

-- R28-P3-2: mr_monitor has NO role memberships (pg_read_all_stats is revoked above with
-- every other membership). It reads the deploy-window lock holders only through this
-- SECURITY DEFINER function, owned by the superuser running this file (postgres on the
-- host), fixed search_path, returning only pid / usename / application_name /
-- backend_start (no query text). EXECUTE: mr_monitor only. Dropped + re-created on every
-- run so its owner, body and ACL are always this file's.
DROP FUNCTION IF EXISTS public.mr_window_lock_holders();
CREATE FUNCTION public.mr_window_lock_holders()
  RETURNS TABLE (pid integer, usename text, application_name text, backend_start timestamptz)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $fn$
  SELECT l.pid, a.usename::text, a.application_name, a.backend_start
    FROM pg_catalog.pg_locks l LEFT JOIN pg_catalog.pg_stat_activity a ON a.pid = l.pid
   WHERE l.locktype = 'advisory' AND l.granted AND l.classid = 26026 AND l.objid = 1 AND l.objsubid = 2
     AND l.database = (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname = pg_catalog.current_database())
$fn$;
REVOKE ALL ON FUNCTION public.mr_window_lock_holders() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.mr_window_lock_holders() TO mr_monitor;

-- Hard verification. Fails the run (ON_ERROR_STOP) instead of just reporting.
DO $$ DECLARE o text; r text;
  settle_fn text := 'mr_spend_settle(text, text, text[], text, text, text, text, text)';
  release_fn text := 'mr_spend_release(text, text, text, text, text, text, bigint, integer, text, text, text, bigint, integer, text, text, text, bigint, integer)';
  fin_fn text := 'mr_spend_app_finalize(text, text, text, text)';
BEGIN
  SELECT tableowner INTO o FROM pg_tables WHERE schemaname = 'public' AND tablename = 'mr_spend_audit';
  FOREACH r IN ARRAY ARRAY['mr_reconcile', 'mr_monitor', 'mr_release'] LOOP
    IF o = r THEN RAISE EXCEPTION '% owns mr_spend_audit', r; END IF;
    IF pg_has_role(r, o, 'MEMBER') THEN RAISE EXCEPTION '% is a member of the audit table owner %', r, o; END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mr_owner') AND pg_has_role(r, 'mr_owner', 'MEMBER') THEN
      RAISE EXCEPTION '% is a member of mr_owner', r;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolbypassrls OR rolinherit OR rolreplication)) THEN
      RAISE EXCEPTION '% has an unsafe role flag', r;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_auth_members am JOIN pg_roles m ON m.oid = am.member WHERE m.rolname = r) THEN -- R28-P3-2: no stats grant either
      RAISE EXCEPTION '% still has role memberships', r;
    END IF;
    IF has_table_privilege(r, 'public.mr_spend', 'INSERT,UPDATE,DELETE,TRUNCATE')
       OR has_table_privilege(r, 'public.mr_spend_audit', 'INSERT,UPDATE,DELETE,TRUNCATE')
       OR has_any_column_privilege(r, 'public.mr_spend', 'INSERT,UPDATE')
       OR has_any_column_privilege(r, 'public.mr_spend_audit', 'INSERT,UPDATE') THEN
      RAISE EXCEPTION '% can write mr_spend / mr_spend_audit directly', r;
    END IF;
    IF has_database_privilege(r, current_database(), 'TEMPORARY') OR has_database_privilege(r, current_database(), 'CREATE') THEN
      RAISE EXCEPTION '% has TEMPORARY or CREATE on the database', r;
    END IF;
  END LOOP;
  IF has_function_privilege('mr_reconcile', release_fn, 'EXECUTE') THEN RAISE EXCEPTION 'mr_reconcile can execute mr_spend_release'; END IF;
  IF has_function_privilege('mr_monitor', release_fn, 'EXECUTE') OR has_function_privilege('mr_monitor', settle_fn, 'EXECUTE') THEN
    RAISE EXCEPTION 'mr_monitor can execute a spend function';
  END IF;
  IF has_function_privilege('mr_release', settle_fn, 'EXECUTE') THEN RAISE EXCEPTION 'mr_release can execute mr_spend_settle'; END IF;
  -- R23-P3-1: app roles
  FOREACH r IN ARRAY ARRAY['mr_demo_api', 'mr_console', 'mr_bridge'] LOOP
    IF o = r OR pg_has_role(r, o, 'MEMBER') THEN RAISE EXCEPTION '% owns or is a member of the audit table owner %', r, o; END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolbypassrls OR rolreplication)) THEN
      RAISE EXCEPTION '% has an unsafe role flag', r;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_auth_members am JOIN pg_roles m ON m.oid = am.member WHERE m.rolname = r) THEN
      RAISE EXCEPTION '% still has role memberships', r;
    END IF;
    IF has_column_privilege(r, 'public.mr_spend', 'status', 'UPDATE') OR has_table_privilege(r, 'public.mr_spend', 'DELETE,TRUNCATE')
       OR has_table_privilege(r, 'public.mr_spend_audit', 'INSERT,UPDATE,DELETE,TRUNCATE') OR has_any_column_privilege(r, 'public.mr_spend_audit', 'INSERT,UPDATE')
       OR has_table_privilege(r, 'public.mr_network', 'INSERT,UPDATE,DELETE,TRUNCATE')
       OR has_table_privilege(r, 'public.mr_network_provider', 'INSERT,UPDATE,DELETE,TRUNCATE') THEN
      RAISE EXCEPTION '% can change mr_spend status / write mr_spend_audit or mr_network directly', r;
    END IF;
    IF has_function_privilege(r, settle_fn, 'EXECUTE') OR has_function_privilege(r, release_fn, 'EXECUTE') THEN
      RAISE EXCEPTION '% can execute mr_spend_settle / mr_spend_release', r;
    END IF;
    IF r <> 'mr_demo_api' AND (has_function_privilege(r, fin_fn, 'EXECUTE') OR has_table_privilege(r, 'public.mr_spend', 'INSERT') OR has_any_column_privilege(r, 'public.mr_spend', 'UPDATE')) THEN
      RAISE EXCEPTION '% has spend rights it does not need', r;
    END IF;
    IF has_database_privilege(r, current_database(), 'TEMPORARY') OR has_database_privilege(r, current_database(), 'CREATE') THEN
      RAISE EXCEPTION '% has TEMPORARY or CREATE on the database', r;
    END IF;
  END LOOP;
  FOREACH r IN ARRAY ARRAY['mr_reconcile', 'mr_monitor', 'mr_release'] LOOP
    IF has_function_privilege(r, fin_fn, 'EXECUTE') THEN RAISE EXCEPTION '% can execute mr_spend_app_finalize', r; END IF;
  END LOOP;
  -- R28-P3-2: mr_window_lock_holders(): superuser-owned SECURITY DEFINER, fixed search_path, EXECUTE for mr_monitor only.
  IF NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_roles ow ON ow.oid = p.proowner
                  WHERE p.oid = 'public.mr_window_lock_holders()'::regprocedure AND ow.rolsuper AND p.prosecdef
                    AND p.proconfig = ARRAY['search_path=pg_catalog, pg_temp']) THEN
    RAISE EXCEPTION 'mr_window_lock_holders() must be superuser-owned, SECURITY DEFINER, search_path=pg_catalog, pg_temp';
  END IF;
  IF NOT has_function_privilege('mr_monitor', 'public.mr_window_lock_holders()', 'EXECUTE') THEN RAISE EXCEPTION 'mr_monitor cannot execute mr_window_lock_holders()'; END IF;
  IF EXISTS (SELECT 1 FROM aclexplode((SELECT proacl FROM pg_proc WHERE oid = 'public.mr_window_lock_holders()'::regprocedure)) x
              WHERE x.grantee <> (SELECT proowner FROM pg_proc WHERE oid = 'public.mr_window_lock_holders()'::regprocedure) AND x.grantee <> 'mr_monitor'::regrole) THEN
    RAISE EXCEPTION 'mr_window_lock_holders() is granted to someone other than mr_monitor';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_auth_members am WHERE am.member = 'mr_monitor'::regrole) THEN RAISE EXCEPTION 'mr_monitor must have no role memberships (R28-P3-2)'; END IF;
  -- R28-P3-3: pinned connection limits, no settings at all (global or per-database).
  IF EXISTS (SELECT 1 FROM pg_roles WHERE (rolname IN ('mr_demo_api', 'mr_console', 'mr_bridge') AND rolconnlimit <> 40)
                                       OR (rolname = 'mr_reconcile' AND rolconnlimit <> 4) OR (rolname IN ('mr_monitor', 'mr_release', 'mr_admin') AND rolconnlimit <> 2)
                                       OR (rolname = o AND NOT rolsuper AND rolconnlimit <> 40)) THEN
    RAISE EXCEPTION 'a managed role has an unexpected connection limit';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_db_role_setting s JOIN pg_roles g ON g.oid = s.setrole
              WHERE g.rolname IN ('mr_reconcile', 'mr_monitor', 'mr_release', 'mr_demo_api', 'mr_console', 'mr_bridge', 'mr_admin', 'mr_pause_writer') OR (g.rolname = o AND NOT g.rolsuper)) THEN
    RAISE EXCEPTION 'a managed role still has settings (rolconfig / per-database)';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_db_role_setting s WHERE s.setrole = 0 AND (s.setdatabase = 0 OR s.setdatabase = (SELECT oid FROM pg_database WHERE datname = current_database()))) THEN
    RAISE EXCEPTION 'database-wide or ALTER ROLE ALL settings remain (R29-P3-2)';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public.mr_network) THEN RAISE EXCEPTION 'mr_network marker is not set; migrate with NETWORK'; END IF;
  -- R24-P3-4: app roles NOINHERIT
  FOREACH r IN ARRAY ARRAY['mr_demo_api', 'mr_console', 'mr_bridge'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r AND rolinherit) THEN RAISE EXCEPTION '% is INHERIT (must be NOINHERIT)', r; END IF;
  END LOOP;
  -- R24-P3-1: a plain (non-superuser) owner must be NOLOGIN, and only mr_admin (SET, no INHERIT) may be a member of it.
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = o AND NOT rolsuper) THEN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = o AND rolcanlogin) THEN RAISE EXCEPTION 'table owner % can still LOGIN', o; END IF;
    IF EXISTS (SELECT 1 FROM pg_auth_members am JOIN pg_roles g ON g.oid = am.roleid JOIN pg_roles m ON m.oid = am.member
                WHERE g.rolname = o AND (m.rolname <> 'mr_admin' OR am.inherit_option OR am.admin_option) AND NOT m.rolsuper) THEN
      RAISE EXCEPTION 'only mr_admin (SET, no INHERIT, no ADMIN) may be a member of %', o;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mr_admin' AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolbypassrls OR rolinherit OR rolreplication)) THEN
      RAISE EXCEPTION 'mr_admin has an unsafe role flag';
    END IF;
  END IF;
  -- R24-P3-1: every expected trigger exists and is enabled (tgenabled = O).
  FOR r IN SELECT x FROM unnest(ARRAY['mr_spend_audit.mr_spend_audit_no_update', 'mr_spend_audit.mr_spend_audit_no_truncate',
                                      'mr_spend.mr_spend_guard_row', 'mr_spend.mr_spend_guard_truncate',
                                      'mr_network.mr_network_no_change', 'mr_network.mr_network_no_truncate']) x LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_trigger t WHERE NOT t.tgisinternal AND t.tgrelid::regclass::text || '.' || t.tgname = r AND t.tgenabled = 'O') THEN
      RAISE EXCEPTION 'trigger % is missing or not enabled (tgenabled must be O)', r;
    END IF;
  END LOOP;
  IF EXISTS (SELECT 1 FROM pg_trigger t WHERE NOT t.tgisinternal AND t.tgrelid::regclass::text LIKE 'mr\_%' AND t.tgenabled <> 'O') THEN
    RAISE EXCEPTION 'an mr_* trigger is not enabled (tgenabled <> O)';
  END IF;
  IF EXISTS (SELECT 1 FROM aclexplode((SELECT datacl FROM pg_database WHERE datname = current_database())) a
              WHERE a.grantee = 0 AND a.privilege_type = 'TEMPORARY') THEN
    RAISE EXCEPTION 'PUBLIC still holds TEMPORARY on %', current_database();
  END IF;
END $$;

SELECT rolname, rolcanlogin AS login, rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolinherit, rolreplication, rolconnlimit,
       (SELECT coalesce(string_agg(g.rolname, ','), '(none)') FROM pg_auth_members am JOIN pg_roles g ON g.oid = am.roleid WHERE am.member = r.oid) AS member_of,
       has_function_privilege(rolname, 'mr_spend_settle(text, text, text[], text, text, text, text, text)', 'EXECUTE') AS can_settle,
       has_function_privilege(rolname, 'mr_spend_release(text, text, text, text, text, text, bigint, integer, text, text, text, bigint, integer, text, text, text, bigint, integer)', 'EXECUTE') AS can_release,
       has_function_privilege(rolname, 'mr_spend_app_finalize(text, text, text, text)', 'EXECUTE') AS can_app_finalize,
       has_database_privilege(rolname, current_database(), 'TEMPORARY') AS can_temp
  FROM pg_roles r WHERE rolname IN ('mr_reconcile', 'mr_monitor', 'mr_release', 'mr_demo_api', 'mr_console', 'mr_bridge', 'mr_owner', 'mr_admin') ORDER BY rolname;
-- R24-P3-1 evidence: who can become the owner, and how.
SELECT g.rolname AS role, m.rolname AS member, am.set_option, am.inherit_option, am.admin_option
  FROM pg_auth_members am JOIN pg_roles g ON g.oid = am.roleid JOIN pg_roles m ON m.oid = am.member
 WHERE g.rolname IN ('mr_owner', 'mr_admin') OR m.rolname IN ('mr_owner', 'mr_admin') ORDER BY 1, 2;
-- Evidence (R23 ask): every table/column/sequence grant held by the service + app roles.
SELECT grantee, table_name, string_agg(privilege_type, ',' ORDER BY privilege_type) AS table_privs
  FROM information_schema.role_table_grants
 WHERE table_schema = 'public' AND grantee IN ('mr_reconcile', 'mr_monitor', 'mr_release', 'mr_demo_api', 'mr_console', 'mr_bridge')
 GROUP BY grantee, table_name ORDER BY grantee, table_name;
SELECT grantee, table_name, column_name, privilege_type
  FROM information_schema.column_privileges
 WHERE table_schema = 'public' AND grantee IN ('mr_reconcile', 'mr_monitor', 'mr_release', 'mr_demo_api', 'mr_console', 'mr_bridge')
   AND NOT EXISTS (SELECT 1 FROM information_schema.role_table_grants t WHERE t.grantee = column_privileges.grantee
                   AND t.table_name = column_privileges.table_name AND t.privilege_type = column_privileges.privilege_type AND t.table_schema = 'public')
 ORDER BY grantee, table_name, column_name, privilege_type;
SELECT c.relname AS sequence, coalesce(c.relacl::text, '(default)') AS acl
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind = 'S' ORDER BY 1;
SELECT c.relname AS table_name, pg_get_userbyid(c.relowner) AS owner, coalesce(c.relacl::text, '(default)') AS acl
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind = 'r' ORDER BY 1;
-- Evidence: each mr_* function's owner, ACL, SECURITY DEFINER flag and search_path.
SELECT p.oid::regprocedure::text AS function, pg_get_userbyid(p.proowner) AS owner, p.prosecdef AS security_definer,
       coalesce(p.proacl::text, '(default: PUBLIC EXECUTE)') AS acl, coalesce(array_to_string(p.proconfig, ' '), '(none)') AS config
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public' AND p.proname LIKE 'mr\_%' ORDER BY 1;
-- R28-P3-2 / R28-P3-3 evidence
SELECT p.oid::regprocedure::text AS function, pg_get_userbyid(p.proowner) AS owner, ow.rolsuper AS owner_is_superuser, p.prosecdef, array_to_string(p.proconfig, ' ') AS config, p.proacl::text AS acl
  FROM pg_proc p JOIN pg_roles ow ON ow.oid = p.proowner WHERE p.oid = 'public.mr_window_lock_holders()'::regprocedure;
SELECT r.rolname, r.rolconnlimit, coalesce((SELECT string_agg(coalesce(d.datname::text, '*') || ':' || array_to_string(s.setconfig, ','), ';') FROM pg_db_role_setting s LEFT JOIN pg_database d ON d.oid = s.setdatabase WHERE s.setrole = r.oid), '(none)') AS settings,
       (SELECT count(*) FROM pg_auth_members am WHERE am.member = r.oid) AS memberships
  FROM pg_roles r WHERE r.rolname IN ('mr_reconcile', 'mr_monitor', 'mr_release', 'mr_demo_api', 'mr_console', 'mr_bridge', 'mr_owner', 'mr_admin') ORDER BY 1;
-- R29-P3-2 evidence: must be 0
SELECT count(*) AS db_and_all_role_settings FROM pg_db_role_setting s
 WHERE s.setrole = 0 AND (s.setdatabase = 0 OR s.setdatabase = (SELECT oid FROM pg_database WHERE datname = current_database()));
SELECT tgrelid::regclass::text AS table_name, tgname, tgenabled FROM pg_trigger WHERE NOT tgisinternal AND tgrelid::regclass::text LIKE 'mr\_%' ORDER BY 1, 2;
SELECT network, genesis_hash, set_at FROM mr_network;
-- R25-P2-1 evidence: the provider allowlist the DB enforces for release proofs.
SELECT network, host, operator_id FROM mr_network_provider ORDER BY 1, 3, 2;
-- R26-P3-2 evidence: members of the owner (empty), and the drift fingerprints the monitor compares
-- (prosrc md5 per mr_* function; provider allowlist md5; deploy/integrity-manifest.json holds the expected values).
SELECT coalesce(string_agg(m.rolname, ', ' ORDER BY m.rolname), '(none)') AS owner_members
  FROM pg_auth_members am JOIN pg_roles m ON m.oid = am.member
 WHERE am.roleid = (SELECT relowner FROM pg_class WHERE relname = 'mr_spend_audit' AND relnamespace = 'public'::regnamespace);
SELECT p.oid::regprocedure::text AS function, md5(p.prosrc) AS prosrc_md5
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public' AND p.proname LIKE 'mr\_%' ORDER BY 1;
SELECT md5(coalesce(string_agg(network || '|' || host || '|' || operator_id, E'\n' ORDER BY network || '|' || host || '|' || operator_id COLLATE "C"), '')) AS provider_allowlist_md5, count(*) AS providers FROM mr_network_provider;
SELECT max(version) AS schema_version FROM mr_schema;
SELECT current_database() AS db, (SELECT datacl FROM pg_database WHERE datname = current_database())::text AS db_acl;
-- R67-P3-1: pin the protected-object ACL fingerprint (inside this file's DDL window, after every grant above)
INSERT INTO public.mr_v16_acl_pin (id, fp) VALUES (true, public.mr_v16_acl_fp()) ON CONFLICT (id) DO UPDATE SET fp = EXCLUDED.fp, pinned_at = now();
SELECT fp AS acl_pin_fp FROM public.mr_v16_acl_pin;
COMMIT;
