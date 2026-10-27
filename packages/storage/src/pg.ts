/**
 * Postgres shared-state backends (Phase 2 T3). One schema, namespaced rows,
 * so several services / processes can share one database.
 *
 * Atomicity:
 * - challenge consume: `UPDATE ... SET used = true WHERE used = false` —
 *   only one statement across all processes can flip a nonce.
 * - everything with a cap or a count (challenge issue, rate limits, queue
 *   insert, mandate create) runs in a transaction holding a
 *   `pg_advisory_xact_lock` for its namespace, so check-then-insert can't
 *   race between processes.
 * - queue finalize: compare-and-set from `pending`.
 * Time comes from the caller (`now` ms); hosts must be NTP-synced.
 * Internal AI review (eng hygiene).
 */
import type { Pool, PoolClient } from "pg";
import { MAINNET_PROFILE, networkProfile, TESTNET_PROFILE, isForbiddenProviderHost, verifyAlgodMatchesProfile, type NetworkProfile } from "@mandaterail/core";
import { v11Sql } from "./v11-attested.js";
import { v12Sql } from "./v12-cosign.js";
import { v16Sql } from "./v16-resume.js";
import { v17Sql } from "./v17-delta.js";
import { deriveSignedTxn, SignedTxnError, type DerivedTxn, type SignedTxnKind } from "./signed-txn.js";
import { IntentMandateSchema, type IntentMandate } from "@mandaterail/schema";
import {
  CHALLENGE_SWEEP_GRACE_MS,
  DEFAULT_CHALLENGE_TTL_MS,
  MandateExistsError,
  newOperatorChallenge,
  StoreFullError,
  type ChallengeConsumeResult,
  type ChallengeStore,
  type MandateStore,
  type OperatorAction,
  type OperatorChallenge,
  type QueueFinalizeResult,
  type QueueInsertResult,
  type QueueItem,
  type QueueLimits,
  type QueueStatus,
  type QueueStore,
  type RateLimitStore,
  type ReceiptLike,
  toMicro,
  utcDayStartMs,
  type SpendCaps,
  type SpendReservation,
  type SpendStatus,
  type SpendStore,
  type ReserveResult,
  type ReceiptStore,
  type StoredMandate,
} from "@mandaterail/core";

/**
 * ST-P3-4: versioned migrations. Each runs once, in order, inside one
 * transaction holding the migrate advisory lock; mr_schema records applied
 * versions. A database newer than this code refuses to start.
 * Never edit a released migration — append a new one.
 */
/** R25-P2-1: SQL VALUES rows for the profiles' provider allowlists (static constants, validated). */
function providerSeedSql(): string {
  const rows: string[] = [];
  for (const p of [TESTNET_PROFILE, MAINNET_PROFILE]) {
    for (const e of p.providerAllowlist) {
      if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(e.host) || isForbiddenProviderHost(e.host) || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(e.operator)) {
        throw new Error(`bad provider allowlist entry ${e.host}`);
      }
      rows.push(`  ('${p.name}', '${e.host}', '${e.operator}')`);
    }
  }
  return rows.join(",\n");
}

export const MIGRATIONS: ReadonlyArray<{ version: number; name: string; sql: string }> = [
  { version: 1, name: "phase2-core-tables", sql: `
CREATE TABLE IF NOT EXISTS mr_challenges (
  audience   text    NOT NULL,
  nonce      text    NOT NULL,
  challenge  jsonb   NOT NULL,
  expires_ms bigint  NOT NULL,
  used       boolean NOT NULL DEFAULT false,
  PRIMARY KEY (audience, nonce)
);
CREATE INDEX IF NOT EXISTS mr_challenges_exp ON mr_challenges (audience, expires_ms);
CREATE TABLE IF NOT EXISTS mr_rate_events (
  seq     bigserial PRIMARY KEY,
  limiter text   NOT NULL,
  key     text   NOT NULL,
  ts_ms   bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS mr_rate_events_lim ON mr_rate_events (limiter, ts_ms);
CREATE INDEX IF NOT EXISTS mr_rate_events_key ON mr_rate_events (limiter, key, ts_ms);
CREATE TABLE IF NOT EXISTS mr_queue (
  queue        text    NOT NULL,
  id           text    NOT NULL,
  seq          bigserial,
  status       text    NOT NULL,
  created_at   text    NOT NULL,
  created_ms   bigint  NOT NULL,
  finalized_ms bigint,
  client_key   text    NOT NULL,
  collected    boolean NOT NULL DEFAULT false,
  request      jsonb   NOT NULL,
  token_hash   bytea   NOT NULL,
  signature    text,
  public_key   text,
  address      text,
  PRIMARY KEY (queue, id)
);
CREATE INDEX IF NOT EXISTS mr_queue_status ON mr_queue (queue, status, client_key);
CREATE TABLE IF NOT EXISTS mr_mandates (
  store           text    NOT NULL,
  id              text    NOT NULL,
  seq             bigserial,
  mandate         jsonb   NOT NULL,
  server_verified boolean NOT NULL DEFAULT false,
  verified_at     text,
  PRIMARY KEY (store, id)
);
CREATE TABLE IF NOT EXISTS mr_receipts (
  store      text  NOT NULL,
  receipt_id text  NOT NULL,
  seq        bigserial,
  receipt    jsonb NOT NULL,
  PRIMARY KEY (store, receipt_id)
);
` },
  {
    version: 2,
    name: "t7-spend-reservations",
    sql: `
CREATE TABLE IF NOT EXISTS mr_spend (
  store        text   NOT NULL,
  id           text   NOT NULL,
  payer        text   NOT NULL,
  amount_micro bigint NOT NULL CHECK (amount_micro > 0),
  status       text   NOT NULL CHECK (status IN ('pending','settled','ambiguous','released')),
  created_ms   bigint NOT NULL,
  updated_ms   bigint NOT NULL,
  tx_id        text,
  PRIMARY KEY (store, id)
);
CREATE INDEX IF NOT EXISTS mr_spend_payer ON mr_spend (store, payer, created_ms);
CREATE INDEX IF NOT EXISTS mr_spend_unresolved ON mr_spend (store, status, created_ms) WHERE status IN ('pending','ambiguous');
`,
  },
  {
    version: 3,
    name: "r18-spend-last-valid-and-audit",
    sql: `
ALTER TABLE mr_spend ADD COLUMN IF NOT EXISTS last_valid bigint;
CREATE TABLE IF NOT EXISTS mr_spend_audit (
  seq         bigserial PRIMARY KEY,
  store       text   NOT NULL,
  id          text   NOT NULL,
  at_ms       bigint NOT NULL,
  actor       text   NOT NULL,
  action      text   NOT NULL,
  from_status text   NOT NULL,
  to_status   text   NOT NULL,
  reason      text   NOT NULL
);
CREATE INDEX IF NOT EXISTS mr_spend_audit_id ON mr_spend_audit (store, id);
`,
  },
  {
    // R19-P3-1: the audit log is append-only. A trigger rejects UPDATE,
    // DELETE and TRUNCATE for every role (including the owner), and
    // UPDATE/DELETE/TRUNCATE are revoked from PUBLIC. Service roles should be
    // granted only SELECT, INSERT (and USAGE on the seq sequence).
    version: 4,
    name: "r19-spend-audit-append-only",
    sql: `
CREATE OR REPLACE FUNCTION mr_spend_audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'mr_spend_audit is append-only (% refused)', TG_OP USING ERRCODE = 'insufficient_privilege';
END $$;
DROP TRIGGER IF EXISTS mr_spend_audit_no_update ON mr_spend_audit;
CREATE TRIGGER mr_spend_audit_no_update BEFORE UPDATE OR DELETE ON mr_spend_audit
  FOR EACH ROW EXECUTE FUNCTION mr_spend_audit_append_only();
DROP TRIGGER IF EXISTS mr_spend_audit_no_truncate ON mr_spend_audit;
CREATE TRIGGER mr_spend_audit_no_truncate BEFORE TRUNCATE ON mr_spend_audit
  FOR EACH STATEMENT EXECUTE FUNCTION mr_spend_audit_append_only();
REVOKE UPDATE, DELETE, TRUNCATE ON mr_spend_audit FROM PUBLIC;
`,
  },
  {
    // R21-P3-2: the only write path for spend status changes by service roles.
    // SECURITY DEFINER (runs as the owner, i.e. mr_owner on the host) with a
    // fixed search_path and schema-qualified names. It changes ONLY status +
    // updated_ms, only pending/ambiguous -> settled/released, and writes the
    // audit row in the same statement. EXECUTE is revoked from PUBLIC; the
    // role SQL grants it to mr_reconcile.
    version: 5,
    name: "r21-spend-transition-definer",
    sql: `
CREATE OR REPLACE FUNCTION mr_spend_transition(
  p_store text, p_id text, p_from text[], p_to text, p_actor text, p_action text,
  p_reason text, p_now_ms bigint, p_expect_tx_id text, p_check_tx boolean)
RETURNS TABLE (ok boolean, from_status text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE cur_status text; cur_tx text;
BEGIN
  IF p_to IS NULL OR p_to NOT IN ('settled', 'released') THEN
    RAISE EXCEPTION 'mr_spend_transition: target status % not allowed', p_to USING ERRCODE = 'check_violation';
  END IF;
  IF p_from IS NULL OR NOT (p_from <@ ARRAY['pending', 'ambiguous']::text[]) THEN
    RAISE EXCEPTION 'mr_spend_transition: source statuses must be pending/ambiguous' USING ERRCODE = 'check_violation';
  END IF;
  IF coalesce(btrim(p_actor), '') = '' OR coalesce(btrim(p_action), '') = '' OR coalesce(btrim(p_reason), '') = '' THEN
    RAISE EXCEPTION 'mr_spend_transition: actor, action and reason are required' USING ERRCODE = 'check_violation';
  END IF;
  SELECT s.status, s.tx_id INTO cur_status, cur_tx FROM public.mr_spend s
   WHERE s.store = p_store AND s.id = p_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT false, NULL::text; RETURN;
  END IF;
  IF NOT (cur_status = ANY (p_from)) OR (p_check_tx AND cur_tx IS DISTINCT FROM p_expect_tx_id) THEN
    RETURN QUERY SELECT false, cur_status; RETURN;
  END IF;
  UPDATE public.mr_spend SET status = p_to, updated_ms = p_now_ms WHERE store = p_store AND id = p_id;
  INSERT INTO public.mr_spend_audit (store, id, at_ms, actor, action, from_status, to_status, reason)
  VALUES (p_store, p_id, p_now_ms, p_actor, p_action, cur_status, p_to, p_reason);
  RETURN QUERY SELECT true, cur_status;
END $fn$;
REVOKE ALL ON FUNCTION mr_spend_transition(text, text, text[], text, text, text, text, bigint, text, boolean) FROM PUBLIC;
`,
  },
  {
    // R22-P3-1: settle and release are split into two SECURITY DEFINER
    // functions. Neither takes a caller-chosen timestamp or actor: the time is
    // clock_timestamp() and the actor is session_user (the caller's label is
    // kept, marked untrusted). Actions are whitelisted per function.
    //  - mr_spend_settle: pending/ambiguous -> settled, or pending -> ambiguous
    //    (reconcile; granted to mr_reconcile by the role SQL)
    //  - mr_spend_release: pending/ambiguous -> released (operator release;
    //    granted ONLY to mr_release). mr_reconcile can never release.
    // The v5 catch-all mr_spend_transition is dropped.
    version: 6,
    name: "r22-split-settle-release",
    sql: `
DROP FUNCTION IF EXISTS mr_spend_transition(text, text, text[], text, text, text, text, bigint, text, boolean);
CREATE OR REPLACE FUNCTION mr_spend_settle(
  p_store text, p_id text, p_from text[], p_to text, p_action text, p_label text,
  p_reason text, p_expect_tx_id text, p_check_tx boolean)
RETURNS TABLE (ok boolean, from_status text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE cur_status text; cur_tx text; now_ms bigint := (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
BEGIN
  IF p_to IS NULL OR p_to NOT IN ('settled', 'ambiguous') THEN
    RAISE EXCEPTION 'mr_spend_settle: target status % not allowed', p_to USING ERRCODE = 'check_violation';
  END IF;
  IF p_from IS NULL OR cardinality(p_from) = 0 OR NOT (p_from <@ (CASE WHEN p_to = 'ambiguous' THEN ARRAY['pending'] ELSE ARRAY['pending', 'ambiguous'] END)::text[]) THEN
    RAISE EXCEPTION 'mr_spend_settle: source statuses not allowed for %', p_to USING ERRCODE = 'check_violation';
  END IF;
  IF p_action IS NULL OR p_action NOT IN ('chain-reconcile', 'chain-reconcile-expired') THEN
    RAISE EXCEPTION 'mr_spend_settle: action % not allowed', p_action USING ERRCODE = 'check_violation';
  END IF;
  IF coalesce(btrim(p_reason), '') = '' THEN
    RAISE EXCEPTION 'mr_spend_settle: reason is required' USING ERRCODE = 'check_violation';
  END IF;
  SELECT s.status, s.tx_id INTO cur_status, cur_tx FROM public.mr_spend s
   WHERE s.store = p_store AND s.id = p_id FOR UPDATE;
  IF NOT FOUND THEN RETURN QUERY SELECT false, NULL::text; RETURN; END IF;
  IF NOT (cur_status = ANY (p_from)) OR (p_check_tx AND cur_tx IS DISTINCT FROM p_expect_tx_id) THEN
    RETURN QUERY SELECT false, cur_status; RETURN;
  END IF;
  UPDATE public.mr_spend SET status = p_to, updated_ms = now_ms WHERE store = p_store AND id = p_id;
  INSERT INTO public.mr_spend_audit (store, id, at_ms, actor, action, from_status, to_status, reason)
  VALUES (p_store, p_id, now_ms,
          session_user::text || CASE WHEN coalesce(btrim(p_label), '') = '' THEN '' ELSE ' (label, untrusted: ' || left(btrim(p_label), 64) || ')' END,
          p_action, cur_status, p_to, left(p_reason, 2000));
  RETURN QUERY SELECT true, cur_status;
END $fn$;
CREATE OR REPLACE FUNCTION mr_spend_release(
  p_store text, p_id text, p_from text[], p_action text, p_label text,
  p_reason text, p_expect_tx_id text, p_check_tx boolean)
RETURNS TABLE (ok boolean, from_status text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE cur_status text; cur_tx text; now_ms bigint := (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
BEGIN
  IF p_from IS NULL OR cardinality(p_from) = 0 OR NOT (p_from <@ ARRAY['pending', 'ambiguous']::text[]) THEN
    RAISE EXCEPTION 'mr_spend_release: source statuses must be pending/ambiguous' USING ERRCODE = 'check_violation';
  END IF;
  IF p_action IS NULL OR p_action NOT IN ('manual-release', 'manual-release-forced') THEN
    RAISE EXCEPTION 'mr_spend_release: action % not allowed', p_action USING ERRCODE = 'check_violation';
  END IF;
  IF coalesce(btrim(p_label), '') = '' OR length(btrim(coalesce(p_reason, ''))) < 8 THEN
    RAISE EXCEPTION 'mr_spend_release: operator label and a reason of 8+ characters are required' USING ERRCODE = 'check_violation';
  END IF;
  IF p_action = 'manual-release' AND (NOT p_check_tx OR position(' | proof: ' IN p_reason) = 0) THEN
    RAISE EXCEPTION 'mr_spend_release: manual-release needs a pinned txId and a recorded proof' USING ERRCODE = 'check_violation';
  END IF;
  SELECT s.status, s.tx_id INTO cur_status, cur_tx FROM public.mr_spend s
   WHERE s.store = p_store AND s.id = p_id FOR UPDATE;
  IF NOT FOUND THEN RETURN QUERY SELECT false, NULL::text; RETURN; END IF;
  IF NOT (cur_status = ANY (p_from)) OR (p_check_tx AND cur_tx IS DISTINCT FROM p_expect_tx_id) THEN
    RETURN QUERY SELECT false, cur_status; RETURN;
  END IF;
  UPDATE public.mr_spend SET status = 'released', updated_ms = now_ms WHERE store = p_store AND id = p_id;
  INSERT INTO public.mr_spend_audit (store, id, at_ms, actor, action, from_status, to_status, reason)
  VALUES (p_store, p_id, now_ms,
          session_user::text || ' (label, untrusted: ' || left(btrim(p_label), 64) || ')',
          p_action, cur_status, 'released', left(p_reason, 2000));
  RETURN QUERY SELECT true, cur_status;
END $fn$;
REVOKE ALL ON FUNCTION mr_spend_settle(text, text, text[], text, text, text, text, text, boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION mr_spend_release(text, text, text[], text, text, text, text, boolean) FROM PUBLIC;
`,
  },  {
    // R23-P2-1 / R23-P3-1 / R23-P3-3 (internal reviewer run 23):
    //  - mr_network: write-once network marker (set by migratePostgres from
    //    NETWORK, with the chain's genesis hash). The DB refuses a forced
    //    release when it says mainnet.
    //  - mr_spend_release takes the chain proof as TYPED arguments (txId,
    //    genesis hash, round checked, lastValid, margin, indexer status),
    //    checks it itself (non-null tx_id + last_valid pinned on the row,
    //    margin >= 0, round_checked > last_valid + margin, status 404,
    //    genesis = marker) and stores it in its own audit columns.
    //    The DB cannot see the chain: round_checked / 404 are what the
    //    release tool observed, so the release credential stays off the
    //    host (two-person procedure, docs/ops/release-two-person.md).
    //  - mr_spend_settle requires a pinned, non-null txId (R23-P3-3).
    //  - mr_spend_guard trigger: no status change, and no change to a pinned
    //    tx_id / last_valid, unless made inside the mr_spend_* SECURITY
    //    DEFINER functions (session flag mr.spend_fn = on AND current_user =
    //    the table owner; the flag alone is settable by anyone, the owner
    //    check is what makes it unforgeable). Identity columns are immutable.
    //  - mr_spend_app_finalize: the app's (mr_demo_api) only status path:
    //    pending -> settled/ambiguous/released, released only while no txId
    //    is pinned (nothing was broadcast); released writes an audit row.
    version: 7,
    name: "r23-db-checked-proof-network-marker-spend-guard",
    sql: `
CREATE TABLE IF NOT EXISTS mr_network (
  singleton    boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  network      text NOT NULL CHECK (network IN ('testnet', 'mainnet')),
  genesis_hash text NOT NULL CHECK (genesis_hash <> ''),
  set_at       timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE OR REPLACE FUNCTION mr_network_write_once() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'mr_network is write-once (% refused)', TG_OP USING ERRCODE = 'insufficient_privilege';
END $$;
DROP TRIGGER IF EXISTS mr_network_no_change ON mr_network;
CREATE TRIGGER mr_network_no_change BEFORE UPDATE OR DELETE ON mr_network FOR EACH ROW EXECUTE FUNCTION mr_network_write_once();
DROP TRIGGER IF EXISTS mr_network_no_truncate ON mr_network;
CREATE TRIGGER mr_network_no_truncate BEFORE TRUNCATE ON mr_network FOR EACH STATEMENT EXECUTE FUNCTION mr_network_write_once();
REVOKE ALL ON mr_network FROM PUBLIC;

ALTER TABLE mr_spend_audit
  ADD COLUMN IF NOT EXISTS proof_tx_id text,
  ADD COLUMN IF NOT EXISTS proof_genesis_hash text,
  ADD COLUMN IF NOT EXISTS proof_round_checked bigint,
  ADD COLUMN IF NOT EXISTS proof_last_valid bigint,
  ADD COLUMN IF NOT EXISTS proof_margin integer,
  ADD COLUMN IF NOT EXISTS proof_indexer_status integer;

CREATE OR REPLACE FUNCTION mr_spend_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE via_fn boolean;
BEGIN
  SELECT coalesce(current_setting('mr.spend_fn', true), '') = 'on' AND pg_get_userbyid(c.relowner) = current_user::text
    INTO via_fn FROM pg_class c WHERE c.oid = TG_RELID;
  IF TG_OP = 'TRUNCATE' THEN
    RAISE EXCEPTION 'mr_spend: TRUNCATE refused' USING ERRCODE = 'insufficient_privilege';
  ELSIF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'mr_spend: DELETE refused (reservations are never deleted)' USING ERRCODE = 'insufficient_privilege';
  ELSIF TG_OP = 'INSERT' THEN
    IF NEW.status NOT IN ('pending', 'settled') AND NOT via_fn THEN
      RAISE EXCEPTION 'mr_spend: a new row may only be pending or settled' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
  END IF;
  IF (NEW.store, NEW.id, NEW.payer, NEW.amount_micro, NEW.created_ms) IS DISTINCT FROM (OLD.store, OLD.id, OLD.payer, OLD.amount_micro, OLD.created_ms) THEN
    RAISE EXCEPTION 'mr_spend: store/id/payer/amount/created_ms are immutable' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF via_fn THEN RETURN NEW; END IF;
  IF NEW.status IS DISTINCT FROM OLD.status THEN
    RAISE EXCEPTION 'mr_spend: status % -> % only through the mr_spend_* functions', OLD.status, NEW.status USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF (NEW.tx_id IS DISTINCT FROM OLD.tx_id OR NEW.last_valid IS DISTINCT FROM OLD.last_valid)
     AND (OLD.status <> 'pending' OR OLD.tx_id IS NOT NULL OR OLD.last_valid IS NOT NULL) THEN
    RAISE EXCEPTION 'mr_spend: tx_id / last_valid can be pinned once, on a pending row' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $fn$;
DROP TRIGGER IF EXISTS mr_spend_guard_row ON mr_spend;
CREATE TRIGGER mr_spend_guard_row BEFORE INSERT OR UPDATE OR DELETE ON mr_spend FOR EACH ROW EXECUTE FUNCTION mr_spend_guard();
DROP TRIGGER IF EXISTS mr_spend_guard_truncate ON mr_spend;
CREATE TRIGGER mr_spend_guard_truncate BEFORE TRUNCATE ON mr_spend FOR EACH STATEMENT EXECUTE FUNCTION mr_spend_guard();
REVOKE ALL ON FUNCTION mr_spend_guard() FROM PUBLIC;

DROP FUNCTION IF EXISTS mr_spend_settle(text, text, text[], text, text, text, text, text, boolean);
DROP FUNCTION IF EXISTS mr_spend_release(text, text, text[], text, text, text, text, boolean);

CREATE OR REPLACE FUNCTION mr_spend_settle(
  p_store text, p_id text, p_from text[], p_to text, p_action text, p_label text,
  p_reason text, p_tx_id text)
RETURNS TABLE (ok boolean, from_status text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE cur_status text; cur_tx text; now_ms bigint := (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
BEGIN
  IF p_to IS NULL OR p_to NOT IN ('settled', 'ambiguous') THEN
    RAISE EXCEPTION 'mr_spend_settle: target status % not allowed', p_to USING ERRCODE = 'check_violation';
  END IF;
  IF p_from IS NULL OR cardinality(p_from) = 0 OR NOT (p_from <@ (CASE WHEN p_to = 'ambiguous' THEN ARRAY['pending'] ELSE ARRAY['pending', 'ambiguous'] END)::text[]) THEN
    RAISE EXCEPTION 'mr_spend_settle: source statuses not allowed for %', p_to USING ERRCODE = 'check_violation';
  END IF;
  IF p_action IS NULL OR p_action NOT IN ('chain-reconcile', 'chain-reconcile-expired') THEN
    RAISE EXCEPTION 'mr_spend_settle: action % not allowed', p_action USING ERRCODE = 'check_violation';
  END IF;
  IF coalesce(btrim(p_reason), '') = '' THEN
    RAISE EXCEPTION 'mr_spend_settle: reason is required' USING ERRCODE = 'check_violation';
  END IF;
  IF coalesce(btrim(p_tx_id), '') = '' THEN
    RAISE EXCEPTION 'mr_spend_settle: a pinned, non-null txId is required' USING ERRCODE = 'check_violation';
  END IF;
  SELECT s.status, s.tx_id INTO cur_status, cur_tx FROM public.mr_spend s
   WHERE s.store = p_store AND s.id = p_id FOR UPDATE;
  IF NOT FOUND THEN RETURN QUERY SELECT false, NULL::text; RETURN; END IF;
  IF NOT (cur_status = ANY (p_from)) OR cur_tx IS NULL OR cur_tx <> p_tx_id THEN
    RETURN QUERY SELECT false, cur_status; RETURN;
  END IF;
  PERFORM set_config('mr.spend_fn', 'on', true);
  UPDATE public.mr_spend SET status = p_to, updated_ms = now_ms WHERE store = p_store AND id = p_id;
  PERFORM set_config('mr.spend_fn', 'off', true);
  INSERT INTO public.mr_spend_audit (store, id, at_ms, actor, action, from_status, to_status, reason, proof_tx_id)
  VALUES (p_store, p_id, now_ms,
          session_user::text || CASE WHEN coalesce(btrim(p_label), '') = '' THEN '' ELSE ' (label, untrusted: ' || left(btrim(p_label), 64) || ')' END,
          p_action, cur_status, p_to, left(p_reason, 2000), cur_tx);
  RETURN QUERY SELECT true, cur_status;
END $fn$;

CREATE OR REPLACE FUNCTION mr_spend_release(
  p_store text, p_id text, p_action text, p_label text, p_reason text,
  p_tx_id text, p_genesis_hash text, p_round_checked bigint, p_last_valid bigint,
  p_margin integer, p_indexer_status integer)
RETURNS TABLE (ok boolean, from_status text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE cur_status text; cur_tx text; cur_lv bigint; net text; net_hash text;
        now_ms bigint := (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
BEGIN
  IF p_action IS NULL OR p_action NOT IN ('manual-release', 'manual-release-forced') THEN
    RAISE EXCEPTION 'mr_spend_release: action % not allowed', p_action USING ERRCODE = 'check_violation';
  END IF;
  IF coalesce(btrim(p_label), '') = '' OR length(btrim(coalesce(p_reason, ''))) < 8 THEN
    RAISE EXCEPTION 'mr_spend_release: operator label and a reason of 8+ characters are required' USING ERRCODE = 'check_violation';
  END IF;
  SELECT n.network, n.genesis_hash INTO net, net_hash FROM public.mr_network n WHERE n.singleton;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'mr_spend_release: network marker (mr_network) is not set; run migrate with NETWORK' USING ERRCODE = 'check_violation';
  END IF;
  IF p_action = 'manual-release-forced' AND net = 'mainnet' THEN
    RAISE EXCEPTION 'mr_spend_release: forced release is refused on mainnet' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF p_action = 'manual-release' THEN
    IF coalesce(btrim(p_tx_id), '') = '' OR p_last_valid IS NULL OR p_round_checked IS NULL OR p_margin IS NULL
       OR p_indexer_status IS NULL OR p_genesis_hash IS NULL THEN
      RAISE EXCEPTION 'mr_spend_release: manual-release needs txId, genesis hash, round checked, lastValid, margin and indexer status' USING ERRCODE = 'check_violation';
    END IF;
    IF p_margin < 0 THEN RAISE EXCEPTION 'mr_spend_release: margin must be >= 0' USING ERRCODE = 'check_violation'; END IF;
    IF p_indexer_status <> 404 THEN RAISE EXCEPTION 'mr_spend_release: proof needs an indexer 404 for the txId' USING ERRCODE = 'check_violation'; END IF;
    IF p_genesis_hash <> net_hash THEN RAISE EXCEPTION 'mr_spend_release: proof genesis hash does not match this database''s network (%)', net USING ERRCODE = 'check_violation'; END IF;
    IF NOT (p_round_checked > p_last_valid + p_margin) THEN
      RAISE EXCEPTION 'mr_spend_release: round % is not past lastValid % + margin %', p_round_checked, p_last_valid, p_margin USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  SELECT s.status, s.tx_id, s.last_valid INTO cur_status, cur_tx, cur_lv FROM public.mr_spend s
   WHERE s.store = p_store AND s.id = p_id FOR UPDATE;
  IF NOT FOUND THEN RETURN QUERY SELECT false, NULL::text; RETURN; END IF;
  IF cur_status NOT IN ('pending', 'ambiguous') THEN RETURN QUERY SELECT false, cur_status; RETURN; END IF;
  IF p_action = 'manual-release' THEN
    IF cur_tx IS NULL OR cur_lv IS NULL THEN
      RAISE EXCEPTION 'mr_spend_release: the row has no pinned tx_id / last_valid; a proof is impossible' USING ERRCODE = 'check_violation';
    END IF;
    IF cur_tx <> p_tx_id OR cur_lv <> p_last_valid THEN
      RETURN QUERY SELECT false, cur_status; RETURN; -- the proof is for another txn / lastValid
    END IF;
  ELSIF p_tx_id IS NOT NULL AND cur_tx IS DISTINCT FROM p_tx_id THEN
    RETURN QUERY SELECT false, cur_status; RETURN;
  END IF;
  PERFORM set_config('mr.spend_fn', 'on', true);
  UPDATE public.mr_spend SET status = 'released', updated_ms = now_ms WHERE store = p_store AND id = p_id;
  PERFORM set_config('mr.spend_fn', 'off', true);
  IF p_action = 'manual-release' THEN
    INSERT INTO public.mr_spend_audit (store, id, at_ms, actor, action, from_status, to_status, reason,
           proof_tx_id, proof_genesis_hash, proof_round_checked, proof_last_valid, proof_margin, proof_indexer_status)
    VALUES (p_store, p_id, now_ms, session_user::text || ' (label, untrusted: ' || left(btrim(p_label), 64) || ')',
            p_action, cur_status, 'released', left(p_reason, 2000),
            cur_tx, p_genesis_hash, p_round_checked, cur_lv, p_margin, p_indexer_status);
  ELSE
    INSERT INTO public.mr_spend_audit (store, id, at_ms, actor, action, from_status, to_status, reason, proof_tx_id)
    VALUES (p_store, p_id, now_ms, session_user::text || ' (label, untrusted: ' || left(btrim(p_label), 64) || ')',
            p_action, cur_status, 'released', left(p_reason, 2000), cur_tx);
  END IF;
  RETURN QUERY SELECT true, cur_status;
END $fn$;

CREATE OR REPLACE FUNCTION mr_spend_app_finalize(p_store text, p_id text, p_to text, p_tx_id text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE cur_status text; cur_tx text; now_ms bigint := (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
BEGIN
  IF p_to IS NULL OR p_to NOT IN ('settled', 'ambiguous', 'released') THEN
    RAISE EXCEPTION 'mr_spend_app_finalize: target status % not allowed', p_to USING ERRCODE = 'check_violation';
  END IF;
  SELECT s.status, s.tx_id INTO cur_status, cur_tx FROM public.mr_spend s
   WHERE s.store = p_store AND s.id = p_id FOR UPDATE;
  IF NOT FOUND OR cur_status <> 'pending' THEN RETURN false; END IF;
  -- Once a txId is pinned the txn may be broadcast: only reconcile / a proven release may free it.
  IF p_to = 'released' AND cur_tx IS NOT NULL THEN RETURN false; END IF;
  PERFORM set_config('mr.spend_fn', 'on', true);
  UPDATE public.mr_spend SET status = p_to, updated_ms = now_ms, tx_id = coalesce(cur_tx, nullif(btrim(p_tx_id), ''))
   WHERE store = p_store AND id = p_id;
  PERFORM set_config('mr.spend_fn', 'off', true);
  IF p_to = 'released' THEN
    INSERT INTO public.mr_spend_audit (store, id, at_ms, actor, action, from_status, to_status, reason)
    VALUES (p_store, p_id, now_ms, session_user::text, 'app-release-unbroadcast', cur_status, 'released',
            'payment not verified / not broadcast; no txId was pinned');
  END IF;
  RETURN true;
END $fn$;
REVOKE ALL ON FUNCTION mr_spend_settle(text, text, text[], text, text, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION mr_spend_release(text, text, text, text, text, text, text, bigint, bigint, integer, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION mr_spend_app_finalize(text, text, text, text) FROM PUBLIC;
`,
  },
  {
    // R24 (internal reviewer run 24):
    //  - R24-P2-1 mitigation: mr_spend_release needs TWO independent chain
    //    observations (different provider hosts, kind indexer|algod, at least
    //    one indexer), each genesis = the mr_network marker, each round >
    //    last_valid + margin, each status 404. Both are stored in typed audit
    //    columns. Still self-attested by the release tool: credential custody
    //    (docs/ops/release-custody.md) is the other half.
    //  - R24-P3-2: a non-owner INSERT into mr_spend must be pending, with a NULL
    //    tx_id / last_valid and created_ms within +-5 min of the DB clock.
    //    (The table owner, NOLOGIN on the host and reached only through the
    //    migrate admin's SET ROLE, keeps the JSON import path for settled rows.)
    //    mr_spend_app_finalize ignores p_tx_id when finalizing to released.
    version: 8,
    name: "r24-two-observation-release-app-insert-guard",
    sql: `
ALTER TABLE mr_spend_audit
  ADD COLUMN IF NOT EXISTS proof_provider text,
  ADD COLUMN IF NOT EXISTS proof_kind text,
  ADD COLUMN IF NOT EXISTS proof2_provider text,
  ADD COLUMN IF NOT EXISTS proof2_kind text,
  ADD COLUMN IF NOT EXISTS proof2_genesis_hash text,
  ADD COLUMN IF NOT EXISTS proof2_round_checked bigint,
  ADD COLUMN IF NOT EXISTS proof2_status integer;

CREATE OR REPLACE FUNCTION mr_spend_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE via_fn boolean; is_owner boolean; now_ms bigint := (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
BEGIN
  SELECT pg_get_userbyid(c.relowner) = current_user::text INTO is_owner FROM pg_class c WHERE c.oid = TG_RELID;
  via_fn := is_owner AND coalesce(current_setting('mr.spend_fn', true), '') = 'on';
  IF TG_OP = 'TRUNCATE' THEN
    RAISE EXCEPTION 'mr_spend: TRUNCATE refused' USING ERRCODE = 'insufficient_privilege';
  ELSIF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'mr_spend: DELETE refused (reservations are never deleted)' USING ERRCODE = 'insufficient_privilege';
  ELSIF TG_OP = 'INSERT' THEN
    IF is_owner THEN
      IF NEW.status NOT IN ('pending', 'settled') AND NOT via_fn THEN
        RAISE EXCEPTION 'mr_spend: a new row may only be pending or settled' USING ERRCODE = 'insufficient_privilege';
      END IF;
      RETURN NEW;
    END IF;
    -- R24-P3-2: app inserts
    IF NEW.status IS DISTINCT FROM 'pending' THEN
      RAISE EXCEPTION 'mr_spend: a new row may only be pending' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NEW.tx_id IS NOT NULL OR NEW.last_valid IS NOT NULL THEN
      RAISE EXCEPTION 'mr_spend: a new row must have a NULL tx_id and last_valid' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NEW.created_ms IS NULL OR abs(NEW.created_ms - now_ms) > 300000 THEN
      RAISE EXCEPTION 'mr_spend: created_ms must be within 5 minutes of the database clock' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
  END IF;
  IF (NEW.store, NEW.id, NEW.payer, NEW.amount_micro, NEW.created_ms) IS DISTINCT FROM (OLD.store, OLD.id, OLD.payer, OLD.amount_micro, OLD.created_ms) THEN
    RAISE EXCEPTION 'mr_spend: store/id/payer/amount/created_ms are immutable' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF via_fn THEN RETURN NEW; END IF;
  IF NEW.status IS DISTINCT FROM OLD.status THEN
    RAISE EXCEPTION 'mr_spend: status % -> % only through the mr_spend_* functions', OLD.status, NEW.status USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF (NEW.tx_id IS DISTINCT FROM OLD.tx_id OR NEW.last_valid IS DISTINCT FROM OLD.last_valid)
     AND (OLD.status <> 'pending' OR OLD.tx_id IS NOT NULL OR OLD.last_valid IS NOT NULL) THEN
    RAISE EXCEPTION 'mr_spend: tx_id / last_valid can be pinned once, on a pending row' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $fn$;
REVOKE ALL ON FUNCTION mr_spend_guard() FROM PUBLIC;

CREATE OR REPLACE FUNCTION mr_spend_app_finalize(p_store text, p_id text, p_to text, p_tx_id text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE cur_status text; cur_tx text; now_ms bigint := (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
BEGIN
  IF p_to IS NULL OR p_to NOT IN ('settled', 'ambiguous', 'released') THEN
    RAISE EXCEPTION 'mr_spend_app_finalize: target status % not allowed', p_to USING ERRCODE = 'check_violation';
  END IF;
  SELECT s.status, s.tx_id INTO cur_status, cur_tx FROM public.mr_spend s
   WHERE s.store = p_store AND s.id = p_id FOR UPDATE;
  IF NOT FOUND OR cur_status <> 'pending' THEN RETURN false; END IF;
  IF p_to = 'released' AND cur_tx IS NOT NULL THEN RETURN false; END IF;
  PERFORM set_config('mr.spend_fn', 'on', true);
  -- R24-P3-2: released never writes a txId (p_tx_id is ignored); settled/ambiguous only fill an unpinned one.
  UPDATE public.mr_spend SET status = p_to, updated_ms = now_ms,
         tx_id = CASE WHEN p_to = 'released' THEN cur_tx ELSE coalesce(cur_tx, nullif(btrim(p_tx_id), '')) END
   WHERE store = p_store AND id = p_id;
  PERFORM set_config('mr.spend_fn', 'off', true);
  IF p_to = 'released' THEN
    INSERT INTO public.mr_spend_audit (store, id, at_ms, actor, action, from_status, to_status, reason)
    VALUES (p_store, p_id, now_ms, session_user::text, 'app-release-unbroadcast', cur_status, 'released',
            'payment not verified / not broadcast; no txId was pinned');
  END IF;
  RETURN true;
END $fn$;
REVOKE ALL ON FUNCTION mr_spend_app_finalize(text, text, text, text) FROM PUBLIC;

DROP FUNCTION IF EXISTS mr_spend_release(text, text, text, text, text, text, text, bigint, bigint, integer, integer);
CREATE OR REPLACE FUNCTION mr_spend_release(
  p_store text, p_id text, p_action text, p_label text, p_reason text,
  p_tx_id text, p_last_valid bigint, p_margin integer,
  p_o1_provider text, p_o1_kind text, p_o1_genesis_hash text, p_o1_round bigint, p_o1_status integer,
  p_o2_provider text, p_o2_kind text, p_o2_genesis_hash text, p_o2_round bigint, p_o2_status integer)
RETURNS TABLE (ok boolean, from_status text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE cur_status text; cur_tx text; cur_lv bigint; net text; net_hash text; i int;
        prov text; kind text; gh text; rnd bigint; st integer;
        now_ms bigint := (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
BEGIN
  IF p_action IS NULL OR p_action NOT IN ('manual-release', 'manual-release-forced') THEN
    RAISE EXCEPTION 'mr_spend_release: action % not allowed', p_action USING ERRCODE = 'check_violation';
  END IF;
  IF coalesce(btrim(p_label), '') = '' OR length(btrim(coalesce(p_reason, ''))) < 8 THEN
    RAISE EXCEPTION 'mr_spend_release: operator label and a reason of 8+ characters are required' USING ERRCODE = 'check_violation';
  END IF;
  SELECT n.network, n.genesis_hash INTO net, net_hash FROM public.mr_network n WHERE n.singleton;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'mr_spend_release: network marker (mr_network) is not set; run migrate with NETWORK' USING ERRCODE = 'check_violation';
  END IF;
  IF p_action = 'manual-release-forced' AND net = 'mainnet' THEN
    RAISE EXCEPTION 'mr_spend_release: forced release is refused on mainnet' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF p_action = 'manual-release' THEN
    IF coalesce(btrim(p_tx_id), '') = '' OR p_last_valid IS NULL OR p_margin IS NULL THEN
      RAISE EXCEPTION 'mr_spend_release: manual-release needs txId, lastValid and margin' USING ERRCODE = 'check_violation';
    END IF;
    IF p_margin < 0 THEN RAISE EXCEPTION 'mr_spend_release: margin must be >= 0' USING ERRCODE = 'check_violation'; END IF;
    FOR i IN 1..2 LOOP
      IF i = 1 THEN prov := p_o1_provider; kind := p_o1_kind; gh := p_o1_genesis_hash; rnd := p_o1_round; st := p_o1_status;
      ELSE prov := p_o2_provider; kind := p_o2_kind; gh := p_o2_genesis_hash; rnd := p_o2_round; st := p_o2_status; END IF;
      IF prov IS NULL OR kind IS NULL OR gh IS NULL OR rnd IS NULL OR st IS NULL THEN
        RAISE EXCEPTION 'mr_spend_release: observation % is incomplete (two observations are required)', i USING ERRCODE = 'check_violation';
      END IF;
      IF prov !~ '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$' THEN
        RAISE EXCEPTION 'mr_spend_release: observation % provider must be a lower-case host[:port]', i USING ERRCODE = 'check_violation';
      END IF;
      IF kind NOT IN ('indexer', 'algod') THEN
        RAISE EXCEPTION 'mr_spend_release: observation % kind must be indexer or algod', i USING ERRCODE = 'check_violation';
      END IF;
      IF st <> 404 THEN RAISE EXCEPTION 'mr_spend_release: observation % must show the txId not found (404)', i USING ERRCODE = 'check_violation'; END IF;
      IF gh <> net_hash THEN RAISE EXCEPTION 'mr_spend_release: observation % genesis hash does not match this database''s network (%)', i, net USING ERRCODE = 'check_violation'; END IF;
      IF NOT (rnd > p_last_valid + p_margin) THEN
        RAISE EXCEPTION 'mr_spend_release: observation % round % is not past lastValid % + margin %', i, rnd, p_last_valid, p_margin USING ERRCODE = 'check_violation';
      END IF;
    END LOOP;
    IF p_o1_provider = p_o2_provider THEN
      RAISE EXCEPTION 'mr_spend_release: the two observations must come from different providers' USING ERRCODE = 'check_violation';
    END IF;
    IF 'indexer' NOT IN (p_o1_kind, p_o2_kind) THEN
      RAISE EXCEPTION 'mr_spend_release: at least one observation must come from an indexer' USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  SELECT s.status, s.tx_id, s.last_valid INTO cur_status, cur_tx, cur_lv FROM public.mr_spend s
   WHERE s.store = p_store AND s.id = p_id FOR UPDATE;
  IF NOT FOUND THEN RETURN QUERY SELECT false, NULL::text; RETURN; END IF;
  IF cur_status NOT IN ('pending', 'ambiguous') THEN RETURN QUERY SELECT false, cur_status; RETURN; END IF;
  IF p_action = 'manual-release' THEN
    IF cur_tx IS NULL OR cur_lv IS NULL THEN
      RAISE EXCEPTION 'mr_spend_release: the row has no pinned tx_id / last_valid; a proof is impossible' USING ERRCODE = 'check_violation';
    END IF;
    IF cur_tx <> p_tx_id OR cur_lv <> p_last_valid THEN
      RETURN QUERY SELECT false, cur_status; RETURN;
    END IF;
  ELSIF p_tx_id IS NOT NULL AND cur_tx IS DISTINCT FROM p_tx_id THEN
    RETURN QUERY SELECT false, cur_status; RETURN;
  END IF;
  PERFORM set_config('mr.spend_fn', 'on', true);
  UPDATE public.mr_spend SET status = 'released', updated_ms = now_ms WHERE store = p_store AND id = p_id;
  PERFORM set_config('mr.spend_fn', 'off', true);
  IF p_action = 'manual-release' THEN
    INSERT INTO public.mr_spend_audit (store, id, at_ms, actor, action, from_status, to_status, reason,
           proof_tx_id, proof_last_valid, proof_margin,
           proof_provider, proof_kind, proof_genesis_hash, proof_round_checked, proof_indexer_status,
           proof2_provider, proof2_kind, proof2_genesis_hash, proof2_round_checked, proof2_status)
    VALUES (p_store, p_id, now_ms, session_user::text || ' (label, untrusted: ' || left(btrim(p_label), 64) || ')',
            p_action, cur_status, 'released', left(p_reason, 2000),
            cur_tx, cur_lv, p_margin,
            p_o1_provider, p_o1_kind, p_o1_genesis_hash, p_o1_round, p_o1_status,
            p_o2_provider, p_o2_kind, p_o2_genesis_hash, p_o2_round, p_o2_status);
  ELSE
    INSERT INTO public.mr_spend_audit (store, id, at_ms, actor, action, from_status, to_status, reason, proof_tx_id)
    VALUES (p_store, p_id, now_ms, session_user::text || ' (label, untrusted: ' || left(btrim(p_label), 64) || ')',
            p_action, cur_status, 'released', left(p_reason, 2000), cur_tx);
  END IF;
  RETURN QUERY SELECT true, cur_status;
END $fn$;
REVOKE ALL ON FUNCTION mr_spend_release(text, text, text, text, text, text, bigint, integer, text, text, text, bigint, integer, text, text, text, bigint, integer) FROM PUBLIC;
`,
  },
  {
    // R25 (internal reviewer run 25), R25-P2-1 partial: "different hosts" was a
    // string compare (127.0.0.1 + localhost, host + host:443, x.invalid +
    // y.invalid all passed). Now mr_network_provider is the provider
    // allowlist of the network profile (host -> operator id, seeded from
    // @mandaterail/core *_PROVIDER_ALLOWLIST), and mr_spend_release requires
    // both observation hosts on the marker network's list with two DIFFERENT
    // operator ids; loopback / localhost / .invalid / IP literals are refused
    // (also by the table CHECK). The operator ids are stored in the audit row.
    // Observations are still self-reported (no signed attestations).
    version: 9,
    name: "r25-provider-allowlist",
    sql: `
CREATE TABLE IF NOT EXISTS mr_network_provider (
  network     text NOT NULL CHECK (network IN ('testnet', 'mainnet')),
  host        text NOT NULL CHECK (host ~ '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$' AND host !~ '^[0-9.]+$'
                                   AND host <> 'localhost' AND host NOT LIKE '%.localhost' AND host <> 'invalid' AND host NOT LIKE '%.invalid'),
  operator_id text NOT NULL CHECK (operator_id ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
  added_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (network, host)
);
REVOKE ALL ON mr_network_provider FROM PUBLIC;
INSERT INTO mr_network_provider (network, host, operator_id) VALUES
${providerSeedSql()}
ON CONFLICT (network, host) DO NOTHING;
ALTER TABLE mr_spend_audit
  ADD COLUMN IF NOT EXISTS proof_operator text,
  ADD COLUMN IF NOT EXISTS proof2_operator text;

CREATE OR REPLACE FUNCTION mr_spend_release(
  p_store text, p_id text, p_action text, p_label text, p_reason text,
  p_tx_id text, p_last_valid bigint, p_margin integer,
  p_o1_provider text, p_o1_kind text, p_o1_genesis_hash text, p_o1_round bigint, p_o1_status integer,
  p_o2_provider text, p_o2_kind text, p_o2_genesis_hash text, p_o2_round bigint, p_o2_status integer)
RETURNS TABLE (ok boolean, from_status text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE cur_status text; cur_tx text; cur_lv bigint; net text; net_hash text; i int;
        prov text; kind text; gh text; rnd bigint; st integer; h text; op text; op1 text; op2 text;
        now_ms bigint := (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
BEGIN
  IF p_action IS NULL OR p_action NOT IN ('manual-release', 'manual-release-forced') THEN
    RAISE EXCEPTION 'mr_spend_release: action % not allowed', p_action USING ERRCODE = 'check_violation';
  END IF;
  IF coalesce(btrim(p_label), '') = '' OR length(btrim(coalesce(p_reason, ''))) < 8 THEN
    RAISE EXCEPTION 'mr_spend_release: operator label and a reason of 8+ characters are required' USING ERRCODE = 'check_violation';
  END IF;
  SELECT n.network, n.genesis_hash INTO net, net_hash FROM public.mr_network n WHERE n.singleton;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'mr_spend_release: network marker (mr_network) is not set; run migrate with NETWORK' USING ERRCODE = 'check_violation';
  END IF;
  IF p_action = 'manual-release-forced' AND net = 'mainnet' THEN
    RAISE EXCEPTION 'mr_spend_release: forced release is refused on mainnet' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF p_action = 'manual-release' THEN
    IF coalesce(btrim(p_tx_id), '') = '' OR p_last_valid IS NULL OR p_margin IS NULL THEN
      RAISE EXCEPTION 'mr_spend_release: manual-release needs txId, lastValid and margin' USING ERRCODE = 'check_violation';
    END IF;
    IF p_margin < 0 THEN RAISE EXCEPTION 'mr_spend_release: margin must be >= 0' USING ERRCODE = 'check_violation'; END IF;
    FOR i IN 1..2 LOOP
      IF i = 1 THEN prov := p_o1_provider; kind := p_o1_kind; gh := p_o1_genesis_hash; rnd := p_o1_round; st := p_o1_status;
      ELSE prov := p_o2_provider; kind := p_o2_kind; gh := p_o2_genesis_hash; rnd := p_o2_round; st := p_o2_status; END IF;
      IF prov IS NULL OR kind IS NULL OR gh IS NULL OR rnd IS NULL OR st IS NULL THEN
        RAISE EXCEPTION 'mr_spend_release: observation % is incomplete (two observations are required)', i USING ERRCODE = 'check_violation';
      END IF;
      IF prov !~ '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$' THEN
        RAISE EXCEPTION 'mr_spend_release: observation % provider must be a lower-case host[:port]', i USING ERRCODE = 'check_violation';
      END IF;
      IF kind NOT IN ('indexer', 'algod') THEN
        RAISE EXCEPTION 'mr_spend_release: observation % kind must be indexer or algod', i USING ERRCODE = 'check_violation';
      END IF;
      -- R25-P2-1: the host (port stripped) must be on this network's provider allowlist; loopback / reserved never.
      h := regexp_replace(prov, ':[0-9]+$', '');
      IF h = 'localhost' OR h LIKE '%.localhost' OR h = 'invalid' OR h LIKE '%.invalid' OR h ~ '^[0-9.]+$' THEN
        RAISE EXCEPTION 'mr_spend_release: observation % provider % is loopback / localhost / .invalid / an IP literal (refused)', i, h USING ERRCODE = 'check_violation';
      END IF;
      op := NULL;
      SELECT a.operator_id INTO op FROM public.mr_network_provider a WHERE a.network = net AND a.host = h;
      IF op IS NULL THEN
        RAISE EXCEPTION 'mr_spend_release: observation % provider % is not on the % provider allowlist (mr_network_provider)', i, h, net USING ERRCODE = 'check_violation';
      END IF;
      IF i = 1 THEN op1 := op; ELSE op2 := op; END IF;
      IF st <> 404 THEN RAISE EXCEPTION 'mr_spend_release: observation % must show the txId not found (404)', i USING ERRCODE = 'check_violation'; END IF;
      IF gh <> net_hash THEN RAISE EXCEPTION 'mr_spend_release: observation % genesis hash does not match this database''s network (%)', i, net USING ERRCODE = 'check_violation'; END IF;
      IF NOT (rnd > p_last_valid + p_margin) THEN
        RAISE EXCEPTION 'mr_spend_release: observation % round % is not past lastValid % + margin %', i, rnd, p_last_valid, p_margin USING ERRCODE = 'check_violation';
      END IF;
    END LOOP;
    IF op1 = op2 THEN
      RAISE EXCEPTION 'mr_spend_release: the two observations must come from different operators (both are %)', op1 USING ERRCODE = 'check_violation';
    END IF;
    IF 'indexer' NOT IN (p_o1_kind, p_o2_kind) THEN
      RAISE EXCEPTION 'mr_spend_release: at least one observation must come from an indexer' USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  SELECT s.status, s.tx_id, s.last_valid INTO cur_status, cur_tx, cur_lv FROM public.mr_spend s
   WHERE s.store = p_store AND s.id = p_id FOR UPDATE;
  IF NOT FOUND THEN RETURN QUERY SELECT false, NULL::text; RETURN; END IF;
  IF cur_status NOT IN ('pending', 'ambiguous') THEN RETURN QUERY SELECT false, cur_status; RETURN; END IF;
  IF p_action = 'manual-release' THEN
    IF cur_tx IS NULL OR cur_lv IS NULL THEN
      RAISE EXCEPTION 'mr_spend_release: the row has no pinned tx_id / last_valid; a proof is impossible' USING ERRCODE = 'check_violation';
    END IF;
    IF cur_tx <> p_tx_id OR cur_lv <> p_last_valid THEN
      RETURN QUERY SELECT false, cur_status; RETURN;
    END IF;
  ELSIF p_tx_id IS NOT NULL AND cur_tx IS DISTINCT FROM p_tx_id THEN
    RETURN QUERY SELECT false, cur_status; RETURN;
  END IF;
  PERFORM set_config('mr.spend_fn', 'on', true);
  UPDATE public.mr_spend SET status = 'released', updated_ms = now_ms WHERE store = p_store AND id = p_id;
  PERFORM set_config('mr.spend_fn', 'off', true);
  IF p_action = 'manual-release' THEN
    INSERT INTO public.mr_spend_audit (store, id, at_ms, actor, action, from_status, to_status, reason,
           proof_tx_id, proof_last_valid, proof_margin,
           proof_provider, proof_kind, proof_genesis_hash, proof_round_checked, proof_indexer_status,
           proof2_provider, proof2_kind, proof2_genesis_hash, proof2_round_checked, proof2_status,
           proof_operator, proof2_operator)
    VALUES (p_store, p_id, now_ms, session_user::text || ' (label, untrusted: ' || left(btrim(p_label), 64) || ')',
            p_action, cur_status, 'released', left(p_reason, 2000),
            cur_tx, cur_lv, p_margin,
            p_o1_provider, p_o1_kind, p_o1_genesis_hash, p_o1_round, p_o1_status,
            p_o2_provider, p_o2_kind, p_o2_genesis_hash, p_o2_round, p_o2_status,
            op1, op2);
  ELSE
    INSERT INTO public.mr_spend_audit (store, id, at_ms, actor, action, from_status, to_status, reason, proof_tx_id)
    VALUES (p_store, p_id, now_ms, session_user::text || ' (label, untrusted: ' || left(btrim(p_label), 64) || ')',
            p_action, cur_status, 'released', left(p_reason, 2000), cur_tx);
  END IF;
  RETURN QUERY SELECT true, cur_status;
END $fn$;
REVOKE ALL ON FUNCTION mr_spend_release(text, text, text, text, text, text, bigint, integer, text, text, text, bigint, integer, text, text, text, bigint, integer) FROM PUBLIC;
`,
  },
];

/**
 * R26 (internal reviewer run 26), R26-P3-4: provider hosts are canonical (lower
 * case, no trailing dot); hex / decimal / octal / mixed IP forms (any numeric
 * last label) and .local / .internal / .home.arpa are refused, by the table
 * CHECK and by mr_spend_release, through ONE immutable predicate that mirrors
 * @mandaterail/core isForbiddenProviderHost. mr_spend_release normalizes the
 * observation host (lower case, port and trailing dot stripped) before the
 * allowlist lookup. Derived from the v9 function body so nothing else changes.
 */
const V9_SQL = MIGRATIONS.find((m) => m.version === 9)!.sql;
const V9_RELEASE_FN = V9_SQL.slice(V9_SQL.indexOf("CREATE OR REPLACE FUNCTION mr_spend_release("));
function v10ReleaseFn(): string {
  const reps: Array<[string, string]> = [
    [`      IF prov !~ '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$' THEN
        RAISE EXCEPTION 'mr_spend_release: observation % provider must be a lower-case host[:port]', i USING ERRCODE = 'check_violation';`,
     `      prov := lower(btrim(prov));
      IF prov !~ '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?[.]?(:[0-9]{1,5})?$' THEN
        RAISE EXCEPTION 'mr_spend_release: observation % provider must be a host[:port]', i USING ERRCODE = 'check_violation';`],
    [`      h := regexp_replace(prov, ':[0-9]+$', '');
      IF h = 'localhost' OR h LIKE '%.localhost' OR h = 'invalid' OR h LIKE '%.invalid' OR h ~ '^[0-9.]+$' THEN
        RAISE EXCEPTION 'mr_spend_release: observation % provider % is loopback / localhost / .invalid / an IP literal (refused)', i, h USING ERRCODE = 'check_violation';`,
     `      h := regexp_replace(regexp_replace(prov, ':[0-9]+$', ''), '[.]$', '');
      IF public.mr_provider_host_refused(h) THEN
        RAISE EXCEPTION 'mr_spend_release: observation % provider % is loopback / localhost / a private suffix / an IP form (refused)', i, h USING ERRCODE = 'check_violation';`],
  ];
  let f = V9_RELEASE_FN;
  for (const [a, b] of reps) {
    if (!f.includes(a)) throw new Error("v10 migration: v9 release function text changed; update v10ReleaseFn");
    f = f.replace(a, () => b); // function form: no $-patterns in b
  }
  return f;
}
(MIGRATIONS as Array<{ version: number; name: string; sql: string }>).push({
  version: 10,
  name: "r26-provider-host-canonical",
  sql: `
CREATE OR REPLACE FUNCTION mr_provider_host_refused(h text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $fn$
  SELECT h = '' OR length(h) > 253
      OR h !~ '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$' OR h ~ '[.][.]'
      OR h ~ '(^|[.])(localhost|invalid|local|internal|home[.]arpa)$'
      OR h ~ '(^|[.])(0x[0-9a-f]*|[0-9]+)$'
$fn$;
ALTER TABLE mr_network_provider DROP CONSTRAINT IF EXISTS mr_network_provider_host_check;
ALTER TABLE mr_network_provider DROP CONSTRAINT IF EXISTS mr_network_provider_host_canonical;
ALTER TABLE mr_network_provider ADD CONSTRAINT mr_network_provider_host_canonical
  CHECK (host = lower(host) AND host !~ '[.]$' AND NOT mr_provider_host_refused(host));
${v10ReleaseFn()}
`,
});
/** v11 operator seed: distinct operator ids of each profile's provider allowlist (static constants, validated). */
function signerOperatorSeedSql(): string {
  const rows = new Set<string>();
  for (const p of [TESTNET_PROFILE, MAINNET_PROFILE]) {
    for (const e of p.providerAllowlist) {
      if (!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(e.operator)) throw new Error(`bad operator ${e.operator}`);
      rows.add(`  ('${p.name}', '${e.operator}')`);
    }
  }
  return [...rows].join(",\n");
}
(MIGRATIONS as Array<{ version: number; name: string; sql: string }>).push({
  version: 11,
  name: "attested-release-signer",
  sql: v11Sql(v10ReleaseFn(), signerOperatorSeedSql()),
});
(MIGRATIONS as Array<{ version: number; name: string; sql: string }>).push({
  version: 12,
  name: "attested-release-cosign",
  sql: v12Sql(),
});
// v13: MainNet operator 2 (GetBlock shared EU algod). v9/v11 seed from the
// allowlist only on first migrate, so an already-migrated DB needs the rows here.
(MIGRATIONS as Array<{ version: number; name: string; sql: string }>).push({
  version: 13,
  name: "mainnet-provider-getblock",
  sql: `
INSERT INTO mr_network_provider (network, host, operator_id) VALUES
  ('mainnet', 'shared.eu-central-1.getblock.io', 'getblock')
ON CONFLICT (network, host) DO NOTHING;
INSERT INTO mr_signer_operator (network, operator) VALUES ('mainnet', 'getblock')
ON CONFLICT (network, operator) DO NOTHING;
`,
});
// v14: MainNet operator 3 (Blockdaemon API Suite algod + indexer, the v12 co-signer's independent operator).
// R54-P3-3: an existing host row (getblock or blockdaemon) pinned to a DIFFERENT operator is an error (RAISE).
// R55-P3-1: a separate version, so DBs already at v13 get these rows.
(MIGRATIONS as Array<{ version: number; name: string; sql: string }>).push({
  version: 14,
  name: "mainnet-provider-blockdaemon",
  sql: `
DO $v14$
DECLARE
  want CONSTANT text[][] := ARRAY[['shared.eu-central-1.getblock.io', 'getblock'], ['svc.blockdaemon.com', 'blockdaemon']];
  i int;
  have text;
BEGIN
  FOR i IN 1 .. array_length(want, 1) LOOP
    SELECT np.operator_id INTO have FROM mr_network_provider np WHERE np.network = 'mainnet' AND np.host = want[i][1];
    IF FOUND AND have IS DISTINCT FROM want[i][2] THEN
      RAISE EXCEPTION 'v14: mainnet provider % is pinned to operator %, expected %; fix the row by hand (refusing to keep it)', want[i][1], have, want[i][2]
        USING ERRCODE = 'check_violation';
    END IF;
    INSERT INTO mr_network_provider (network, host, operator_id) VALUES ('mainnet', want[i][1], want[i][2])
      ON CONFLICT (network, host) DO NOTHING;
    INSERT INTO mr_signer_operator (network, operator) VALUES ('mainnet', want[i][2])
      ON CONFLICT (network, operator) DO NOTHING;
  END LOOP;
END
$v14$;
`,
});
// v15: MainNet operator 4 (dRPC free algod, the co-signer's operator) + the blockscan-full observation method.
// blockscan-full has the blockscan rule (idxRound = lastValid exactly; the scan covered [fv, lv]); only the way the
// txids are obtained differs (msgpack blocks, computed locally). The v11/v12 functions are patched in place
// (CREATE OR REPLACE keeps owner/ACLs); each patch must match exactly once or the migration RAISEs.
(MIGRATIONS as Array<{ version: number; name: string; sql: string }>).push({
  version: 15,
  name: "mainnet-provider-drpc-blockscan-full",
  sql: `
DO $v15$
DECLARE
  have text;
  def text;
  n int;
BEGIN
  SELECT np.operator_id INTO have FROM mr_network_provider np WHERE np.network = 'mainnet' AND np.host = 'algorand.drpc.org';
  IF FOUND AND have IS DISTINCT FROM 'drpc' THEN
    RAISE EXCEPTION 'v15: mainnet provider algorand.drpc.org is pinned to operator %, expected drpc; fix the row by hand', have USING ERRCODE = 'check_violation';
  END IF;
  INSERT INTO mr_network_provider (network, host, operator_id) VALUES ('mainnet', 'algorand.drpc.org', 'drpc') ON CONFLICT (network, host) DO NOTHING;
  INSERT INTO mr_signer_operator (network, operator) VALUES ('mainnet', 'drpc') ON CONFLICT (network, operator) DO NOTHING;

  def := pg_get_functiondef('mr_spend_release_attested_v11(text, text, bytea, bytea, text, text)'::regprocedure);
  n := (length(def) - length(replace(def, $q$ELSIF o->>'method' = 'blockscan' THEN$q$, ''))) / length($q$ELSIF o->>'method' = 'blockscan' THEN$q$);
  IF n <> 1 THEN RAISE EXCEPTION 'v15: v11 method patch matched % times (expected 1)', n; END IF;
  EXECUTE replace(def, $q$ELSIF o->>'method' = 'blockscan' THEN$q$, $q$ELSIF o->>'method' IN ('blockscan', 'blockscan-full') THEN$q$);

  def := pg_get_functiondef('mr_spend_release_attested(text, text, bytea, bytea, bytea, bytea, text, text)'::regprocedure);
  n := (length(def) - length(replace(def, $q$(o->>'method' = 'blockscan' AND$q$, ''))) / length($q$(o->>'method' = 'blockscan' AND$q$);
  IF n <> 1 THEN RAISE EXCEPTION 'v15: v12 blockscan patch matched % times (expected 1)', n; END IF;
  n := (length(def) - length(replace(def, $q$NOT IN ('idx404', 'blockscan')$q$, ''))) / length($q$NOT IN ('idx404', 'blockscan')$q$);
  IF n <> 1 THEN RAISE EXCEPTION 'v15: v12 method-list patch matched % times (expected 1)', n; END IF;
  def := replace(def, $q$(o->>'method' = 'blockscan' AND$q$, $q$(o->>'method' IN ('blockscan', 'blockscan-full') AND$q$);
  def := replace(def, $q$NOT IN ('idx404', 'blockscan')$q$, $q$NOT IN ('idx404', 'blockscan', 'blockscan-full')$q$);
  EXECUTE def;
END
$v15$;
`,
});
// v16 (rev 21, renumbered from r51's v13 after getblock v13-v15, R62-MIG-1): automatic resume + DB-enforced caps.
(MIGRATIONS as Array<{ version: number; name: string; sql: string }>).push({
  version: 16,
  name: "automatic-resume-and-db-caps",
  sql: v16Sql(),
});
// v17 (R66-P3-4): v16 is frozen; converge any reviewed v16 text + backfill the caps ledger, then later deltas.
(MIGRATIONS as Array<{ version: number; name: string; sql: string }>).push({
  version: 17,
  name: "v16-converge-and-ledger-backfill",
  sql: v17Sql(),
});
export const PG_SCHEMA_VERSION = MIGRATIONS[MIGRATIONS.length - 1]!.version;

export class SchemaTooNewError extends Error {}
export class SchemaNameMismatchError extends Error {}

/** Apply pending migrations. Idempotent, safe from several processes at once. */
export class NetworkMarkerError extends Error {}

/** Normalised network name for the marker, or null if NETWORK is unset. */
function markerNetwork(raw: string | undefined, allowMainnet: boolean): "testnet" | "mainnet" | null {
  const v = (raw ?? "").trim();
  if (!v) return null;
  if (isNetworkMainnet(v) && !allowMainnet) {
    // R24-P3-3: NETWORK=mainnet alone never implies MainNet; ALLOW_MAINNET=1 must be explicit.
    throw new NetworkMarkerError("NETWORK=mainnet needs an explicit ALLOW_MAINNET=1 to migrate");
  }
  return networkProfile({ NETWORK: v, ALLOW_MAINNET: isNetworkMainnet(v) ? "1" : undefined }).name;
}
function isNetworkMainnet(v: string): boolean {
  return v.toLowerCase() === "mainnet" || v === MAINNET_PROFILE.caip2;
}
const flagOn = (v: string | undefined) => ["1", "true", "yes"].includes((v ?? "").trim().toLowerCase());

/** Proves the chain the marker will name (default: verifyAlgodMatchesProfile against ALGOD_URL / the public algod). */
export type NetworkVerifier = (profile: NetworkProfile) => Promise<{ genesisHash: string }>;

export interface MigrateOptions {
  /** R31-P3-4 tests only: runs inside the migrate transaction right after DDL. */
  afterDdlForTest?: (c: PoolClient) => Promise<void>;
  /** NETWORK for the write-once marker (default process.env.NETWORK). */
  network?: string;
  /** R24-P3-3: required for a mainnet marker (default process.env.ALLOW_MAINNET). */
  allowMainnet?: boolean;
  /** R24-P3-3: runs before the marker is written; its genesis hash must match the profile. */
  verifyNetwork?: NetworkVerifier;
  /**
   * R24-P3-1: SET ROLE to this (NOLOGIN) owner role inside the migration
   * transaction, so a login admin role migrates while every object stays
   * owned by the owner (default process.env.MIGRATE_SET_ROLE).
   */
  setRole?: string;
}

/**
 * Apply pending migrations. Idempotent, safe from several processes at once.
 * R23-P2-1: `network` (default process.env.NETWORK) sets the write-once
 * mr_network marker the first time v7+ is present; it is required then. A
 * later run with a different NETWORK is refused (the marker never changes).
 * R24-P3-3: before the marker is written, `verifyNetwork` (default: algod
 * /versions genesis + USDC ASA decimals) must prove the chain; mainnet needs
 * allowMainnet / ALLOW_MAINNET=1.
 */
/** R30-P3-1: migrate refuses while database-wide / ALTER ROLE ALL settings exist. */
export class DatabaseSettingsError extends Error {
  override name = "DatabaseSettingsError";
}

/** R31-P3-4: bounded migrate session timeouts (never 0). */
export const MIGRATE_STATEMENT_TIMEOUT = "10min";
export const MIGRATE_LOCK_TIMEOUT = "60s";
export const MIGRATE_IDLE_TIMEOUT = "10min";
async function assertNoDatabaseSettings(c: PoolClient, when: string): Promise<void> {
  const dbs = await c.query<{ n: number }>(
    "SELECT count(*)::int AS n FROM pg_catalog.pg_db_role_setting WHERE setrole = 0 AND setdatabase IN (0, (SELECT oid FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database()))",
  );
  if ((dbs.rows[0]?.n ?? 0) > 0) {
    throw new DatabaseSettingsError(`${dbs.rows[0]!.n} database-wide / ALTER ROLE ALL setting row(s) exist (pg_db_role_setting setrole=0) ${when}; reset them (ALTER DATABASE ... RESET ALL; ALTER ROLE ALL [IN DATABASE ...] RESET ALL) before migrating`);
  }
}

export async function migratePostgres(pool: Pool, opts: MigrateOptions = {}): Promise<{ from: number; to: number; network?: "testnet" | "mainnet"; role?: string }> {
  const allowMainnet = opts.allowMainnet ?? flagOn(process.env.ALLOW_MAINNET);
  const wanted = markerNetwork(opts.network ?? process.env.NETWORK, allowMainnet);
  const setRole = (opts.setRole ?? process.env.MIGRATE_SET_ROLE ?? "").trim();
  const verify: NetworkVerifier = opts.verifyNetwork ?? ((p) => verifyAlgodMatchesProfile(p, { algodUrl: process.env.ALGOD_URL, token: process.env.ALGOD_TOKEN }));
  return tx(pool, "mr:migrate", async (c) => {
    let role: string | undefined;
    // R30-P3-1: pin the session (never inherit search_path / timeouts from settings) and
    // refuse while ALTER DATABASE SET / ALTER ROLE ALL [IN DATABASE] SET rows exist.
    await c.query("SET LOCAL search_path = public, pg_catalog");
    // R31-P3-4: timeouts are bounded (never 0 = unbounded) so a stuck lock cannot hang a deploy.
    await c.query(`SET LOCAL statement_timeout = '${MIGRATE_STATEMENT_TIMEOUT}'`);
    await c.query(`SET LOCAL lock_timeout = '${MIGRATE_LOCK_TIMEOUT}'`);
    await c.query(`SET LOCAL idle_in_transaction_session_timeout = '${MIGRATE_IDLE_TIMEOUT}'`);
    await assertNoDatabaseSettings(c, "before migrating");
    if (setRole) {
      if (!/^[a-z_][a-z0-9_]*$/.test(setRole)) throw new Error("MIGRATE_SET_ROLE must be a plain role name");
      await c.query(`SET LOCAL ROLE ${setRole}`);
      role = setRole;
      // Objects must end up owned by that role: refuse if it does not own the existing schema.
      const o = await c.query<{ owner: string | null }>("SELECT pg_get_userbyid(c.relowner) AS owner FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = current_schema() AND c.relname = 'mr_schema'");
      const owner = o.rows[0]?.owner;
      if (owner && owner !== setRole) throw new Error(`mr_schema is owned by ${owner}, not ${setRole}; refusing to migrate`);
    }
    await c.query("CREATE TABLE IF NOT EXISTS mr_schema (version integer PRIMARY KEY)");
    await c.query("ALTER TABLE mr_schema ADD COLUMN IF NOT EXISTS name text");
    await c.query("ALTER TABLE mr_schema ADD COLUMN IF NOT EXISTS applied_at timestamptz DEFAULT now()");
    const { rows } = await c.query<{ v: number | null }>("SELECT max(version) AS v FROM mr_schema");
    const from = rows[0]?.v ?? 0;
    if (from > PG_SCHEMA_VERSION) {
      throw new SchemaTooNewError(`database schema v${from} is newer than this build (v${PG_SCHEMA_VERSION}); refusing`);
    }
    // R55-P3-1: every applied version must carry the name this build expects (a renamed/rewritten migration
    // would otherwise be skipped silently). NULL names (rows from before the name column) are accepted.
    const applied = await c.query<{ version: number; name: string | null }>("SELECT version, name FROM mr_schema ORDER BY version");
    for (const r of applied.rows) {
      const m = MIGRATIONS.find((x) => x.version === r.version);
      if (!m) throw new SchemaNameMismatchError(`mr_schema has version ${r.version}, unknown to this build; refusing to migrate`);
      if (r.name !== null && r.name !== m.name) throw new SchemaNameMismatchError(`mr_schema v${r.version} is "${r.name}", this build expects "${m.name}"; refusing to migrate. If this database was migrated by a pre-release build, verify the schema matches and, as the schema owner, run UPDATE mr_schema SET name = '${m.name}' WHERE version = ${r.version}; then migrate again (see docs/ops/mainnet-provider-blockdaemon.md)`);
    }
    for (const m of MIGRATIONS) {
      if (m.version <= from) continue;
      await c.query(m.sql);
      await c.query("INSERT INTO mr_schema (version, name) VALUES ($1, $2)", [m.version, m.name]);
    }
    if (opts.afterDdlForTest) await opts.afterDdlForTest(c);
    // R31-P3-4: re-check after DDL, still inside the advisory-lock transaction, so a
    // setting added concurrently (between the first check and here) aborts the migration.
    await assertNoDatabaseSettings(c, "after DDL");
    const cur = await c.query<{ network: "testnet" | "mainnet" }>("SELECT network FROM mr_network WHERE singleton");
    let network = cur.rows[0]?.network;
    if (!network) {
      if (!wanted) throw new NetworkMarkerError("NETWORK (testnet|mainnet) is required to set the mr_network marker");
      const prof = wanted === "mainnet" ? MAINNET_PROFILE : TESTNET_PROFILE;
      const want = prof.caip2.slice("algorand:".length);
      let seen: string;
      try {
        seen = (await verify(prof)).genesisHash;
      } catch (e) {
        throw new NetworkMarkerError(`network check failed before writing the ${wanted} marker: ${String((e as Error)?.message ?? e)}`);
      }
      if (seen !== want) throw new NetworkMarkerError(`network check returned genesis ${seen}, expected ${want}; marker not written`);
      await c.query("INSERT INTO mr_network (network, genesis_hash) VALUES ($1, $2)", [wanted, want]);
      network = wanted;
    } else if (wanted && wanted !== network) {
      throw new NetworkMarkerError(`database network marker is ${network}; refusing to migrate with NETWORK=${wanted}`);
    }
    return { from, to: PG_SCHEMA_VERSION, network, ...(role ? { role } : {}) };
  });
}

/** Applied versions (ascending). */
export async function schemaVersions(pool: Pool): Promise<number[]> {
  const { rows } = await pool.query<{ version: number }>("SELECT version FROM mr_schema ORDER BY version");
  return rows.map((r) => r.version);
}

/** Run `fn` in a transaction holding an advisory lock on `lockName`. */
async function tx<T>(pool: Pool, lockName: string, fn: (c: PoolClient) => Promise<T>): Promise<T> {
  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    await c.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [lockName]);
    const out = await fn(c);
    await c.query("COMMIT");
    return out;
  } catch (e) {
    await c.query("ROLLBACK").catch(() => undefined);
    throw e;
  } finally {
    c.release();
  }
}

const num = (v: unknown): number => (v === null || v === undefined ? NaN : Number(v));

// ---------------------------------------------------------------------------

export class PgChallengeStore implements ChallengeStore {
  constructor(
    private readonly pool: Pool,
    private readonly opts: {
      audience: string;
      ttlMs?: number;
      maxEntries?: number;
      now?: () => number;
    },
  ) {}
  private now(): number {
    return this.opts.now ? this.opts.now() : Date.now();
  }

  async issue(action: OperatorAction, subjectId: string): Promise<OperatorChallenge> {
    const now = this.now();
    const ttl = this.opts.ttlMs ?? DEFAULT_CHALLENGE_TTL_MS;
    const max = this.opts.maxEntries ?? 10_000;
    const ch = newOperatorChallenge(action, subjectId, this.opts.audience, now, ttl);
    await tx(this.pool, `mr:ch:${this.opts.audience}`, async (c) => {
      // Same sweep as the in-memory store: keep used entries until expiry + grace.
      await c.query(
        "DELETE FROM mr_challenges WHERE audience = $1 AND expires_ms + $2 < $3",
        [this.opts.audience, CHALLENGE_SWEEP_GRACE_MS, now],
      );
      const { rows } = await c.query(
        "SELECT count(*)::bigint AS n FROM mr_challenges WHERE audience = $1",
        [this.opts.audience],
      );
      if (num(rows[0].n) >= max) throw new Error("operator challenge store full");
      await c.query(
        "INSERT INTO mr_challenges (audience, nonce, challenge, expires_ms) VALUES ($1, $2, $3, $4)",
        [this.opts.audience, ch.nonce, JSON.stringify(ch), now + ttl],
      );
    });
    return ch;
  }

  async consume(nonce: string): Promise<ChallengeConsumeResult> {
    // Single statement flip: exactly one caller across all processes wins.
    const won = await this.pool.query(
      `UPDATE mr_challenges SET used = true
        WHERE audience = $1 AND nonce = $2 AND used = false
        RETURNING challenge, expires_ms`,
      [this.opts.audience, nonce],
    );
    if (won.rowCount === 1) {
      const row = won.rows[0];
      if (this.now() > num(row.expires_ms)) return { ok: false, error: "expired_nonce" };
      return { ok: true, challenge: row.challenge as OperatorChallenge };
    }
    const seen = await this.pool.query(
      "SELECT 1 FROM mr_challenges WHERE audience = $1 AND nonce = $2",
      [this.opts.audience, nonce],
    );
    return { ok: false, error: seen.rowCount ? "replayed_nonce" : "unknown_nonce" };
  }
}

// ---------------------------------------------------------------------------

export class PgRateLimitStore implements RateLimitStore {
  constructor(
    private readonly pool: Pool,
    private readonly opts: {
      name: string;
      windowMs: number;
      perKey: number;
      global: number;
      now?: () => number;
    },
  ) {}

  async take(key: string): Promise<boolean> {
    const now = this.opts.now ? this.opts.now() : Date.now();
    const cutoff = now - this.opts.windowMs;
    const name = this.opts.name;
    return tx(this.pool, `mr:rl:${name}`, async (c) => {
      await c.query("DELETE FROM mr_rate_events WHERE limiter = $1 AND ts_ms <= $2", [name, cutoff]);
      const { rows } = await c.query(
        `SELECT count(*)::bigint AS g, count(*) FILTER (WHERE key = $2)::bigint AS k
           FROM mr_rate_events WHERE limiter = $1`,
        [name, key],
      );
      if (num(rows[0].g) >= this.opts.global) return false;
      if (num(rows[0].k) >= this.opts.perKey) return false;
      await c.query("INSERT INTO mr_rate_events (limiter, key, ts_ms) VALUES ($1, $2, $3)", [name, key, now]);
      return true;
    });
  }
}

// ---------------------------------------------------------------------------

type QueueRow = {
  id: string;
  status: QueueStatus;
  created_at: string;
  created_ms: string;
  finalized_ms: string | null;
  client_key: string;
  collected: boolean;
  request: unknown;
  token_hash: Buffer;
  signature: string | null;
  public_key: string | null;
  address: string | null;
};

function rowToItem<R>(r: QueueRow): QueueItem<R> {
  const item: QueueItem<R> = {
    id: r.id,
    status: r.status,
    createdAt: r.created_at,
    createdMs: num(r.created_ms),
    clientKey: r.client_key,
    request: r.request as R,
    requesterTokenHash: Buffer.from(r.token_hash),
  };
  if (r.finalized_ms !== null) item.finalizedMs = num(r.finalized_ms);
  if (r.collected) item.collected = true;
  if (r.signature !== null) item.signature = r.signature;
  if (r.public_key !== null) item.publicKey = r.public_key;
  if (r.address !== null) item.address = r.address;
  return item;
}

export class PgQueueStore<R = unknown> implements QueueStore<R> {
  constructor(
    private readonly pool: Pool,
    private readonly opts: { queue: string; limits: QueueLimits },
  ) {}
  private get q(): string {
    return this.opts.queue;
  }

  private async sweep(c: Pool | PoolClient, now: number): Promise<void> {
    const l = this.opts.limits;
    await c.query(
      `UPDATE mr_queue SET status = 'expired', finalized_ms = $2
        WHERE queue = $1 AND status = 'pending' AND $2 - created_ms >= $3`,
      [this.q, now, l.pendingTtlMs],
    );
    await c.query(
      `DELETE FROM mr_queue
        WHERE queue = $1 AND status <> 'pending' AND $2 - COALESCE(finalized_ms, $2) >= $3`,
      [this.q, now, l.retentionMs],
    );
  }

  async insert(item: QueueItem<R>, now: number): Promise<QueueInsertResult> {
    const l = this.opts.limits;
    return tx(this.pool, `mr:q:${this.q}`, async (c) => {
      await this.sweep(c, now);
      const { rows } = await c.query(
        `SELECT count(*)::bigint AS total,
                count(*) FILTER (WHERE status = 'pending' AND client_key = $2)::bigint AS mine
           FROM mr_queue WHERE queue = $1`,
        [this.q, item.clientKey],
      );
      if (num(rows[0].mine) >= l.maxPendingPerClient) return "client_pending_cap";
      if (num(rows[0].total) >= l.maxPending) {
        // OA-P2-N: only collected, finalized items are evictable.
        const ev = await c.query(
          `DELETE FROM mr_queue WHERE queue = $1 AND id = (
             SELECT id FROM mr_queue
              WHERE queue = $1 AND status <> 'pending' AND collected
              ORDER BY finalized_ms ASC, seq ASC LIMIT 1)
           RETURNING id`,
          [this.q],
        );
        if (!ev.rowCount) return "queue_full";
      }
      await c.query(
        `INSERT INTO mr_queue
           (queue, id, status, created_at, created_ms, finalized_ms, client_key, collected,
            request, token_hash, signature, public_key, address)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
        [
          this.q,
          item.id,
          item.status,
          item.createdAt,
          item.createdMs,
          item.finalizedMs ?? null,
          item.clientKey,
          item.collected ?? false,
          JSON.stringify(item.request),
          item.requesterTokenHash,
          item.signature ?? null,
          item.publicKey ?? null,
          item.address ?? null,
        ],
      );
      return "ok";
    });
  }

  async get(id: string, now: number): Promise<QueueItem<R> | null> {
    await this.sweep(this.pool, now);
    const { rows } = await this.pool.query<QueueRow>(
      "SELECT * FROM mr_queue WHERE queue = $1 AND id = $2",
      [this.q, id],
    );
    return rows[0] ? rowToItem<R>(rows[0]) : null;
  }

  async list(now: number): Promise<QueueItem<R>[]> {
    await this.sweep(this.pool, now);
    const { rows } = await this.pool.query<QueueRow>(
      "SELECT * FROM mr_queue WHERE queue = $1 ORDER BY seq ASC",
      [this.q],
    );
    return rows.map((r) => rowToItem<R>(r));
  }

  async countPending(now: number): Promise<number> {
    await this.sweep(this.pool, now);
    const { rows } = await this.pool.query(
      "SELECT count(*)::bigint AS n FROM mr_queue WHERE queue = $1 AND status = 'pending'",
      [this.q],
    );
    return num(rows[0].n);
  }

  async finalize(
    id: string,
    status: "approved" | "rejected",
    patch: { signature?: string; publicKey?: string; address?: string },
    now: number,
  ): Promise<QueueFinalizeResult<R>> {
    await this.sweep(this.pool, now);
    const { rows } = await this.pool.query<QueueRow>(
      `UPDATE mr_queue
          SET status = $3, finalized_ms = $4,
              signature = COALESCE($5, signature),
              public_key = COALESCE($6, public_key),
              address = COALESCE($7, address)
        WHERE queue = $1 AND id = $2 AND status = 'pending'
        RETURNING *`,
      [this.q, id, status, now, patch.signature ?? null, patch.publicKey ?? null, patch.address ?? null],
    );
    if (rows[0]) return { ok: true, item: rowToItem<R>(rows[0]) };
    const cur = await this.pool.query<{ status: QueueStatus }>(
      "SELECT status FROM mr_queue WHERE queue = $1 AND id = $2",
      [this.q, id],
    );
    if (!cur.rows[0]) return { ok: false, error: "not_found" };
    return { ok: false, error: "not_pending", status: cur.rows[0].status };
  }

  async markCollected(id: string): Promise<void> {
    await this.pool.query(
      "UPDATE mr_queue SET collected = true WHERE queue = $1 AND id = $2 AND status <> 'pending'",
      [this.q, id],
    );
  }
}

// ---------------------------------------------------------------------------

type MandateRow = { mandate: unknown; server_verified: boolean; verified_at: string | null };

function rowToStored(r: MandateRow): StoredMandate | null {
  const p = IntentMandateSchema.safeParse(r.mandate);
  if (!p.success) return null;
  return {
    mandate: p.data,
    server: r.server_verified
      ? { signatureVerified: true, verifiedAt: r.verified_at ?? undefined }
      : { signatureVerified: false },
  };
}

export class PgMandateStore implements MandateStore {
  constructor(
    private readonly pool: Pool,
    private readonly opts: { store?: string } = {},
  ) {}
  private get s(): string {
    return this.opts.store ?? "console";
  }

  async list(): Promise<StoredMandate[]> {
    const { rows } = await this.pool.query<MandateRow>(
      "SELECT mandate, server_verified, verified_at FROM mr_mandates WHERE store = $1 ORDER BY seq ASC",
      [this.s],
    );
    return rows.map(rowToStored).filter((x): x is StoredMandate => x !== null);
  }

  async get(id: string): Promise<StoredMandate | null> {
    const { rows } = await this.pool.query<MandateRow>(
      "SELECT mandate, server_verified, verified_at FROM mr_mandates WHERE store = $1 AND id = $2",
      [this.s, id],
    );
    return rows[0] ? rowToStored(rows[0]) : null;
  }

  async create(
    input: IntentMandate,
    opts: { maxMandates?: number; signatureVerified?: boolean; now?: number } = {},
  ): Promise<StoredMandate> {
    const nowIso = new Date(opts.now ?? Date.now()).toISOString();
    const mandate = IntentMandateSchema.parse({
      ...input,
      revoked: input.revoked ?? false,
      createdAt: input.createdAt ?? nowIso,
    });
    const verified = opts.signatureVerified === true;
    return tx(this.pool, `mr:m:${this.s}`, async (c) => {
      const dup = await c.query("SELECT 1 FROM mr_mandates WHERE store = $1 AND id = $2", [this.s, mandate.id]);
      if (dup.rowCount) throw new MandateExistsError(mandate.id);
      if (opts.maxMandates !== undefined) {
        const { rows } = await c.query("SELECT count(*)::bigint AS n FROM mr_mandates WHERE store = $1", [this.s]);
        if (num(rows[0].n) >= opts.maxMandates) throw new StoreFullError(opts.maxMandates);
      }
      await c.query(
        `INSERT INTO mr_mandates (store, id, mandate, server_verified, verified_at)
         VALUES ($1, $2, $3, $4, $5)`,
        [this.s, mandate.id, JSON.stringify(mandate), verified, verified ? nowIso : null],
      );
      return {
        mandate,
        server: verified ? { signatureVerified: true, verifiedAt: nowIso } : { signatureVerified: false },
      };
    });
  }

  async revoke(id: string): Promise<StoredMandate | null> {
    const { rows } = await this.pool.query<MandateRow>(
      `UPDATE mr_mandates SET mandate = jsonb_set(mandate, '{revoked}', 'true'::jsonb)
        WHERE store = $1 AND id = $2
        RETURNING mandate, server_verified, verified_at`,
      [this.s, id],
    );
    return rows[0] ? rowToStored(rows[0]) : null;
  }
}

// ---------------------------------------------------------------------------

export class PgReceiptStore<T extends ReceiptLike> implements ReceiptStore<T> {
  constructor(
    private readonly pool: Pool,
    private readonly opts: { store?: string } = {},
  ) {}
  private get s(): string {
    return this.opts.store ?? "demo-api";
  }
  async add(r: T): Promise<void> {
    await this.pool.query(
      "INSERT INTO mr_receipts (store, receipt_id, receipt) VALUES ($1, $2, $3)",
      [this.s, r.receiptId, JSON.stringify(r)],
    );
  }
  async get(id: string): Promise<T | null> {
    const { rows } = await this.pool.query<{ receipt: T }>(
      "SELECT receipt FROM mr_receipts WHERE store = $1 AND receipt_id = $2",
      [this.s, id],
    );
    return rows[0]?.receipt ?? null;
  }
  async list(limit: number): Promise<T[]> {
    const { rows } = await this.pool.query<{ receipt: T }>(
      "SELECT receipt FROM mr_receipts WHERE store = $1 ORDER BY seq DESC LIMIT $2",
      [this.s, Math.max(0, Math.floor(limit))],
    );
    return rows.map((r) => r.receipt);
  }
  /** T7 daily cap: settled amount by payer since `sinceMs`, exact (micro-units). */
  async sumSpentMicro(payer: string, sinceMs: number): Promise<bigint> {
    const { rows } = await this.pool.query<{ amount: string }>(
      `SELECT receipt->>'amount' AS amount FROM mr_receipts
        WHERE store = $1 AND receipt->>'payer' = $2
          AND (receipt->>'createdAt')::timestamptz >= to_timestamp($3::double precision / 1000)`,
      [this.s, payer, sinceMs],
    );
    return rows.reduce((acc, r) => acc + toMicro(r.amount), 0n);
  }
}

// ---------------------------------------------------------------------------
// T7-P2-1 / T7-P2-2: spend reservations, per-payer advisory lock

type SpendRow = {
  id: string; payer: string; amount_micro: string; status: SpendStatus;
  created_ms: string; updated_ms: string; tx_id: string | null; last_valid: string | null;
};
const toRes = (r: SpendRow): SpendReservation => ({
  id: r.id, payer: r.payer, amountMicro: BigInt(r.amount_micro), status: r.status,
  createdMs: Number(r.created_ms), updatedMs: Number(r.updated_ms), txId: r.tx_id,
  lastValid: r.last_valid === null || r.last_valid === undefined ? null : Number(r.last_valid),
});

export class PgSpendStore implements SpendStore {
  constructor(
    private readonly pool: Pool,
    private readonly opts: { store?: string } = {},
  ) {}
  private get s(): string {
    return this.opts.store ?? "demo-api";
  }
  private async sum(c: Pool | PoolClient, payer: string, sinceMs: number): Promise<bigint> {
    const { rows } = await c.query<{ n: string | null }>(
      `SELECT COALESCE(sum(amount_micro), 0)::text AS n FROM mr_spend
        WHERE store = $1 AND payer = $2 AND created_ms >= $3 AND status IN ('pending','settled','ambiguous')`,
      [this.s, payer, sinceMs],
    );
    return BigInt(rows[0]?.n ?? "0");
  }
  spentSinceMicro(payer: string, sinceMs: number): Promise<bigint> {
    return this.sum(this.pool, payer, sinceMs);
  }
  /** Check + insert under a per-payer advisory lock: N processes, one cap. */
  reserve(i: { id: string; payer: string; amountMicro: bigint; caps: SpendCaps; nowMs: number }): Promise<ReserveResult> {
    return tx(this.pool, `mr:spend:${this.s}:${i.payer}`, async (c) => {
      const spent = await this.sum(c, i.payer, utcDayStartMs(i.nowMs));
      if (i.amountMicro > i.caps.perPaymentMicro) return { ok: false, reason: "per_payment_cap_exceeded", spentBeforeMicro: spent };
      if (spent + i.amountMicro > i.caps.perDayMicro) return { ok: false, reason: "daily_cap_exceeded", spentBeforeMicro: spent };
      const { rows } = await c.query<SpendRow>(
        `INSERT INTO mr_spend (store, id, payer, amount_micro, status, created_ms, updated_ms)
         VALUES ($1, $2, $3, $4, 'pending', $5, $5)
         RETURNING id, payer, amount_micro::text, status, created_ms::text, updated_ms::text, tx_id, last_valid::text`,
        [this.s, i.id, i.payer, i.amountMicro.toString(), i.nowMs],
      );
      return { ok: true, reservation: toRes(rows[0]!), spentBeforeMicro: spent };
    });
  }
  async attachTxId(id: string, txId: string, nowMs: number, lastValid?: number | null): Promise<boolean> {
    const r = await this.pool.query(
      // R23-P3-1: pin once (the mr_spend_guard trigger refuses re-pinning)
      "UPDATE mr_spend SET tx_id = $3, updated_ms = $4, last_valid = $5 WHERE store = $1 AND id = $2 AND status = 'pending' AND tx_id IS NULL AND last_valid IS NULL",
      [this.s, id, txId, nowMs, lastValid ?? null],
    );
    return (r.rowCount ?? 0) === 1;
  }
  /**
   * v11 (§2.1): store the exact signed bytes submitted, with fields derived from those bytes (never from the
   * client's claims), and the submit round. submit_at is the DB clock. Write-once (mr_spend_signed_guard);
   * pins tx_id / last_valid in the same statement when they were not pinned yet.
   */
  async attachSignedTxn(id: string, i: { signedTxn: Uint8Array; kind: SignedTxnKind; payer?: string; submitRound: number; nowMs: number }): Promise<DerivedTxn | null> {
    let payer = i.payer;
    if (payer === undefined) {
      const { rows } = await this.pool.query<{ payer: string }>("SELECT payer FROM mr_spend WHERE store = $1 AND id = $2", [this.s, id]);
      if (!rows[0]) return null;
      payer = rows[0].payer;
    }
    const d = deriveSignedTxn(i.signedTxn, i.kind, payer);
    if (d.sender !== payer) throw new SignedTxnError("signed_txn sender is not the reserved payer");
    if (!Number.isSafeInteger(i.submitRound) || i.submitRound < 0) throw new SignedTxnError("submit round");
    const r = await this.pool.query(
      `UPDATE mr_spend SET signed_txn = $3, signed_txn_kind = $4, tx_id = $5, first_valid = $6, last_valid = $7, group_id = $8,
              sender = $9, submit_round = $10, submit_at = clock_timestamp(), updated_ms = $11
        WHERE store = $1 AND id = $2 AND status = 'pending' AND signed_txn IS NULL
          AND (tx_id IS NULL OR (tx_id = $5 AND last_valid = $7))`,
      [this.s, id, Buffer.from(i.signedTxn), i.kind, d.txId, d.firstValid, d.lastValid, d.groupId, d.sender, i.submitRound, i.nowMs],
    );
    return (r.rowCount ?? 0) === 1 ? d : null;
  }
  /**
   * R23-P3-1: the app's only status path is the SECURITY DEFINER
   * mr_spend_app_finalize (pending -> settled/ambiguous/released; released
   * only while no txId is pinned). The DB clock sets updated_ms.
   */
  async finalize(id: string, outcome: "settled" | "ambiguous" | "released", _nowMs: number, txId?: string | null): Promise<boolean> {
    const { rows } = await this.pool.query<{ ok: boolean }>(
      "SELECT mr_spend_app_finalize($1, $2, $3, $4) AS ok",
      [this.s, id, outcome, txId ?? null],
    );
    return rows[0]?.ok === true;
  }
  /** Not available on Postgres (R22/R23): use reconcileSpendPg (settle) and `spend release` (proof). */
  async reconcile(_id: string, _outcome: "settled" | "released", _nowMs: number, _txId?: string | null): Promise<boolean> {
    throw new Error("PgSpendStore.reconcile is disabled: use reconcileSpendPg (mr_reconcile) or `spend release` (mr_release)");
  }
  async get(id: string): Promise<SpendReservation | null> {
    const { rows } = await this.pool.query<SpendRow>(
      "SELECT id, payer, amount_micro::text, status, created_ms::text, updated_ms::text, tx_id, last_valid::text FROM mr_spend WHERE store = $1 AND id = $2",
      [this.s, id],
    );
    return rows[0] ? toRes(rows[0]) : null;
  }
  async listUnresolved(nowMs: number, pendingOlderThanMs: number, limit: number): Promise<SpendReservation[]> {
    const { rows } = await this.pool.query<SpendRow>(
      `SELECT id, payer, amount_micro::text, status, created_ms::text, updated_ms::text, tx_id, last_valid::text FROM mr_spend
        WHERE store = $1 AND (status = 'ambiguous' OR (status = 'pending' AND created_ms <= $2))
        ORDER BY created_ms LIMIT $3`,
      [this.s, nowMs - pendingOlderThanMs, Math.max(0, Math.floor(limit))],
    );
    return rows.map(toRes);
  }
  async recordSettled(r: { id: string; payer: string; amountMicro: bigint; createdMs: number; txId?: string | null }): Promise<boolean> {
    const q = await this.pool.query(
      `INSERT INTO mr_spend (store, id, payer, amount_micro, status, created_ms, updated_ms, tx_id)
       VALUES ($1, $2, $3, $4, 'settled', $5, $5, $6) ON CONFLICT DO NOTHING`,
      [this.s, r.id, r.payer, r.amountMicro.toString(), r.createdMs, r.txId ?? null],
    );
    return (q.rowCount ?? 0) === 1;
  }
}
