/**
 * v16: fully automatic operation (no human unlock, no human pause or kill switch; docs §23).
 *
 * - mr_pause_state (one row per network): the DB's own record of a TAMPER / INTEGRITY pause. While paused, every
 *   attested release is refused. tamper_count is persisted here and drives the exponential cooldown:
 *   base_cooldown_s * 2^(tamper_count - 1), exponent capped at 6 (6 h, 12 h, 24 h ... 16 d with the 6 h base). A
 *   tamper more than 30 days after the previous one restarts the count at 1. MainNet's base is >= 6 h (CHECK).
 * - mr_tamper_pause(reason): machine detectors (release automation, reconcile, monitor) record a pause. Pausing is
 *   fail-safe and idempotent while paused. Nothing in the DB can lift it except mr_tamper_resume.
 * - mr_tamper_resume(smsg, ssig, cmsg, csig): a FRESH 2-of-2 resume quorum. The signer's MR-RESUME-ATTEST-v1 (its
 *   pinned mr_signer_key) and mr-verifier's MR-RESUME-COSIGN-v1 (its pinned mr_cosigner_key, bound to sha256 of
 *   the signer's message), both restricted JCS, both naming the CURRENT pause_seq and tamper_count, the same chain
 *   head, issuedAt within +-60 s of the DB clock, expiry <= 15 min, nonces single-use (mr_resume_nonce), and the two
 *   keys in different trust-domain PROVIDERS (as v12). Refused before paused_at + cooldown.
 * - mr_release_caps: per-release and rolling-24 h released amount, enforced in the DB on every attested release.
 *   These are the loss bound. Owner-only: changed only by a migration / redeploy (admin window), every change is
 *   appended to mr_config_audit (append-only).
 * - mr_spend_release_attested (8-arg) becomes a wrapper: pause check + caps, then the v12 function (renamed
 *   mr_spend_release_attested_v12, internal). The 6-arg form already calls the 8-arg by name.
 * Never edit after release; append v14.
 * R66-P3-4: FROZEN. The sha256 of v16Sql() is pinned (v17-delta.ts V16_SQL_SHA256); changes go in v17-delta.ts and later.
 */
export const RESUME_PREFIX = "MR-RESUME-ATTEST-v1\n";
export const RESUME_COSIGN_PREFIX = "MR-RESUME-COSIGN-v1\n";
export const RESUME_MSG_KEYS = ["chainHead", "chainSeq", "expiry", "genesisHash", "issuedAt", "keyId", "network", "nonce", "pauseSeq", "tamperCount", "v"] as const;
export const RESUME_COSIGN_KEYS = ["attestHash", "chainHead", "chainSeq", "expiry", "genesisHash", "issuedAt", "keyId", "network", "nonce", "pauseSeq", "v"] as const;
export const TAMPER_BASE_COOLDOWN_S = 21_600;
export const MAINNET_COOLDOWN_FLOOR_S = 21_600;
export const TAMPER_BACKOFF_MAX_EXP = 6;
export const TAMPER_DECAY_DAYS = 30;
/** Defaults seeded by v16 (micro-USDC). Change only with a new migration. */
export const RELEASE_CAPS_SEED = { mainnet: { perRelease: 10_000n, perDay: 50_000n }, testnet: { perRelease: 10_000_000n, perDay: 50_000_000n } };

/** Cooldown for the Nth tamper pause (mirrors the DB). */
export const tamperCooldownS = (base: number, count: number) => base * 2 ** Math.min(Math.max(count, 1) - 1, TAMPER_BACKOFF_MAX_EXP);

/** R62-P2-1: NOLOGIN role (created by deploy/sql/t11) that owns mr_tamper_pause / mr_tamper_resume. */
export const PAUSE_WRITER_ROLE = "mr_pause_writer";

export function v16Sql(): string {
  const arr = (a: readonly string[]) => `ARRAY['${a.join("','")}']`;
  return `
CREATE TABLE IF NOT EXISTS mr_pause_state (
  network         text PRIMARY KEY CHECK (network IN ('testnet', 'mainnet')),
  paused          boolean NOT NULL DEFAULT false,
  reason          text,
  paused_at       timestamptz,
  pause_seq       bigint NOT NULL DEFAULT 0 CHECK (pause_seq >= 0),
  tamper_count    integer NOT NULL DEFAULT 0 CHECK (tamper_count >= 0),
  base_cooldown_s integer NOT NULL DEFAULT ${TAMPER_BASE_COOLDOWN_S} CHECK (base_cooldown_s >= 1),
  resumed_at      timestamptz,
  CHECK (network <> 'mainnet' OR base_cooldown_s >= ${MAINNET_COOLDOWN_FLOOR_S}),
  CHECK (NOT paused OR (paused_at IS NOT NULL AND reason IS NOT NULL))
);
REVOKE ALL ON mr_pause_state FROM PUBLIC;
INSERT INTO mr_pause_state (network) VALUES ('mainnet'), ('testnet') ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS mr_resume_nonce (
  nonce     bytea PRIMARY KEY CHECK (length(nonce) = 32),
  network   text NOT NULL,
  pause_seq bigint NOT NULL,
  role      text NOT NULL CHECK (role IN ('signer', 'verifier')),
  tamper_count integer NOT NULL CHECK (tamper_count >= 1),
  -- R63-P2-1: the signed message + signature + key, so the monitor re-verifies every resume against the pinned keys
  key_id    text NOT NULL,
  msg       bytea NOT NULL,
  sig       bytea NOT NULL CHECK (length(sig) = 64),
  used_at   timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON mr_resume_nonce FROM PUBLIC;

-- R62-P2-1: append-only log of every tamper pause (the monitor checks mr_pause_state against it and mr_resume_nonce)
CREATE TABLE IF NOT EXISTS mr_pause_log (
  network      text NOT NULL,
  pause_seq    bigint NOT NULL CHECK (pause_seq >= 1),
  tamper_count integer NOT NULL CHECK (tamper_count >= 1),
  reason       text NOT NULL,
  paused_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (network, pause_seq)
);
REVOKE ALL ON mr_pause_log FROM PUBLIC;

CREATE TABLE IF NOT EXISTS mr_release_caps (
  network            text PRIMARY KEY CHECK (network IN ('testnet', 'mainnet')),
  max_release_micro  bigint NOT NULL CHECK (max_release_micro > 0),
  max_day_micro      bigint NOT NULL CHECK (max_day_micro > 0),
  CHECK (max_release_micro <= max_day_micro),
  -- R64-P2-1: MainNet upper bound (0.01 USDC per release, 0.05 USDC per rolling 24 h); raising it needs a new migration
  CONSTRAINT mr_release_caps_mainnet_max CHECK (network <> 'mainnet' OR (max_release_micro <= ${RELEASE_CAPS_SEED.mainnet.perRelease} AND max_day_micro <= ${RELEASE_CAPS_SEED.mainnet.perDay}))
);
REVOKE ALL ON mr_release_caps FROM PUBLIC;

-- R65-P2-1: the rolling-24 h cap basis. One row per release the wrapper counted, written only by the wrapper
-- (owner mr_pause_writer after t11), append-only. mr_release_nonce (app-owner table) is no longer the basis, and a
-- nonce row without a ledger row is refused (mr_v16_nonce_ledger), so _v11 can't release outside the wrapper.
CREATE TABLE IF NOT EXISTS mr_release_ledger (
  store        text NOT NULL,
  spend_id     text NOT NULL,
  network      text NOT NULL CHECK (network IN ('testnet', 'mainnet')),
  amount_micro bigint NOT NULL CHECK (amount_micro > 0),
  at           timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (store, spend_id)
);
CREATE INDEX IF NOT EXISTS mr_release_ledger_at ON mr_release_ledger (network, at);
REVOKE ALL ON mr_release_ledger FROM PUBLIC;

CREATE TABLE IF NOT EXISTS mr_config_audit (
  seq      bigserial PRIMARY KEY,
  at       timestamptz NOT NULL DEFAULT clock_timestamp(),
  actor    text NOT NULL,
  tbl      text NOT NULL,
  op       text NOT NULL,
  old_row  jsonb,
  new_row  jsonb
);
REVOKE ALL ON mr_config_audit FROM PUBLIC;

-- R62-P2-1: pause state, the pause log and resume nonces are written ONLY by the two SECURITY DEFINER functions, which
-- deploy/sql/t11 re-owns to the NOLOGIN role mr_pause_writer (nobody is a member; inside them current_user is
-- mr_pause_writer). No GUC / session flag is trusted: the table owner's own session can't pose as the functions, and
-- can't CREATE OR REPLACE them (not their owner). Disabling the trigger or replacing this guard is drift the monitor
-- pages only if left disabled (tgenabled; R64: a one-txn DISABLE/write/ENABLE is stopped by ownership + mr_v16_ddl_guard,
-- not by the page); a replaced guard pages (prosrc md5); a pause_seq / tamper_count that goes down or an unpause without its two nonces too.
CREATE OR REPLACE FUNCTION mr_v16_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE is_owner boolean; writer boolean := current_user::text = '${PAUSE_WRITER_ROLE}';
BEGIN
  SELECT pg_get_userbyid(c.relowner) = current_user::text INTO is_owner FROM pg_class c WHERE c.oid = TG_RELID;
  IF TG_OP IN ('TRUNCATE', 'DELETE') THEN
    RAISE EXCEPTION '%: % refused', TG_TABLE_NAME, TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF TG_TABLE_NAME = 'mr_config_audit' THEN
    IF TG_OP = 'UPDATE' OR NOT is_owner THEN RAISE EXCEPTION 'mr_config_audit: append-only' USING ERRCODE = 'insufficient_privilege'; END IF;
    RETURN NEW;
  END IF;
  IF TG_TABLE_NAME = 'mr_release_ledger' THEN
    IF TG_OP = 'UPDATE' OR NOT is_owner THEN RAISE EXCEPTION 'mr_release_ledger: written only by mr_spend_release_attested' USING ERRCODE = 'insufficient_privilege'; END IF;
    RETURN NEW; -- release data, not config: not copied into mr_config_audit
  END IF;
  IF TG_TABLE_NAME IN ('mr_resume_nonce', 'mr_pause_log') THEN
    IF TG_OP = 'UPDATE' OR NOT writer THEN RAISE EXCEPTION '%: written only by mr_tamper_pause / mr_tamper_resume', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege'; END IF;
    RETURN NEW;
  END IF;
  IF TG_TABLE_NAME = 'mr_pause_state' THEN
    -- (nested IFs: NEW's pause_state fields only exist on this table)
    IF TG_OP = 'UPDATE' THEN
      IF writer THEN
        IF NEW.pause_seq < OLD.pause_seq OR (NEW.pause_seq = OLD.pause_seq AND NEW.tamper_count <> OLD.tamper_count) OR NEW.base_cooldown_s <> OLD.base_cooldown_s THEN
          RAISE EXCEPTION 'mr_pause_state: counters only move forward' USING ERRCODE = 'insufficient_privilege';
        END IF;
        RETURN NEW;
      END IF;
      -- R63-P2-1: the table is owned by mr_pause_writer (t11); the app owner holds only UPDATE (base_cooldown_s), so a
      -- redeploy may change the cooldown base and nothing else; pause / count / seq never by hand
      IF (NEW.paused, NEW.reason, NEW.paused_at, NEW.pause_seq, NEW.tamper_count, NEW.resumed_at)
         IS DISTINCT FROM (OLD.paused, OLD.reason, OLD.paused_at, OLD.pause_seq, OLD.tamper_count, OLD.resumed_at) THEN
        RAISE EXCEPTION 'mr_pause_state: pause state changes only through mr_tamper_pause / mr_tamper_resume' USING ERRCODE = 'insufficient_privilege';
      END IF;
    END IF;
    IF TG_OP = 'INSERT' THEN
      IF NEW.paused OR NEW.tamper_count <> 0 OR NEW.pause_seq <> 0 THEN
        RAISE EXCEPTION 'mr_pause_state: rows start unpaused with zero counters' USING ERRCODE = 'insufficient_privilege';
      END IF;
    END IF;
  ELSIF NOT is_owner THEN
    RAISE EXCEPTION '%: owner only', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
  END IF;
  -- R64-P2-1: mr_config_audit is owned by mr_pause_writer (t11); rows go in only through mr_v16_audit (same owner)
  PERFORM public.mr_v16_audit(TG_TABLE_NAME::text, TG_OP::text, CASE WHEN TG_OP = 'UPDATE' THEN to_jsonb(OLD) END, to_jsonb(NEW));
  RETURN NEW;
END $fn$;
-- R64-P2-1: the audit append (SECURITY DEFINER, owned like mr_config_audit; actor = the login, session_user)
CREATE OR REPLACE FUNCTION mr_v16_audit(p_tbl text, p_op text, p_old jsonb, p_new jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
BEGIN
  -- R65-P3-1: only from inside a guard trigger on a protected table (a direct call by the owner can't append rows)
  IF pg_trigger_depth() < 1 OR p_tbl NOT IN ('mr_pause_state', 'mr_release_caps') OR p_op NOT IN ('INSERT', 'UPDATE') THEN
    RAISE EXCEPTION 'mr_v16_audit: only the v16 guard trigger writes mr_config_audit' USING ERRCODE = 'insufficient_privilege';
  END IF;
  INSERT INTO public.mr_config_audit (actor, tbl, op, old_row, new_row) VALUES (session_user::text, p_tbl, p_op, p_old, p_new);
END $fn$;
REVOKE ALL ON FUNCTION mr_v16_audit(text, text, jsonb, jsonb) FROM PUBLIC;
DO $t$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['mr_pause_state', 'mr_resume_nonce', 'mr_pause_log', 'mr_release_caps', 'mr_config_audit', 'mr_release_ledger'] LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I', t || '_guard', t);
    EXECUTE format('CREATE TRIGGER %I BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION mr_v16_guard()', t || '_guard', t);
    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I', t || '_guard_t', t);
    EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION mr_v16_guard()', t || '_guard_t', t);
  END LOOP;
END $t$;
-- R65-P2-1: every attested release (mr_release_nonce row, written by _v11) must have been counted by the wrapper first
CREATE OR REPLACE FUNCTION mr_v16_nonce_ledger() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $fn$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM public.mr_release_ledger l WHERE l.store = NEW.store AND l.spend_id = NEW.spend_id) THEN
    RAISE EXCEPTION 'mr_release_nonce: release % / % was not counted by mr_spend_release_attested (caps ledger)', NEW.store, NEW.spend_id USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $fn$;
REVOKE ALL ON FUNCTION mr_v16_nonce_ledger() FROM PUBLIC;
DROP TRIGGER IF EXISTS mr_release_nonce_ledger ON mr_release_nonce;
CREATE TRIGGER mr_release_nonce_ledger BEFORE INSERT ON mr_release_nonce FOR EACH ROW EXECUTE FUNCTION mr_v16_nonce_ledger();
INSERT INTO mr_release_caps (network, max_release_micro, max_day_micro) VALUES
  ('mainnet', ${RELEASE_CAPS_SEED.mainnet.perRelease}, ${RELEASE_CAPS_SEED.mainnet.perDay}),
  ('testnet', ${RELEASE_CAPS_SEED.testnet.perRelease}, ${RELEASE_CAPS_SEED.testnet.perDay})
ON CONFLICT DO NOTHING;

CREATE OR REPLACE FUNCTION mr_v16_cooldown(base integer, cnt integer) RETURNS interval LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$
  SELECT make_interval(secs => base::double precision * power(2, least(greatest(cnt, 1) - 1, ${TAMPER_BACKOFF_MAX_EXP})))
$fn$;

-- a tamper / integrity pause. Idempotent while paused (the first reason and time stand).
CREATE OR REPLACE FUNCTION mr_tamper_pause(p_reason text) RETURNS TABLE (pause_seq bigint, tamper_count integer, resume_not_before timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE net text; s record;
BEGIN
  SELECT n.network INTO net FROM public.mr_network n WHERE n.singleton;
  IF net IS NULL THEN RAISE EXCEPTION 'mr_tamper_pause: network marker is not set' USING ERRCODE = 'check_violation'; END IF;
  IF p_reason IS NULL OR length(btrim(p_reason)) < 3 THEN RAISE EXCEPTION 'mr_tamper_pause: reason required' USING ERRCODE = 'check_violation'; END IF;
  SELECT * INTO s FROM public.mr_pause_state ps WHERE ps.network = net FOR UPDATE;
  IF NOT s.paused THEN
    UPDATE public.mr_pause_state ps SET paused = true, reason = left(p_reason, 500), paused_at = clock_timestamp(), pause_seq = ps.pause_seq + 1,
      tamper_count = CASE WHEN ps.paused_at IS NOT NULL AND ps.paused_at < clock_timestamp() - interval '${TAMPER_DECAY_DAYS} days' THEN 1 ELSE ps.tamper_count + 1 END
     WHERE ps.network = net;
    SELECT * INTO s FROM public.mr_pause_state ps WHERE ps.network = net;
    INSERT INTO public.mr_pause_log (network, pause_seq, tamper_count, reason, paused_at) VALUES (net, s.pause_seq, s.tamper_count, s.reason, s.paused_at);
  END IF;
  RETURN QUERY SELECT s.pause_seq, s.tamper_count, s.paused_at + public.mr_v16_cooldown(s.base_cooldown_s, s.tamper_count);
END $fn$;
REVOKE ALL ON FUNCTION mr_tamper_pause(text) FROM PUBLIC;

-- parses PREFIX + restricted JCS with the exact key set; raises otherwise
CREATE OR REPLACE FUNCTION mr_v16_parse(p_msg bytea, p_prefix text, p_keys text[]) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE pfx bytea := convert_to(p_prefix, 'UTF8'); body bytea; bt text; j jsonb;
BEGIN
  IF p_msg IS NULL OR length(p_msg) > 2048 OR length(p_msg) <= length(pfx) OR substring(p_msg FROM 1 FOR length(pfx)) <> pfx THEN
    RAISE EXCEPTION 'resume: prefix / length' USING ERRCODE = 'check_violation';
  END IF;
  body := substring(p_msg FROM length(pfx) + 1);
  IF position('\\x00'::bytea IN body) > 0 THEN RAISE EXCEPTION 'resume: NUL' USING ERRCODE = 'check_violation'; END IF;
  bt := convert_from(body, 'UTF8');
  IF bt !~ '^[ -~]+$' THEN RAISE EXCEPTION 'resume: not printable ASCII' USING ERRCODE = 'check_violation'; END IF;
  BEGIN j := bt::jsonb; EXCEPTION WHEN others THEN RAISE EXCEPTION 'resume: not JSON' USING ERRCODE = 'check_violation'; END;
  IF jsonb_typeof(j) <> 'object' OR public.mr_jcs(j) <> bt THEN RAISE EXCEPTION 'resume: not canonical (restricted JCS)' USING ERRCODE = 'check_violation'; END IF;
  IF (SELECT array_agg(x ORDER BY x) FROM jsonb_object_keys(j) x) <> (SELECT array_agg(x ORDER BY x) FROM unnest(p_keys) x) OR j->'v' <> '1'::jsonb THEN
    RAISE EXCEPTION 'resume: key set / version' USING ERRCODE = 'check_violation';
  END IF;
  RETURN j;
END $fn$;

CREATE OR REPLACE FUNCTION mr_tamper_resume(p_smsg bytea, p_ssig bytea, p_cmsg bytea, p_csig bytea)
RETURNS TABLE (resumed boolean, pause_seq bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE net text; net_hash text; s record; a jsonb; c jsonb; sk record; ck record; t timestamptz; iso text := '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$';
BEGIN
  SELECT n.network, n.genesis_hash INTO net, net_hash FROM public.mr_network n WHERE n.singleton;
  IF net IS NULL THEN RAISE EXCEPTION 'mr_tamper_resume: network marker is not set' USING ERRCODE = 'check_violation'; END IF;
  SELECT * INTO s FROM public.mr_pause_state ps WHERE ps.network = net FOR UPDATE;
  IF NOT s.paused THEN RAISE EXCEPTION 'mr_tamper_resume: not paused' USING ERRCODE = 'check_violation'; END IF;
  IF clock_timestamp() < s.paused_at + public.mr_v16_cooldown(s.base_cooldown_s, s.tamper_count) THEN
    RAISE EXCEPTION 'mr_tamper_resume: cooldown not over (tamper % of this period, not before %)', s.tamper_count, s.paused_at + public.mr_v16_cooldown(s.base_cooldown_s, s.tamper_count) USING ERRCODE = 'insufficient_privilege';
  END IF;
  a := public.mr_v16_parse(p_smsg, E'${RESUME_PREFIX.replace("\n", "\\n")}', ${arr(RESUME_MSG_KEYS)});
  c := public.mr_v16_parse(p_cmsg, E'${RESUME_COSIGN_PREFIX.replace("\n", "\\n")}', ${arr(RESUME_COSIGN_KEYS)});
  SELECT * INTO sk FROM public.mr_signer_key k WHERE k.key_id = a->>'keyId';
  IF NOT FOUND OR sk.revoked_at IS NOT NULL OR sk.network <> net THEN RAISE EXCEPTION 'mr_tamper_resume: signer key unknown, revoked or of another network' USING ERRCODE = 'insufficient_privilege'; END IF;
  SELECT * INTO ck FROM public.mr_cosigner_key k WHERE k.key_id = c->>'keyId';
  IF NOT FOUND OR ck.revoked_at IS NOT NULL OR ck.network <> net THEN RAISE EXCEPTION 'mr_tamper_resume: verifier key unknown, revoked or of another network' USING ERRCODE = 'insufficient_privilege'; END IF;
  IF ck.pubkey = sk.pubkey OR sk.trust_domain IS NULL OR split_part(sk.trust_domain, ':', 1) = split_part(ck.trust_domain, ':', 1) THEN
    RAISE EXCEPTION 'mr_tamper_resume: the two keys must be pinned in different trust domains (providers)' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NOT mr_crypto.mr_ed25519_verify(p_smsg, p_ssig, sk.pubkey) THEN RAISE EXCEPTION 'mr_tamper_resume: signer signature does not verify' USING ERRCODE = 'insufficient_privilege'; END IF;
  IF NOT mr_crypto.mr_ed25519_verify(p_cmsg, p_csig, ck.pubkey) THEN RAISE EXCEPTION 'mr_tamper_resume: verifier signature does not verify' USING ERRCODE = 'insufficient_privilege'; END IF;
  IF c->>'attestHash' <> encode(sha256(p_smsg), 'hex') THEN RAISE EXCEPTION 'mr_tamper_resume: verifier message is not bound to the signer message' USING ERRCODE = 'check_violation'; END IF;
  IF a->>'network' <> net OR c->>'network' <> net OR a->>'genesisHash' <> net_hash OR c->>'genesisHash' <> net_hash THEN
    RAISE EXCEPTION 'mr_tamper_resume: network / genesis' USING ERRCODE = 'check_violation'; END IF;
  IF jsonb_typeof(a->'pauseSeq') <> 'number' OR (a->>'pauseSeq')::bigint <> s.pause_seq OR c->'pauseSeq' <> a->'pauseSeq'
     OR jsonb_typeof(a->'tamperCount') <> 'number' OR (a->>'tamperCount')::int <> s.tamper_count THEN
    RAISE EXCEPTION 'mr_tamper_resume: not for the current pause (seq % / tamper %)', s.pause_seq, s.tamper_count USING ERRCODE = 'check_violation';
  END IF;
  IF jsonb_typeof(a->'chainSeq') <> 'number' OR c->'chainSeq' <> a->'chainSeq' OR a->>'chainHead' !~ '^[0-9a-f]{64}$' OR c->>'chainHead' <> a->>'chainHead' THEN
    RAISE EXCEPTION 'mr_tamper_resume: the two chain checks disagree' USING ERRCODE = 'check_violation';
  END IF;
  FOREACH t IN ARRAY ARRAY[(a->>'issuedAt')::timestamptz, (c->>'issuedAt')::timestamptz] LOOP
    IF t > clock_timestamp() + interval '60 seconds' OR t < clock_timestamp() - interval '60 seconds' THEN
      RAISE EXCEPTION 'mr_tamper_resume: issuedAt not within 60 s of the DB clock' USING ERRCODE = 'check_violation'; END IF;
  END LOOP;
  IF a->>'issuedAt' !~ iso OR c->>'issuedAt' !~ iso OR a->>'expiry' !~ iso OR c->>'expiry' !~ iso
     OR (a->>'expiry')::timestamptz <= clock_timestamp() OR (a->>'expiry')::timestamptz > clock_timestamp() + interval '15 minutes'
     OR (c->>'expiry')::timestamptz <= clock_timestamp() OR (c->>'expiry')::timestamptz > clock_timestamp() + interval '15 minutes'
     OR a->>'nonce' !~ '^[A-Za-z0-9_-]{43}$' OR c->>'nonce' !~ '^[A-Za-z0-9_-]{43}$' THEN
    RAISE EXCEPTION 'mr_tamper_resume: formats / expiry' USING ERRCODE = 'check_violation';
  END IF;
  BEGIN
    INSERT INTO public.mr_resume_nonce (nonce, network, pause_seq, role, tamper_count, key_id, msg, sig) VALUES
      (decode(translate(a->>'nonce', '-_', '+/') || '=', 'base64'), net, s.pause_seq, 'signer', s.tamper_count, sk.key_id, p_smsg, p_ssig),
      (decode(translate(c->>'nonce', '-_', '+/') || '=', 'base64'), net, s.pause_seq, 'verifier', s.tamper_count, ck.key_id, p_cmsg, p_csig);
  EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION 'mr_tamper_resume: nonce replay' USING ERRCODE = 'unique_violation';
  END;
  UPDATE public.mr_pause_state ps SET paused = false, resumed_at = clock_timestamp() WHERE ps.network = net;
  RETURN QUERY SELECT true, s.pause_seq;
END $fn$;
REVOKE ALL ON FUNCTION mr_tamper_resume(bytea, bytea, bytea, bytea) FROM PUBLIC;

ALTER FUNCTION mr_spend_release_attested(text, text, bytea, bytea, bytea, bytea, text, text) RENAME TO mr_spend_release_attested_v12;
REVOKE ALL ON FUNCTION mr_spend_release_attested_v12(text, text, bytea, bytea, bytea, bytea, text, text) FROM PUBLIC;
DO $rv$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mr_release') THEN
    EXECUTE 'REVOKE ALL ON FUNCTION mr_spend_release_attested_v12(text, text, bytea, bytea, bytea, bytea, text, text) FROM mr_release';
  END IF;
END $rv$;

CREATE OR REPLACE FUNCTION mr_spend_release_attested(p_store text, p_id text, p_msg bytea, p_sig bytea,
                                                     p_cmsg bytea, p_csig bytea, p_label text, p_reason text)
RETURNS TABLE (ok boolean, from_status text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE net text; ps record; cap record; amt bigint; st text; day bigint; r record;
BEGIN
  -- R62-P3-1: the rolling-24 h sum below is only race-free under READ COMMITTED (the table lock is taken after the
  -- snapshot under REPEATABLE READ / SERIALIZABLE, so two releases could each miss the other)
  IF current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'mr_spend_release_attested: must run under READ COMMITTED (is %)', current_setting('transaction_isolation') USING ERRCODE = 'insufficient_privilege';
  END IF;
  SELECT n.network INTO net FROM public.mr_network n WHERE n.singleton;
  IF net IS NULL THEN RAISE EXCEPTION 'mr_spend_release_attested: network marker is not set' USING ERRCODE = 'check_violation'; END IF;
  SELECT * INTO ps FROM public.mr_pause_state p WHERE p.network = net FOR SHARE;
  IF NOT FOUND OR ps.paused THEN
    RAISE EXCEPTION 'mr_spend_release_attested: paused (tamper/integrity: %); resumes only with a 2-of-2 resume quorum after the cooldown', coalesce(ps.reason, 'no pause row') USING ERRCODE = 'insufficient_privilege';
  END IF;
  SELECT * INTO cap FROM public.mr_release_caps c WHERE c.network = net;
  IF NOT FOUND THEN RAISE EXCEPTION 'mr_spend_release_attested: no release caps for %', net USING ERRCODE = 'insufficient_privilege'; END IF;
  SELECT s.amount_micro, s.status INTO amt, st FROM public.mr_spend s WHERE s.store = p_store AND s.id = p_id;
  IF amt IS NOT NULL AND st <> 'released' THEN
    IF amt > cap.max_release_micro THEN
      RAISE EXCEPTION 'mr_spend_release_attested: amount % above the per-release cap %', amt, cap.max_release_micro USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- R65-P2-1: the basis is the wrapper's own ledger (mr_pause_writer-owned, append-only), not mr_release_nonce
    LOCK TABLE public.mr_release_ledger IN SHARE ROW EXCLUSIVE MODE;
    SELECT coalesce(sum(l.amount_micro), 0) INTO day FROM public.mr_release_ledger l
     WHERE l.network = net AND l.at > clock_timestamp() - interval '24 hours' AND NOT (l.store = p_store AND l.spend_id = p_id);
    IF day + amt > cap.max_day_micro THEN
      RAISE EXCEPTION 'mr_spend_release_attested: rolling 24 h released amount would be % (cap %)', day + amt, cap.max_day_micro USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- (a refused release rolls this back with the transaction; an earlier counted-but-unreleased row stays counted)
    INSERT INTO public.mr_release_ledger (store, spend_id, network, amount_micro) VALUES (p_store, p_id, net, amt) ON CONFLICT DO NOTHING;
  END IF;
  SELECT * INTO r FROM public.mr_spend_release_attested_v12(p_store, p_id, p_msg, p_sig, p_cmsg, p_csig, p_label, p_reason);
  RETURN QUERY SELECT r.ok, r.from_status;
END $fn$;
REVOKE ALL ON FUNCTION mr_spend_release_attested(text, text, bytea, bytea, bytea, bytea, text, text) FROM PUBLIC;
DO $g$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mr_release') THEN
    EXECUTE 'GRANT EXECUTE ON FUNCTION mr_spend_release_attested(text, text, bytea, bytea, bytea, bytea, text, text) TO mr_release';
  END IF;
END $g$;
`;
}
