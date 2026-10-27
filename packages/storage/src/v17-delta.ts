/**
 * v17 (R66-P3-4): v16 is FROZEN from here (its text is pinned by sha256 in v17-delta.test.ts); every later change ships
 * as a delta. v16's text was revised in place during review (R62-R65), so a database that applied an earlier v16 text
 * would never get those revisions from a version-numbered runner. v17 converges any reviewed v16 state to the current
 * one, idempotently:
 *  - refuses (RAISE) a pre-R62 v16 (no mr_pause_log / mr_release_caps / mr_config_audit): rebuild that TestNet DB;
 *  - R63: mr_resume_nonce key_id / msg / sig (refuses existing rows without them; nothing can re-sign them);
 *  - R64: the MainNet caps CHECK; R65: mr_release_ledger + its index, the wrapper body, the nonce-ledger trigger;
 *  - BACKFILL: one ledger row per existing mr_release_nonce row (amount from mr_spend, at = used_at), so the rolling
 *    24 h sum counts releases made before the ledger existed and the monitor's ledger cross-check holds;
 *  - re-creates every v16 guard trigger (the ledger's refuses UPDATE / DELETE / TRUNCATE, any role but superuser replica).
 * On a database where deploy/sql/t11 already ran, the v16 objects belong to mr_pause_writer: apply as a superuser in a
 * deploy window (SET mr.ddl_window = 'open'; SET ROLE is not needed), then re-run t11. Never edit after release; append v18.
 */
import { v16Sql } from "./v16-resume.js";

export const V16_SQL_SHA256 = "1e0dc0f232225d30350fb943487b6e100b7d8819e3f88531d385f0603ae64e21";

/** One `CREATE OR REPLACE FUNCTION <head> ... END $fn$;` block from the frozen v16 text. */
export function v16Block(head: string): string {
  const s = v16Sql();
  const i = s.indexOf(`CREATE OR REPLACE FUNCTION ${head}`);
  if (i < 0 || s.indexOf(`CREATE OR REPLACE FUNCTION ${head}`, i + 1) >= 0) throw new Error(`v17: v16 block ${head} not found exactly once`);
  const j = s.indexOf("END $fn$;", i);
  if (j < 0) throw new Error(`v17: v16 block ${head} has no end`);
  return s.slice(i, j + "END $fn$;".length);
}
/** Replace exactly one occurrence (a patch that no longer matches is a build error, not a silent no-op). */
export function patchOnce(src: string, from: string, to: string, what: string): string {
  const i = src.indexOf(from);
  if (i < 0 || src.indexOf(from, i + 1) >= 0) throw new Error(`v17: patch ${what} matched ${i < 0 ? 0 : "more than one"} time(s)`);
  return src.slice(0, i) + to + src.slice(i + from.length);
}

const W8 = "mr_spend_release_attested(text, text, bytea, bytea, bytea, bytea, text, text)";
const V12 = "mr_spend_release_attested_v12(text, text, bytea, bytea, bytea, bytea, text, text)";

/**
 * R66-P3-1: the cooldown base changes only through mr_set_tamper_cooldown_base (owned by mr_pause_writer after t11,
 * EXECUTE for the app owner only): alone (no other column), never while paused, and audited like a caps change. A
 * direct UPDATE by anyone but the table owner (= mr_pause_writer after t11; superusers included) is refused.
 */
export function v17Guard(): string {
  let g = v16Block("mr_v16_guard()");
  g = patchOnce(g, `IF NEW.pause_seq < OLD.pause_seq OR (NEW.pause_seq = OLD.pause_seq AND NEW.tamper_count <> OLD.tamper_count) OR NEW.base_cooldown_s <> OLD.base_cooldown_s THEN
          RAISE EXCEPTION 'mr_pause_state: counters only move forward' USING ERRCODE = 'insufficient_privilege';
        END IF;
        RETURN NEW;
      END IF;`, `IF NEW.pause_seq < OLD.pause_seq OR (NEW.pause_seq = OLD.pause_seq AND NEW.tamper_count <> OLD.tamper_count) THEN
          RAISE EXCEPTION 'mr_pause_state: counters only move forward' USING ERRCODE = 'insufficient_privilege';
        END IF;
        IF NEW.base_cooldown_s IS NOT DISTINCT FROM OLD.base_cooldown_s THEN RETURN NEW; END IF;
        -- R66-P3-1: mr_set_tamper_cooldown_base (falls through to the audit below)
      ELSIF NOT is_owner AND NEW.base_cooldown_s IS DISTINCT FROM OLD.base_cooldown_s THEN
        RAISE EXCEPTION 'mr_pause_state: changed only through mr_tamper_pause / mr_tamper_resume / mr_set_tamper_cooldown_base' USING ERRCODE = 'insufficient_privilege';
      END IF;
      IF NEW.base_cooldown_s IS DISTINCT FROM OLD.base_cooldown_s AND OLD.paused THEN
        RAISE EXCEPTION 'mr_pause_state: the cooldown base can not change while paused' USING ERRCODE = 'insufficient_privilege';
      END IF;`, "guard: cooldown base");
  return g;
}
/** R66-P3-1: the only way to change the cooldown base (the app owner's redeploy; the CHECKs keep the MainNet 6 h floor). */
export function v17CooldownSetter(): string {
  return `CREATE OR REPLACE FUNCTION mr_set_tamper_cooldown_base(p_secs integer) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE net text;
BEGIN
  SELECT n.network INTO net FROM public.mr_network n WHERE n.singleton;
  IF net IS NULL THEN RAISE EXCEPTION 'mr_set_tamper_cooldown_base: network marker is not set' USING ERRCODE = 'check_violation'; END IF;
  IF p_secs IS NULL OR p_secs < 1 THEN RAISE EXCEPTION 'mr_set_tamper_cooldown_base: seconds must be >= 1' USING ERRCODE = 'check_violation'; END IF;
  UPDATE public.mr_pause_state ps SET base_cooldown_s = p_secs WHERE ps.network = net; -- guard: alone, unpaused, audited
  RETURN p_secs;
END $fn$;
REVOKE ALL ON FUNCTION mr_set_tamper_cooldown_base(integer) FROM PUBLIC;`;
}
/**
 * Optional (run 66): a release that _v12 reports as a no-op (ok = false: row gone or no longer pending/ambiguous) leaves
 * no ledger row. The ledger insert and the _v12 call share a sub-block; ok = false raises MR066 inside it, which rolls
 * back to the block's savepoint (no DELETE on the append-only ledger), and the wrapper returns _v12's answer.
 */
export function v17Wrapper(): string {
  let w = v16Block("mr_spend_release_attested(p_store text");
  w = patchOnce(w, "DECLARE net text; ps record; cap record; amt bigint; st text; day bigint; r record;",
    "DECLARE net text; ps record; cap record; amt bigint; st text; day bigint; r record; counted boolean := false;", "wrapper: declare");
  w = patchOnce(w, "    INSERT INTO public.mr_release_ledger (store, spend_id, network, amount_micro) VALUES (p_store, p_id, net, amt) ON CONFLICT DO NOTHING;\n",
    "    counted := true;\n", "wrapper: defer the ledger insert");
  w = patchOnce(w, "  SELECT * INTO r FROM public.mr_spend_release_attested_v12(p_store, p_id, p_msg, p_sig, p_cmsg, p_csig, p_label, p_reason);\n",
    `  BEGIN
    IF counted THEN
      INSERT INTO public.mr_release_ledger (store, spend_id, network, amount_micro) VALUES (p_store, p_id, net, amt) ON CONFLICT DO NOTHING;
    END IF;
    SELECT * INTO r FROM public.mr_spend_release_attested_v12(p_store, p_id, p_msg, p_sig, p_cmsg, p_csig, p_label, p_reason);
    IF counted AND NOT r.ok THEN RAISE EXCEPTION 'no-op release: ledger row dropped' USING ERRCODE = 'MR066'; END IF;
  EXCEPTION WHEN SQLSTATE 'MR066' THEN
    NULL; -- savepoint rollback: the ledger row is gone, r keeps _v12's (false, status)
  END;
`, "wrapper: savepoint around _v12");
  return w;
}

export function v17Sql(): string {
  return `
DO $v17$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['mr_pause_state', 'mr_resume_nonce', 'mr_pause_log', 'mr_release_caps', 'mr_config_audit'] LOOP
    IF to_regclass('public.' || t) IS NULL THEN
      RAISE EXCEPTION 'v17: % is missing (a pre-R62 v16 text was applied); rebuild this database, v17 does not convert it', t USING ERRCODE = 'check_violation';
    END IF;
  END LOOP;
  IF to_regprocedure('${V12}') IS NULL THEN
    RAISE EXCEPTION 'v17: % is missing (v16 did not rename the release function); rebuild this database', '${V12}' USING ERRCODE = 'check_violation';
  END IF;
END $v17$;

-- R63-P2-1 columns (an early v16 lacked them). Existing rows can't be re-signed: refuse instead of inventing values.
ALTER TABLE mr_resume_nonce ADD COLUMN IF NOT EXISTS key_id text, ADD COLUMN IF NOT EXISTS msg bytea, ADD COLUMN IF NOT EXISTS sig bytea;
DO $v17n$ BEGIN
  IF EXISTS (SELECT 1 FROM public.mr_resume_nonce WHERE key_id IS NULL OR msg IS NULL OR sig IS NULL) THEN
    RAISE EXCEPTION 'v17: mr_resume_nonce has rows without key_id / msg / sig (applied before R63); rebuild this TestNet database' USING ERRCODE = 'check_violation';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'public.mr_resume_nonce'::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%length(sig) = 64%') THEN
    ALTER TABLE public.mr_resume_nonce ADD CONSTRAINT mr_resume_nonce_sig_len CHECK (length(sig) = 64);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'public.mr_release_caps'::regclass AND conname = 'mr_release_caps_mainnet_max') THEN
    ALTER TABLE public.mr_release_caps ADD CONSTRAINT mr_release_caps_mainnet_max CHECK (network <> 'mainnet' OR (max_release_micro <= 10000 AND max_day_micro <= 50000));
  END IF;
END $v17n$;
ALTER TABLE mr_resume_nonce ALTER COLUMN key_id SET NOT NULL, ALTER COLUMN msg SET NOT NULL, ALTER COLUMN sig SET NOT NULL;

-- R65-P2-1 caps ledger (an earlier v16 had none)
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

-- R66-P3-4: the guard and the wrapper as reviewed (CREATE OR REPLACE; identical bodies on an up-to-date v16)
${v17Guard()}
${v17Wrapper()}
REVOKE ALL ON FUNCTION ${W8} FROM PUBLIC;
${v17CooldownSetter()}
${v16Block("mr_v16_nonce_ledger()")}
REVOKE ALL ON FUNCTION mr_v16_nonce_ledger() FROM PUBLIC;

-- R66-P3-4 BACKFILL: every attested release already recorded gets its ledger row (before the triggers below, the
-- guard on a fresh table already allows the owner's INSERT; ON CONFLICT keeps it idempotent)
INSERT INTO mr_release_ledger (store, spend_id, network, amount_micro, at)
SELECT n.store, n.spend_id, m.network, s.amount_micro, n.used_at
  FROM mr_release_nonce n
  JOIN mr_spend s ON s.store = n.store AND s.id = n.spend_id
  JOIN mr_network m ON m.singleton
 WHERE s.amount_micro > 0
ON CONFLICT (store, spend_id) DO NOTHING;
DO $v17b$ BEGIN
  IF EXISTS (SELECT 1 FROM public.mr_release_nonce n WHERE NOT EXISTS (SELECT 1 FROM public.mr_release_ledger l WHERE l.store = n.store AND l.spend_id = n.spend_id)) THEN
    RAISE EXCEPTION 'v17: backfill left attested releases without a ledger row (no network marker or zero amount)' USING ERRCODE = 'check_violation';
  END IF;
END $v17b$;

-- every v16 guard trigger (the ledger's included: UPDATE / DELETE / TRUNCATE refused) and the nonce -> ledger check
DO $t$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['mr_pause_state', 'mr_resume_nonce', 'mr_pause_log', 'mr_release_caps', 'mr_config_audit', 'mr_release_ledger'] LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I', t || '_guard', t);
    EXECUTE format('CREATE TRIGGER %I BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION mr_v16_guard()', t || '_guard', t);
    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I', t || '_guard_t', t);
    EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION mr_v16_guard()', t || '_guard_t', t);
  END LOOP;
END $t$;
DROP TRIGGER IF EXISTS mr_release_nonce_ledger ON mr_release_nonce;
CREATE TRIGGER mr_release_nonce_ledger BEFORE INSERT ON mr_release_nonce FOR EACH ROW EXECUTE FUNCTION mr_v16_nonce_ledger();
`;
}
