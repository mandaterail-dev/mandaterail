/**
 * v11: attested releases (docs/ops/attested-release-signer.md rev 9/10, closes R25-P2-1 in the DB).
 *
 * - mr_signer_key: pinned Ed25519 attestation keys, write-once; only revoked_at/revoke_reason may change, once.
 * - mr_signer_operator: pinned operator ids per network (observations need >= 2 distinct ones).
 * - mr_release_nonce: replay table (nonce PK, one attested release per spend).
 * - mr_spend: signed_txn (+kind), app-derived first_valid/group_id/sender, submit_round/submit_at,
 *   attestation_msg/sig, CHECKs and an immutability trigger (R36-5, R37-3, rev 5 held batch).
 * - mr_jcs(jsonb): restricted RFC 8785 serializer; the verifier requires byte equality (strict canonical JSON).
 * - mr_spend_release_attested(...): the only release path on mainnet; verifies the Ed25519 signature with
 *   mr_crypto.mr_ed25519_verify (the mr_ed25519 C extension, installed by a superuser beforehand).
 * - mr_spend_release (v10 body): unsigned 'manual-release' is refused on mainnet (forced already was).
 * - mr_signer_revoke(key_id, reason): one-way revoke, only from an mr-admin-window session.
 * Never edit after release; append v12. (Amended for R43-P2-1 before any database applied it.)
 */
export const ATTEST_PREFIX = "MR-RELEASE-ATTEST-v1\n";
export const ATTEST_MSG_KEYS = [
  "expiry", "firstValid", "genesisHash", "groupId", "keyId", "lastValid", "network", "nonce",
  "observations", "round", "sender", "spendId", "store", "txId", "v",
] as const;
export const ATTEST_OBS_KEYS = ["at", "idxRound", "method", "operator", "provider", "round"] as const;
/** keyId = first 32 hex chars (128 bits) of sha256(pubkey) (R42-P3-1: fixed length). */
export const KEY_ID_HEX_LEN = 32;
/** R43-P2-1: DB-side cap on attested releases (0.05 USDC/day at 0.01 per payment). */
export const ATTESTED_RELEASES_PER_24H = 5;

export function v11Sql(v10ReleaseFnText: string, operatorSeed: string): string {
  const unsignedRefused = v10ReleaseFnText.replace(
    `  IF p_action = 'manual-release-forced' AND net = 'mainnet' THEN
    RAISE EXCEPTION 'mr_spend_release: forced release is refused on mainnet' USING ERRCODE = 'insufficient_privilege';
  END IF;`,
    () => `  IF net = 'mainnet' THEN
    RAISE EXCEPTION 'mr_spend_release: unsigned releases are refused on mainnet; use mr_spend_release_attested' USING ERRCODE = 'insufficient_privilege';
  END IF;`,
  );
  if (unsignedRefused === v10ReleaseFnText) throw new Error("v11 migration: v10 release function text changed");
  return `
DO $chk$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
                  WHERE n.nspname = 'mr_crypto' AND p.proname = 'mr_ed25519_verify'
                    AND pg_catalog.pg_get_function_identity_arguments(p.oid) = 'msg bytea, sig bytea, pk bytea') THEN
    RAISE EXCEPTION 'v11: mr_crypto.mr_ed25519_verify is missing; a superuser must CREATE SCHEMA mr_crypto; CREATE EXTENSION mr_ed25519 SCHEMA mr_crypto (ops/pg/mr_ed25519) before migrating';
  END IF;
END $chk$;

CREATE TABLE IF NOT EXISTS mr_signer_key (
  key_id        text PRIMARY KEY CHECK (key_id ~ '^[0-9a-f]{${KEY_ID_HEX_LEN}}$'),
  pubkey        bytea NOT NULL UNIQUE CHECK (length(pubkey) = 32),
  network       text NOT NULL CHECK (network IN ('testnet', 'mainnet')),
  margin_rounds integer NOT NULL CHECK (margin_rounds >= 10 AND margin_rounds <= 1000),
  created_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
  revoked_at    timestamptz,
  revoke_reason text,
  CHECK (key_id = left(encode(sha256(pubkey), 'hex'), ${KEY_ID_HEX_LEN})),
  CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
);
REVOKE ALL ON mr_signer_key FROM PUBLIC;

CREATE TABLE IF NOT EXISTS mr_signer_operator (
  network  text NOT NULL CHECK (network IN ('testnet', 'mainnet')),
  operator text NOT NULL CHECK (operator ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
  added_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (network, operator)
);
REVOKE ALL ON mr_signer_operator FROM PUBLIC;
INSERT INTO mr_signer_operator (network, operator) VALUES
${operatorSeed}
ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS mr_release_nonce (
  nonce    bytea PRIMARY KEY CHECK (length(nonce) = 32),
  store    text NOT NULL,
  spend_id text NOT NULL,
  key_id   text NOT NULL REFERENCES mr_signer_key(key_id),
  used_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (store, spend_id)
);
REVOKE ALL ON mr_release_nonce FROM PUBLIC;

-- write-once tables: INSERT only by the table owner (migration) or a superuser; mr_signer_key may only be revoked.
CREATE OR REPLACE FUNCTION mr_signer_tables_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE is_owner boolean; is_super boolean; net text;
BEGIN
  SELECT pg_get_userbyid(c.relowner) = current_user::text INTO is_owner FROM pg_class c WHERE c.oid = TG_RELID;
  SELECT r.rolsuper INTO is_super FROM pg_roles r WHERE r.rolname = current_user;
  IF TG_OP = 'TRUNCATE' OR TG_OP = 'DELETE' THEN
    RAISE EXCEPTION '%: % refused (write-once)', TG_TABLE_NAME, TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF TG_TABLE_NAME = 'mr_release_nonce' THEN
    IF TG_OP = 'UPDATE' THEN RAISE EXCEPTION 'mr_release_nonce: UPDATE refused' USING ERRCODE = 'insufficient_privilege'; END IF;
    IF coalesce(current_setting('mr.spend_fn', true), '') <> 'on' OR NOT is_owner THEN
      RAISE EXCEPTION 'mr_release_nonce: rows are written only by mr_spend_release_attested' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NOT (is_owner OR is_super) THEN
      RAISE EXCEPTION '%: INSERT only by the schema owner (a migration)', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF TG_TABLE_NAME = 'mr_signer_key' THEN
      SELECT n.network INTO net FROM public.mr_network n WHERE n.singleton;
      IF net IS NULL OR NEW.network <> net THEN
        RAISE EXCEPTION 'mr_signer_key: key network % does not match this database (%)', NEW.network, net USING ERRCODE = 'check_violation';
      END IF;
      IF NEW.revoked_at IS NOT NULL THEN RAISE EXCEPTION 'mr_signer_key: a new key cannot be revoked' USING ERRCODE = 'check_violation'; END IF;
    END IF;
    RETURN NEW;
  END IF;
  -- UPDATE
  IF TG_TABLE_NAME = 'mr_signer_key'
     AND (NEW.key_id, NEW.pubkey, NEW.network, NEW.margin_rounds, NEW.created_at) IS NOT DISTINCT FROM (OLD.key_id, OLD.pubkey, OLD.network, OLD.margin_rounds, OLD.created_at)
     AND OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
     AND coalesce(current_setting('mr.signer_revoke', true), '') = 'on' THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION '%: UPDATE refused (write-once; keys change only via mr_signer_revoke)', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
END $fn$;
REVOKE ALL ON FUNCTION mr_signer_tables_guard() FROM PUBLIC;
DROP TRIGGER IF EXISTS mr_signer_key_guard ON mr_signer_key;
CREATE TRIGGER mr_signer_key_guard BEFORE INSERT OR UPDATE OR DELETE ON mr_signer_key FOR EACH ROW EXECUTE FUNCTION mr_signer_tables_guard();
DROP TRIGGER IF EXISTS mr_signer_key_guard_truncate ON mr_signer_key;
CREATE TRIGGER mr_signer_key_guard_truncate BEFORE TRUNCATE ON mr_signer_key FOR EACH STATEMENT EXECUTE FUNCTION mr_signer_tables_guard();
DROP TRIGGER IF EXISTS mr_signer_operator_guard ON mr_signer_operator;
CREATE TRIGGER mr_signer_operator_guard BEFORE INSERT OR UPDATE OR DELETE ON mr_signer_operator FOR EACH ROW EXECUTE FUNCTION mr_signer_tables_guard();
DROP TRIGGER IF EXISTS mr_signer_operator_guard_truncate ON mr_signer_operator;
CREATE TRIGGER mr_signer_operator_guard_truncate BEFORE TRUNCATE ON mr_signer_operator FOR EACH STATEMENT EXECUTE FUNCTION mr_signer_tables_guard();
DROP TRIGGER IF EXISTS mr_release_nonce_guard ON mr_release_nonce;
CREATE TRIGGER mr_release_nonce_guard BEFORE INSERT OR UPDATE OR DELETE ON mr_release_nonce FOR EACH ROW EXECUTE FUNCTION mr_signer_tables_guard();
DROP TRIGGER IF EXISTS mr_release_nonce_guard_truncate ON mr_release_nonce;
CREATE TRIGGER mr_release_nonce_guard_truncate BEFORE TRUNCATE ON mr_release_nonce FOR EACH STATEMENT EXECUTE FUNCTION mr_signer_tables_guard();

ALTER TABLE mr_spend
  ADD COLUMN IF NOT EXISTS signed_txn bytea,
  ADD COLUMN IF NOT EXISTS signed_txn_kind text,
  ADD COLUMN IF NOT EXISTS first_valid bigint,
  ADD COLUMN IF NOT EXISTS group_id text,
  ADD COLUMN IF NOT EXISTS sender text,
  ADD COLUMN IF NOT EXISTS submit_round bigint,
  ADD COLUMN IF NOT EXISTS submit_at timestamptz,
  ADD COLUMN IF NOT EXISTS attestation_msg bytea,
  ADD COLUMN IF NOT EXISTS attestation_sig bytea;
ALTER TABLE mr_spend DROP CONSTRAINT IF EXISTS mr_spend_signed_kind;
ALTER TABLE mr_spend ADD CONSTRAINT mr_spend_signed_kind CHECK (signed_txn_kind IS NULL OR signed_txn_kind IN ('group', 'xpayment'));
ALTER TABLE mr_spend DROP CONSTRAINT IF EXISTS mr_spend_signed_complete;
ALTER TABLE mr_spend ADD CONSTRAINT mr_spend_signed_complete CHECK (
  (signed_txn IS NULL AND signed_txn_kind IS NULL AND first_valid IS NULL AND group_id IS NULL AND sender IS NULL
     AND submit_round IS NULL AND submit_at IS NULL)
  OR (signed_txn IS NOT NULL AND length(signed_txn) BETWEEN 1 AND 16384 AND signed_txn_kind IS NOT NULL
     AND tx_id ~ '^[A-Z2-7]{52}$' AND first_valid IS NOT NULL AND last_valid IS NOT NULL
     AND group_id IS NOT NULL AND (group_id = '' OR group_id ~ '^[A-Za-z0-9+/]{43}=$')
     AND sender ~ '^[A-Z2-7]{58}$' AND submit_round IS NOT NULL AND submit_at IS NOT NULL));
ALTER TABLE mr_spend DROP CONSTRAINT IF EXISTS mr_spend_valid_window;
ALTER TABLE mr_spend ADD CONSTRAINT mr_spend_valid_window CHECK (
  first_valid IS NULL OR last_valid IS NULL OR (first_valid < last_valid AND last_valid <= first_valid + 1000));
ALTER TABLE mr_spend DROP CONSTRAINT IF EXISTS mr_spend_submit_round;
ALTER TABLE mr_spend ADD CONSTRAINT mr_spend_submit_round CHECK (submit_round IS NULL OR last_valid IS NULL OR submit_round <= last_valid);
ALTER TABLE mr_spend DROP CONSTRAINT IF EXISTS mr_spend_attestation_pair;
ALTER TABLE mr_spend ADD CONSTRAINT mr_spend_attestation_pair CHECK ((attestation_msg IS NULL) = (attestation_sig IS NULL));

CREATE OR REPLACE FUNCTION mr_spend_signed_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE via_fn boolean; is_owner boolean;
BEGIN
  SELECT pg_get_userbyid(c.relowner) = current_user::text INTO is_owner FROM pg_class c WHERE c.oid = TG_RELID;
  via_fn := is_owner AND coalesce(current_setting('mr.spend_fn', true), '') = 'on';
  IF TG_OP = 'INSERT' THEN
    IF (NEW.signed_txn, NEW.signed_txn_kind, NEW.first_valid, NEW.group_id, NEW.sender, NEW.submit_round, NEW.submit_at, NEW.attestation_msg, NEW.attestation_sig)
       IS DISTINCT FROM (NULL::bytea, NULL::text, NULL::bigint, NULL::text, NULL::text, NULL::bigint, NULL::timestamptz, NULL::bytea, NULL::bytea) THEN
      RAISE EXCEPTION 'mr_spend: a new row has no signed_txn / attestation yet' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
  END IF;
  -- attestation columns: set once, only inside mr_spend_release_attested
  IF (NEW.attestation_msg, NEW.attestation_sig) IS DISTINCT FROM (OLD.attestation_msg, OLD.attestation_sig) THEN
    IF NOT via_fn OR OLD.attestation_msg IS NOT NULL THEN
      RAISE EXCEPTION 'mr_spend: attestation is written once, only by mr_spend_release_attested' USING ERRCODE = 'insufficient_privilege';
    END IF;
  END IF;
  IF (NEW.signed_txn, NEW.signed_txn_kind, NEW.first_valid, NEW.group_id, NEW.sender, NEW.submit_round, NEW.submit_at)
     IS NOT DISTINCT FROM (OLD.signed_txn, OLD.signed_txn_kind, OLD.first_valid, OLD.group_id, OLD.sender, OLD.submit_round, OLD.submit_at) THEN
    IF OLD.signed_txn IS NOT NULL AND (NEW.tx_id, NEW.last_valid) IS DISTINCT FROM (OLD.tx_id, OLD.last_valid) THEN
      RAISE EXCEPTION 'mr_spend: tx_id / last_valid are immutable once signed_txn is stored' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.signed_txn IS NULL THEN
    -- first write: on a pending row, together with tx_id / last_valid (app-derived from the same bytes)
    IF OLD.status <> 'pending' THEN
      RAISE EXCEPTION 'mr_spend: signed_txn can be stored only on a pending row' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF OLD.tx_id IS NOT NULL AND (NEW.tx_id IS DISTINCT FROM OLD.tx_id OR NEW.last_valid IS DISTINCT FROM OLD.last_valid) THEN
      RAISE EXCEPTION 'mr_spend: signed_txn does not match the pinned tx_id / last_valid' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NEW.submit_at IS NULL OR abs(extract(epoch FROM (NEW.submit_at - clock_timestamp()))) > 5 THEN
      RAISE EXCEPTION 'mr_spend: submit_at must be the database clock (within 5 s)' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
  END IF;
  -- the single allowed change: xpayment -> group with identical derived fields, before any attestation
  IF OLD.signed_txn_kind = 'xpayment' AND NEW.signed_txn_kind = 'group' AND OLD.attestation_msg IS NULL
     AND NOT EXISTS (SELECT 1 FROM public.mr_release_nonce r WHERE r.store = OLD.store AND r.spend_id = OLD.id)
     AND (NEW.tx_id, NEW.first_valid, NEW.last_valid, NEW.group_id, NEW.sender, NEW.submit_round, NEW.submit_at)
         IS NOT DISTINCT FROM (OLD.tx_id, OLD.first_valid, OLD.last_valid, OLD.group_id, OLD.sender, OLD.submit_round, OLD.submit_at) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'mr_spend: signed_txn and its derived fields are immutable once stored' USING ERRCODE = 'insufficient_privilege';
END $fn$;
REVOKE ALL ON FUNCTION mr_spend_signed_guard() FROM PUBLIC;
DROP TRIGGER IF EXISTS mr_spend_signed_guard_row ON mr_spend;
CREATE TRIGGER mr_spend_signed_guard_row BEFORE INSERT OR UPDATE ON mr_spend FOR EACH ROW EXECUTE FUNCTION mr_spend_signed_guard();

-- Restricted RFC 8785 serializer: objects (ASCII alnum keys, sorted bytewise), arrays, printable-ASCII strings
-- without quote/backslash, non-negative integers < 2^53. Anything else raises.
CREATE OR REPLACE FUNCTION mr_jcs(j jsonb) RETURNS text LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE t text; s text; n numeric; r text; k text; v jsonb;
BEGIN
  t := jsonb_typeof(j);
  IF t = 'object' THEN
    r := '';
    FOR k, v IN SELECT e.key, e.value FROM jsonb_each(j) e ORDER BY convert_to(e.key, 'UTF8') LOOP
      IF k !~ '^[A-Za-z0-9]{1,32}$' THEN RAISE EXCEPTION 'mr_jcs: bad key' USING ERRCODE = 'check_violation'; END IF;
      r := r || CASE WHEN r = '' THEN '' ELSE ',' END || '"' || k || '":' || public.mr_jcs(v);
    END LOOP;
    RETURN '{' || r || '}';
  ELSIF t = 'array' THEN
    SELECT coalesce(string_agg(public.mr_jcs(e.value), ',' ORDER BY e.ord), '') INTO r FROM jsonb_array_elements(j) WITH ORDINALITY e(value, ord);
    RETURN '[' || r || ']';
  ELSIF t = 'string' THEN
    s := j #>> '{}';
    IF s !~ '^[ !#-\\[\\]-~]*$' THEN RAISE EXCEPTION 'mr_jcs: string outside the restricted ASCII profile' USING ERRCODE = 'check_violation'; END IF;
    RETURN '"' || s || '"';
  ELSIF t = 'number' THEN
    s := j::text;
    IF s !~ '^(0|[1-9][0-9]{0,15})$' THEN RAISE EXCEPTION 'mr_jcs: only plain non-negative integers' USING ERRCODE = 'check_violation'; END IF;
    n := s::numeric;
    IF n >= 9007199254740992 THEN RAISE EXCEPTION 'mr_jcs: integer >= 2^53' USING ERRCODE = 'check_violation'; END IF;
    RETURN s;
  END IF;
  RAISE EXCEPTION 'mr_jcs: % not allowed', t USING ERRCODE = 'check_violation';
END $fn$;
REVOKE ALL ON FUNCTION mr_jcs(jsonb) FROM PUBLIC;

CREATE OR REPLACE FUNCTION mr_spend_release_attested(p_store text, p_id text, p_msg bytea, p_sig bytea, p_label text, p_reason text)
RETURNS TABLE (ok boolean, from_status text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE
  pfx bytea := convert_to(E'MR-RELEASE-ATTEST-v1\\n', 'UTF8');
  body bytea; bt text; m jsonb; net text; net_hash text; k record; s record;
  o jsonb; ops text[] := '{}'; ts timestamptz; exp timestamptz; lv_est timestamptz; i int := 0;
  iso text := '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$';
  want_keys text[] := ARRAY['${ATTEST_MSG_KEYS.join("','")}'];
  want_obs text[] := ARRAY['${ATTEST_OBS_KEYS.join("','")}'];
  now_ms bigint := (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
BEGIN
  IF coalesce(btrim(p_label), '') = '' OR length(btrim(coalesce(p_reason, ''))) < 8 THEN
    RAISE EXCEPTION 'mr_spend_release_attested: operator label and a reason of 8+ characters are required' USING ERRCODE = 'check_violation';
  END IF;
  SELECT n.network, n.genesis_hash INTO net, net_hash FROM public.mr_network n WHERE n.singleton;
  IF net IS NULL THEN RAISE EXCEPTION 'mr_spend_release_attested: network marker is not set' USING ERRCODE = 'check_violation'; END IF;
  IF p_msg IS NULL OR p_sig IS NULL THEN
    RAISE EXCEPTION 'mr_spend_release_attested: an attestation (msg + sig) is required' USING ERRCODE = 'check_violation';
  END IF;
  IF length(p_msg) > 4096 OR length(p_msg) <= length(pfx) OR substring(p_msg FROM 1 FOR length(pfx)) <> pfx THEN
    RAISE EXCEPTION 'mr_spend_release_attested: message prefix / length' USING ERRCODE = 'check_violation';
  END IF;
  body := substring(p_msg FROM length(pfx) + 1);
  IF position('\\x00'::bytea IN body) > 0 THEN RAISE EXCEPTION 'mr_spend_release_attested: NUL in message' USING ERRCODE = 'check_violation'; END IF;
  bt := convert_from(body, 'UTF8');
  IF bt !~ '^[ -~]+$' THEN RAISE EXCEPTION 'mr_spend_release_attested: message is not printable ASCII' USING ERRCODE = 'check_violation'; END IF;
  BEGIN m := bt::jsonb; EXCEPTION WHEN others THEN RAISE EXCEPTION 'mr_spend_release_attested: message is not JSON' USING ERRCODE = 'check_violation'; END;
  IF jsonb_typeof(m) <> 'object' OR public.mr_jcs(m) <> bt THEN
    RAISE EXCEPTION 'mr_spend_release_attested: message is not canonical (restricted JCS)' USING ERRCODE = 'check_violation';
  END IF;
  IF (SELECT array_agg(x ORDER BY x) FROM jsonb_object_keys(m) x) <> (SELECT array_agg(x ORDER BY x) FROM unnest(want_keys) x) THEN
    RAISE EXCEPTION 'mr_spend_release_attested: message key set' USING ERRCODE = 'check_violation';
  END IF;
  IF m->'v' <> '1'::jsonb OR jsonb_typeof(m->'observations') <> 'array' THEN
    RAISE EXCEPTION 'mr_spend_release_attested: version / observations' USING ERRCODE = 'check_violation';
  END IF;
  -- key: pinned, not revoked, same network as the database and the message
  SELECT * INTO k FROM public.mr_signer_key sk WHERE sk.key_id = m->>'keyId' FOR SHARE; -- R43-P3: no revoke race
  IF NOT FOUND OR k.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'mr_spend_release_attested: key % is unknown or revoked', m->>'keyId' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF k.network <> net OR m->>'network' <> net THEN
    RAISE EXCEPTION 'mr_spend_release_attested: key / message network must be %', net USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NOT mr_crypto.mr_ed25519_verify(p_msg, p_sig, k.pubkey) THEN
    RAISE EXCEPTION 'mr_spend_release_attested: signature does not verify' USING ERRCODE = 'insufficient_privilege';
  END IF;
  -- formats
  IF m->>'genesisHash' <> net_hash THEN RAISE EXCEPTION 'mr_spend_release_attested: genesis hash' USING ERRCODE = 'check_violation'; END IF;
  IF m->>'store' <> p_store OR m->>'spendId' <> p_id THEN RAISE EXCEPTION 'mr_spend_release_attested: store / spendId' USING ERRCODE = 'check_violation'; END IF;
  IF m->>'txId' !~ '^[A-Z2-7]{52}$' OR m->>'sender' !~ '^[A-Z2-7]{58}$' OR (m->>'groupId' <> '' AND m->>'groupId' !~ '^[A-Za-z0-9+/]{43}=$')
     OR m->>'nonce' !~ '^[A-Za-z0-9_-]{43}$' OR m->>'expiry' !~ iso
     OR jsonb_typeof(m->'firstValid') <> 'number' OR jsonb_typeof(m->'lastValid') <> 'number' OR jsonb_typeof(m->'round') <> 'number' THEN
    RAISE EXCEPTION 'mr_spend_release_attested: field formats' USING ERRCODE = 'check_violation';
  END IF;
  exp := (m->>'expiry')::timestamptz;
  IF exp <= clock_timestamp() OR exp - clock_timestamp() > interval '15 minutes' THEN
    RAISE EXCEPTION 'mr_spend_release_attested: expired or expiry more than 15 min ahead' USING ERRCODE = 'check_violation';
  END IF;
  -- the row: app-derived fields must equal the attested ones
  SELECT * INTO s FROM public.mr_spend sp WHERE sp.store = p_store AND sp.id = p_id FOR UPDATE;
  IF NOT FOUND THEN RETURN QUERY SELECT false, NULL::text; RETURN; END IF;
  IF s.status NOT IN ('pending', 'ambiguous') THEN RETURN QUERY SELECT false, s.status; RETURN; END IF;
  IF s.signed_txn IS NULL OR s.submit_round IS NULL OR s.submit_at IS NULL THEN
    RAISE EXCEPTION 'mr_spend_release_attested: the row has no stored signed_txn / submit fields' USING ERRCODE = 'check_violation';
  END IF;
  IF (m->>'txId', (m->>'firstValid')::bigint, (m->>'lastValid')::bigint, m->>'groupId', m->>'sender')
     IS DISTINCT FROM (s.tx_id, s.first_valid, s.last_valid, s.group_id, s.sender) THEN
    RAISE EXCEPTION 'mr_spend_release_attested: attested txId/firstValid/lastValid/groupId/sender differ from the stored row' USING ERRCODE = 'check_violation';
  END IF;
  IF NOT (s.first_valid < s.last_valid AND s.last_valid <= s.first_valid + 1000) THEN
    RAISE EXCEPTION 'mr_spend_release_attested: valid window' USING ERRCODE = 'check_violation';
  END IF;
  IF (m->>'round')::bigint < s.last_valid + k.margin_rounds THEN
    RAISE EXCEPTION 'mr_spend_release_attested: round is not past lastValid + margin' USING ERRCODE = 'check_violation';
  END IF;
  lv_est := s.submit_at + make_interval(secs => (s.last_valid - s.submit_round) * 2.5);
  IF jsonb_array_length(m->'observations') < 2 OR jsonb_array_length(m->'observations') > 4 THEN
    RAISE EXCEPTION 'mr_spend_release_attested: 2 to 4 observations' USING ERRCODE = 'check_violation';
  END IF;
  FOR o IN SELECT e.value FROM jsonb_array_elements(m->'observations') e LOOP
    i := i + 1;
    IF jsonb_typeof(o) <> 'object' OR (SELECT array_agg(x ORDER BY x) FROM jsonb_object_keys(o) x) <> (SELECT array_agg(x ORDER BY x) FROM unnest(want_obs) x) THEN
      RAISE EXCEPTION 'mr_spend_release_attested: observation % key set', i USING ERRCODE = 'check_violation';
    END IF;
    IF o->>'at' !~ iso OR jsonb_typeof(o->'round') <> 'number' OR jsonb_typeof(o->'idxRound') <> 'number' THEN
      RAISE EXCEPTION 'mr_spend_release_attested: observation % formats', i USING ERRCODE = 'check_violation';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.mr_signer_operator so WHERE so.network = net AND so.operator = o->>'operator')
       OR NOT EXISTS (SELECT 1 FROM public.mr_network_provider np WHERE np.network = net AND np.host = o->>'provider' AND np.operator_id = o->>'operator') THEN
      RAISE EXCEPTION 'mr_spend_release_attested: observation % operator/provider is not pinned for %', i, net USING ERRCODE = 'check_violation';
    END IF;
    IF (o->>'round')::bigint < s.last_valid + k.margin_rounds THEN
      RAISE EXCEPTION 'mr_spend_release_attested: observation % round is not past lastValid + margin', i USING ERRCODE = 'check_violation';
    END IF;
    IF o->>'method' = 'idx404' THEN
      IF (o->>'idxRound')::bigint < s.last_valid + k.margin_rounds THEN
        RAISE EXCEPTION 'mr_spend_release_attested: observation % (idx404) idxRound is not past lastValid + margin', i USING ERRCODE = 'check_violation';
      END IF;
    ELSIF o->>'method' = 'blockscan' THEN
      IF (o->>'idxRound')::bigint <> s.last_valid THEN
        RAISE EXCEPTION 'mr_spend_release_attested: observation % (blockscan) must have scanned up to lastValid exactly', i USING ERRCODE = 'check_violation';
      END IF;
    ELSE
      RAISE EXCEPTION 'mr_spend_release_attested: observation % method', i USING ERRCODE = 'check_violation';
    END IF;
    ts := (o->>'at')::timestamptz;
    IF ts < lv_est OR ts > clock_timestamp() + interval '60 seconds' OR ts < clock_timestamp() - interval '15 minutes' OR ts > exp THEN
      RAISE EXCEPTION 'mr_spend_release_attested: observation % time is outside [lv_est, now+60s], older than 15 min, or after expiry', i USING ERRCODE = 'check_violation';
    END IF;
    IF NOT (o->>'operator' = ANY (ops)) THEN ops := ops || (o->>'operator'); END IF;
  END LOOP;
  IF cardinality(ops) < 2 THEN
    RAISE EXCEPTION 'mr_spend_release_attested: observations need at least 2 distinct pinned operators' USING ERRCODE = 'check_violation';
  END IF;
  -- R43-P2-1: DB-side limit, independent of the signer host's state: at most ${ATTESTED_RELEASES_PER_24H}
  -- attested releases in any rolling 24 h (all keys). The lock serializes concurrent releases for the count.
  LOCK TABLE public.mr_release_nonce IN SHARE ROW EXCLUSIVE MODE;
  IF (SELECT count(*) FROM public.mr_release_nonce r WHERE r.used_at > clock_timestamp() - interval '24 hours') >= ${ATTESTED_RELEASES_PER_24H} THEN
    RAISE EXCEPTION 'mr_spend_release_attested: limit of ${ATTESTED_RELEASES_PER_24H} attested releases per 24 h reached' USING ERRCODE = 'insufficient_privilege';
  END IF;
  PERFORM set_config('mr.spend_fn', 'on', true);
  BEGIN
    INSERT INTO public.mr_release_nonce (nonce, store, spend_id, key_id)
    VALUES (decode(translate(m->>'nonce', '-_', '+/') || '=', 'base64'), p_store, p_id, k.key_id);
  EXCEPTION WHEN unique_violation THEN
    PERFORM set_config('mr.spend_fn', 'off', true);
    RAISE EXCEPTION 'mr_spend_release_attested: replay (nonce or spend already attested)' USING ERRCODE = 'unique_violation';
  END;
  UPDATE public.mr_spend SET status = 'released', updated_ms = now_ms, attestation_msg = p_msg, attestation_sig = p_sig
   WHERE store = p_store AND id = p_id;
  INSERT INTO public.mr_spend_audit (store, id, at_ms, actor, action, from_status, to_status, reason, proof_tx_id, proof_last_valid, proof_margin)
  VALUES (p_store, p_id, now_ms, session_user::text || ' (label, untrusted: ' || left(btrim(p_label), 64) || ')',
          'attested-release', s.status, 'released', left(p_reason, 2000) || ' [key ' || k.key_id || ']', s.tx_id, s.last_valid, k.margin_rounds);
  PERFORM set_config('mr.spend_fn', 'off', true);
  RETURN QUERY SELECT true, s.status;
END $fn$;
REVOKE ALL ON FUNCTION mr_spend_release_attested(text, text, bytea, bytea, text, text) FROM PUBLIC;

-- R44: a pending row with stored signed bytes whose settle outcome never got recorded (client saw an error, process
-- died) is moved to ambiguous after a timeout, so it can take the attested-release path. Never to released.
CREATE OR REPLACE FUNCTION mr_spend_pending_signed_to_ambiguous(p_store text, p_older_than_ms bigint)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE now_ms bigint := (extract(epoch FROM clock_timestamp()) * 1000)::bigint; r record; n integer := 0;
BEGIN
  IF p_older_than_ms IS NULL OR p_older_than_ms < 60000 THEN
    RAISE EXCEPTION 'mr_spend_pending_signed_to_ambiguous: timeout must be >= 60000 ms' USING ERRCODE = 'check_violation';
  END IF;
  FOR r IN SELECT s.id FROM public.mr_spend s
            WHERE s.store = p_store AND s.status = 'pending' AND s.signed_txn IS NOT NULL AND s.updated_ms < now_ms - p_older_than_ms
            ORDER BY s.id FOR UPDATE LOOP
    PERFORM set_config('mr.spend_fn', 'on', true);
    UPDATE public.mr_spend SET status = 'ambiguous', updated_ms = now_ms WHERE store = p_store AND id = r.id;
    INSERT INTO public.mr_spend_audit (store, id, at_ms, actor, action, from_status, to_status, reason)
    VALUES (p_store, r.id, now_ms, session_user::text, 'stuck-pending-ambiguous', 'pending', 'ambiguous',
            'signed bytes stored but no settle outcome recorded within ' || p_older_than_ms || ' ms');
    PERFORM set_config('mr.spend_fn', 'off', true);
    n := n + 1;
  END LOOP;
  RETURN n;
END $fn$;
REVOKE ALL ON FUNCTION mr_spend_pending_signed_to_ambiguous(text, bigint) FROM PUBLIC;

CREATE OR REPLACE FUNCTION mr_signer_revoke(p_key_id text, p_reason text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE n bigint;
BEGIN
  -- R43-P3: application_name is a guard against accidental calls only; the real control is EXECUTE (owner only).
  IF coalesce(current_setting('application_name', true), '') <> 'mr-admin-window' THEN
    RAISE EXCEPTION 'mr_signer_revoke: only from an mr-admin-window session' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF length(btrim(coalesce(p_reason, ''))) < 8 THEN
    RAISE EXCEPTION 'mr_signer_revoke: a reason of 8+ characters is required' USING ERRCODE = 'check_violation';
  END IF;
  PERFORM set_config('mr.signer_revoke', 'on', true);
  UPDATE public.mr_signer_key SET revoked_at = clock_timestamp(), revoke_reason = left(p_reason, 500) || ' (by ' || session_user::text || ')'
   WHERE key_id = p_key_id AND revoked_at IS NULL;
  GET DIAGNOSTICS n = ROW_COUNT;
  PERFORM set_config('mr.signer_revoke', 'off', true);
  IF n = 0 THEN RETURN false; END IF;
  RAISE NOTICE 'mr_signer_revoke: key % revoked', p_key_id;
  RETURN true;
END $fn$;
REVOKE ALL ON FUNCTION mr_signer_revoke(text, text) FROM PUBLIC;

${unsignedRefused}
`;
}
