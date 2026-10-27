/**
 * v12: M-of-N attested releases (R45-GATE-1, docs/ops/attested-release-signer.md §15).
 *
 * - mr_cosigner_key: pinned Ed25519 keys of the SECOND VERIFIER, write-once like mr_signer_key, and never the same
 *   key (or pubkey) as any primary signer key (trigger). Only revoked_at/revoke_reason may change, once.
 * - mr_release_quorum: per network, how many attestations a release needs. MainNet is fixed at 2 (CHECK);
 *   TestNet is seeded at 1 (dev flows) and the owner may raise it to 2.
 * - mr_release_cosign: one row per co-signed release (nonce PK, unique per spend), written only inside the release fn.
 * - mr_spend_release_attested(store, id, msg, sig, cmsg, csig, label, reason): verifies the co-signature
 *   (MR-RELEASE-COSIGN-v1\n + restricted JCS) with mr_ed25519, checks it binds to sha256(msg) and the same spend /
 *   txId / lastValid, that its own observations are from pinned operators DISJOINT from the primary's (an
 *   independent absence check), then runs the v11 checks (renamed mr_spend_release_attested_v11, callable only
 *   from here). The 6-argument form remains as a wrapper with no co-signature: refused where the quorum is 2.
 * - R48-P2-1 (v12 amended before any database applied it): every key pins its TRUST DOMAIN, "<provider>:<account>"
 *   (e.g. gcp:mr-signer-prod, aws:123456789012). mr_cosigner_key.trust_domain is NOT NULL; mr_signer_key gains a
 *   write-once trust_domain column (set at INSERT, never changed). A co-signed release requires both set and the
 *   PROVIDERS to differ (split_part(.., ':', 1)), so a Google-hosted signer can't be co-signed by a Google key.
 * Never edit after release; append v13.
 */
import { ATTEST_OBS_KEYS, KEY_ID_HEX_LEN } from "./v11-attested.js";

export const COSIGN_PREFIX = "MR-RELEASE-COSIGN-v1\n";
export const COSIGN_MSG_KEYS = [
  "attestHash", "expiry", "genesisHash", "keyId", "lastValid", "network", "nonce", "observations", "round", "spendId", "store", "txId", "v",
] as const;

/** "<provider>:<account>", provider a lowercase word (gcp, aws, vultr, home, testnet-local ...). */
export const TRUST_DOMAIN_RE = "^[a-z][a-z0-9-]{1,15}:[A-Za-z0-9._-]{1,63}$";

export function v12Sql(): string {
  return `
-- R49-P3: the trust domain is bound to the KMS / hardware resource id (write-once with it)
CREATE OR REPLACE FUNCTION mr_v12_domain_matches(dom text, res text) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$
  SELECT CASE split_part(dom, ':', 1)
    WHEN 'gcp' THEN split_part(dom, ':', 2) ~ '^[a-z][a-z0-9-]{4,28}[a-z0-9]$' AND res ~ ('^projects/' || split_part(dom, ':', 2) || '/locations/[a-z0-9-]+/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+/cryptoKeyVersions/[0-9]+$')
    WHEN 'aws' THEN split_part(dom, ':', 2) ~ '^[0-9]{12}$' AND res ~ ('^arn:aws:kms:[a-z0-9-]+:' || split_part(dom, ':', 2) || ':key/[0-9a-f-]{36}$')
    -- R50-P3: the serial is checked to be digits before it is used in the pattern (no regex injection)
    WHEN 'yubikey' THEN split_part(dom, ':', 2) ~ '^[0-9]{1,12}$' AND res ~ ('^piv:' || split_part(dom, ':', 2) || ':9[acde]$')
    -- R50-P3: any other provider is refused (add a WHEN for a new provider deliberately)
    ELSE false
  END IS TRUE
$fn$;

CREATE TABLE IF NOT EXISTS mr_cosigner_key (
  key_id        text PRIMARY KEY CHECK (key_id ~ '^[0-9a-f]{${KEY_ID_HEX_LEN}}$'),
  pubkey        bytea NOT NULL UNIQUE CHECK (length(pubkey) = 32),
  network       text NOT NULL CHECK (network IN ('testnet', 'mainnet')),
  trust_domain  text NOT NULL CHECK (trust_domain ~ '${TRUST_DOMAIN_RE}'),
  key_resource  text NOT NULL CHECK (length(key_resource) <= 256),
  CHECK (mr_v12_domain_matches(trust_domain, key_resource)),
  created_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
  revoked_at    timestamptz,
  revoke_reason text,
  CHECK (key_id = left(encode(sha256(pubkey), 'hex'), ${KEY_ID_HEX_LEN})),
  CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
);
REVOKE ALL ON mr_cosigner_key FROM PUBLIC;

-- R48-P2-1: the primary signer key's trust domain, write-once (v11 rows from before v12 stay NULL and can't co-sign)
ALTER TABLE mr_signer_key ADD COLUMN IF NOT EXISTS trust_domain text CHECK (trust_domain ~ '${TRUST_DOMAIN_RE}');
ALTER TABLE mr_signer_key ADD COLUMN IF NOT EXISTS key_resource text CHECK (length(key_resource) <= 256);
ALTER TABLE mr_signer_key DROP CONSTRAINT IF EXISTS mr_signer_key_domain_resource;
ALTER TABLE mr_signer_key ADD CONSTRAINT mr_signer_key_domain_resource CHECK (trust_domain IS NULL OR mr_v12_domain_matches(trust_domain, key_resource));
CREATE OR REPLACE FUNCTION mr_v12_signer_domain_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $fn$
BEGIN
  IF TG_OP = 'UPDATE' AND (NEW.trust_domain, NEW.key_resource) IS DISTINCT FROM (OLD.trust_domain, OLD.key_resource) THEN
    RAISE EXCEPTION 'mr_signer_key: trust_domain / key_resource are write-once (set at INSERT)' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF TG_OP = 'INSERT' AND NEW.trust_domain IS NULL THEN
    RAISE EXCEPTION 'mr_signer_key: trust_domain is required (provider:account)' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $fn$;
DROP TRIGGER IF EXISTS mr_signer_key_domain_guard ON mr_signer_key;
CREATE TRIGGER mr_signer_key_domain_guard BEFORE INSERT OR UPDATE ON mr_signer_key FOR EACH ROW EXECUTE FUNCTION mr_v12_signer_domain_guard();

CREATE TABLE IF NOT EXISTS mr_release_quorum (
  network    text PRIMARY KEY CHECK (network IN ('testnet', 'mainnet')),
  required_m integer NOT NULL CHECK (required_m IN (1, 2)),
  CHECK (network <> 'mainnet' OR required_m = 2)
);
REVOKE ALL ON mr_release_quorum FROM PUBLIC;
INSERT INTO mr_release_quorum (network, required_m) VALUES ('mainnet', 2), ('testnet', 1) ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS mr_release_cosign (
  nonce           bytea PRIMARY KEY CHECK (length(nonce) = 32),
  store           text NOT NULL,
  spend_id        text NOT NULL,
  cosigner_key_id text NOT NULL REFERENCES mr_cosigner_key(key_id),
  attest_hash     text NOT NULL CHECK (attest_hash ~ '^[0-9a-f]{64}$'),
  cosign_msg      bytea NOT NULL,
  cosign_sig      bytea NOT NULL CHECK (length(cosign_sig) = 64),
  used_at         timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (store, spend_id)
);
REVOKE ALL ON mr_release_cosign FROM PUBLIC;

CREATE OR REPLACE FUNCTION mr_v12_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE is_owner boolean;
BEGIN
  SELECT pg_get_userbyid(c.relowner) = current_user::text INTO is_owner FROM pg_class c WHERE c.oid = TG_RELID;
  IF TG_OP IN ('TRUNCATE', 'DELETE') THEN
    RAISE EXCEPTION '%: % refused (write-once)', TG_TABLE_NAME, TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF TG_TABLE_NAME = 'mr_release_cosign' THEN
    IF TG_OP = 'UPDATE' OR coalesce(current_setting('mr.cosign_fn', true), '') <> 'on' OR NOT is_owner THEN
      RAISE EXCEPTION 'mr_release_cosign: rows are written only by mr_spend_release_attested' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
  END IF;
  IF TG_TABLE_NAME = 'mr_release_quorum' THEN
    IF NOT is_owner THEN RAISE EXCEPTION 'mr_release_quorum: owner only' USING ERRCODE = 'insufficient_privilege'; END IF;
    IF TG_OP = 'UPDATE' AND NEW.required_m < OLD.required_m THEN
      RAISE EXCEPTION 'mr_release_quorum: the quorum can only be raised' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
  END IF;
  -- mr_cosigner_key
  IF NOT is_owner THEN RAISE EXCEPTION 'mr_cosigner_key: owner only' USING ERRCODE = 'insufficient_privilege'; END IF;
  IF TG_OP = 'INSERT' THEN
    IF EXISTS (SELECT 1 FROM public.mr_signer_key k WHERE k.key_id = NEW.key_id OR k.pubkey = NEW.pubkey) THEN
      RAISE EXCEPTION 'mr_cosigner_key: a co-signer key must be distinct from every primary signer key' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF (NEW.key_id, NEW.pubkey, NEW.network, NEW.trust_domain, NEW.key_resource, NEW.created_at) IS DISTINCT FROM (OLD.key_id, OLD.pubkey, OLD.network, OLD.trust_domain, OLD.key_resource, OLD.created_at)
     OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL THEN
    RAISE EXCEPTION 'mr_cosigner_key: only a one-way revoke is allowed' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $fn$;
DROP TRIGGER IF EXISTS mr_cosigner_key_guard ON mr_cosigner_key;
CREATE TRIGGER mr_cosigner_key_guard BEFORE INSERT OR UPDATE OR DELETE ON mr_cosigner_key FOR EACH ROW EXECUTE FUNCTION mr_v12_guard();
DROP TRIGGER IF EXISTS mr_cosigner_key_guard_t ON mr_cosigner_key;
CREATE TRIGGER mr_cosigner_key_guard_t BEFORE TRUNCATE ON mr_cosigner_key FOR EACH STATEMENT EXECUTE FUNCTION mr_v12_guard();
DROP TRIGGER IF EXISTS mr_release_quorum_guard ON mr_release_quorum;
CREATE TRIGGER mr_release_quorum_guard BEFORE INSERT OR UPDATE OR DELETE ON mr_release_quorum FOR EACH ROW EXECUTE FUNCTION mr_v12_guard();
DROP TRIGGER IF EXISTS mr_release_quorum_guard_t ON mr_release_quorum;
CREATE TRIGGER mr_release_quorum_guard_t BEFORE TRUNCATE ON mr_release_quorum FOR EACH STATEMENT EXECUTE FUNCTION mr_v12_guard();
DROP TRIGGER IF EXISTS mr_release_cosign_guard ON mr_release_cosign;
CREATE TRIGGER mr_release_cosign_guard BEFORE INSERT OR UPDATE OR DELETE ON mr_release_cosign FOR EACH ROW EXECUTE FUNCTION mr_v12_guard();
DROP TRIGGER IF EXISTS mr_release_cosign_guard_t ON mr_release_cosign;
CREATE TRIGGER mr_release_cosign_guard_t BEFORE TRUNCATE ON mr_release_cosign FOR EACH STATEMENT EXECUTE FUNCTION mr_v12_guard();

-- the v11 verifier becomes internal: only the v12 entry point (same owner, SECURITY DEFINER) calls it
ALTER FUNCTION mr_spend_release_attested(text, text, bytea, bytea, text, text) RENAME TO mr_spend_release_attested_v11;
REVOKE ALL ON FUNCTION mr_spend_release_attested_v11(text, text, bytea, bytea, text, text) FROM PUBLIC;
DO $rv$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mr_release') THEN
    EXECUTE 'REVOKE ALL ON FUNCTION mr_spend_release_attested_v11(text, text, bytea, bytea, text, text) FROM mr_release';
  END IF;
END $rv$;

CREATE OR REPLACE FUNCTION mr_spend_release_attested(p_store text, p_id text, p_msg bytea, p_sig bytea,
                                                     p_cmsg bytea, p_csig bytea, p_label text, p_reason text)
RETURNS TABLE (ok boolean, from_status text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE
  pfx bytea := convert_to(E'MR-RELEASE-COSIGN-v1\\n', 'UTF8');
  apfx_len int := length(convert_to(E'MR-RELEASE-ATTEST-v1\\n', 'UTF8'));
  net text; net_hash text; need_m int; body bytea; bt text; c jsonb; a jsonb; ck record; margin int;
  o jsonb; sdom text; prim_ops text[] := '{}'; ops text[] := '{}'; i int := 0; ts timestamptz; exp timestamptz; r record;
  iso text := '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$';
  want_keys text[] := ARRAY['${COSIGN_MSG_KEYS.join("','")}'];
  want_obs text[] := ARRAY['${ATTEST_OBS_KEYS.join("','")}'];
BEGIN
  SELECT n.network, n.genesis_hash INTO net, net_hash FROM public.mr_network n WHERE n.singleton;
  IF net IS NULL THEN RAISE EXCEPTION 'mr_spend_release_attested: network marker is not set' USING ERRCODE = 'check_violation'; END IF;
  SELECT q.required_m INTO need_m FROM public.mr_release_quorum q WHERE q.network = net;
  IF need_m IS NULL THEN need_m := 2; END IF; -- fail closed
  IF p_cmsg IS NULL OR p_csig IS NULL THEN
    IF need_m >= 2 THEN
      RAISE EXCEPTION 'mr_spend_release_attested: % requires 2 attestations (signer + second verifier); no co-signature given', net USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN QUERY SELECT * FROM public.mr_spend_release_attested_v11(p_store, p_id, p_msg, p_sig, p_label, p_reason);
    RETURN;
  END IF;
  -- co-signature: prefix, printable canonical JSON, exact key set
  IF p_msg IS NULL OR length(p_msg) <= apfx_len THEN RAISE EXCEPTION 'mr_spend_release_attested: primary attestation missing' USING ERRCODE = 'check_violation'; END IF;
  IF length(p_cmsg) > 4096 OR length(p_cmsg) <= length(pfx) OR substring(p_cmsg FROM 1 FOR length(pfx)) <> pfx THEN
    RAISE EXCEPTION 'mr_spend_release_attested: co-signature prefix / length' USING ERRCODE = 'check_violation';
  END IF;
  body := substring(p_cmsg FROM length(pfx) + 1);
  IF position('\\x00'::bytea IN body) > 0 THEN RAISE EXCEPTION 'mr_spend_release_attested: NUL in co-signature' USING ERRCODE = 'check_violation'; END IF;
  bt := convert_from(body, 'UTF8');
  IF bt !~ '^[ -~]+$' THEN RAISE EXCEPTION 'mr_spend_release_attested: co-signature is not printable ASCII' USING ERRCODE = 'check_violation'; END IF;
  BEGIN c := bt::jsonb; EXCEPTION WHEN others THEN RAISE EXCEPTION 'mr_spend_release_attested: co-signature is not JSON' USING ERRCODE = 'check_violation'; END;
  IF jsonb_typeof(c) <> 'object' OR public.mr_jcs(c) <> bt THEN
    RAISE EXCEPTION 'mr_spend_release_attested: co-signature is not canonical (restricted JCS)' USING ERRCODE = 'check_violation';
  END IF;
  IF (SELECT array_agg(x ORDER BY x) FROM jsonb_object_keys(c) x) <> (SELECT array_agg(x ORDER BY x) FROM unnest(want_keys) x)
     OR c->'v' <> '1'::jsonb OR jsonb_typeof(c->'observations') <> 'array' THEN
    RAISE EXCEPTION 'mr_spend_release_attested: co-signature key set / version' USING ERRCODE = 'check_violation';
  END IF;
  -- the co-signer key: pinned, not revoked, this network, distinct from the primary key
  BEGIN a := convert_from(substring(p_msg FROM apfx_len + 1), 'UTF8')::jsonb; EXCEPTION WHEN others THEN
    RAISE EXCEPTION 'mr_spend_release_attested: primary attestation is not JSON' USING ERRCODE = 'check_violation'; END;
  SELECT * INTO ck FROM public.mr_cosigner_key k WHERE k.key_id = c->>'keyId' FOR SHARE;
  IF NOT FOUND OR ck.revoked_at IS NOT NULL OR ck.network <> net OR c->>'network' <> net THEN
    RAISE EXCEPTION 'mr_spend_release_attested: co-signer key % is unknown, revoked or of another network', c->>'keyId' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF ck.key_id = a->>'keyId' OR EXISTS (SELECT 1 FROM public.mr_signer_key k WHERE k.pubkey = ck.pubkey) THEN
    RAISE EXCEPTION 'mr_spend_release_attested: the two attestations must come from distinct pinned keys' USING ERRCODE = 'insufficient_privilege';
  END IF;
  -- R48-P2-1: different trust domains, and different PROVIDERS
  SELECT k.trust_domain INTO sdom FROM public.mr_signer_key k WHERE k.key_id = a->>'keyId';
  IF sdom IS NULL OR ck.trust_domain IS NULL OR split_part(sdom, ':', 1) = split_part(ck.trust_domain, ':', 1) THEN
    RAISE EXCEPTION 'mr_spend_release_attested: the co-signer key must be pinned in a different trust domain (provider) than the signer key (% vs %)', coalesce(sdom, 'unset'), coalesce(ck.trust_domain, 'unset') USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NOT mr_crypto.mr_ed25519_verify(p_cmsg, p_csig, ck.pubkey) THEN
    RAISE EXCEPTION 'mr_spend_release_attested: co-signature does not verify' USING ERRCODE = 'insufficient_privilege';
  END IF;
  -- binding: the co-signature is over THIS primary attestation and the same spend
  IF c->>'attestHash' <> encode(sha256(p_msg), 'hex') THEN
    RAISE EXCEPTION 'mr_spend_release_attested: co-signature is not bound to this attestation' USING ERRCODE = 'check_violation';
  END IF;
  IF c->>'genesisHash' <> net_hash OR c->>'store' <> p_store OR c->>'spendId' <> p_id OR c->>'txId' <> a->>'txId'
     OR c->'lastValid' <> a->'lastValid' OR jsonb_typeof(c->'round') <> 'number' OR c->>'nonce' !~ '^[A-Za-z0-9_-]{43}$' OR c->>'expiry' !~ iso THEN
    RAISE EXCEPTION 'mr_spend_release_attested: co-signature fields differ from the attestation / spend' USING ERRCODE = 'check_violation';
  END IF;
  exp := (c->>'expiry')::timestamptz;
  IF exp <= clock_timestamp() OR exp - clock_timestamp() > interval '15 minutes' THEN
    RAISE EXCEPTION 'mr_spend_release_attested: co-signature expired or expiry more than 15 min ahead' USING ERRCODE = 'check_violation';
  END IF;
  SELECT k.margin_rounds INTO margin FROM public.mr_signer_key k WHERE k.key_id = a->>'keyId';
  IF margin IS NULL THEN RAISE EXCEPTION 'mr_spend_release_attested: primary key unknown' USING ERRCODE = 'insufficient_privilege'; END IF;
  IF (c->>'round')::bigint < (a->>'lastValid')::bigint + margin THEN
    RAISE EXCEPTION 'mr_spend_release_attested: co-signature round is not past lastValid + margin' USING ERRCODE = 'check_violation';
  END IF;
  -- independence: the second verifier's own observations, from pinned operators the primary did not use
  SELECT coalesce(array_agg(DISTINCT e.value->>'operator'), '{}') INTO prim_ops FROM jsonb_array_elements(a->'observations') e;
  IF jsonb_array_length(c->'observations') < 1 OR jsonb_array_length(c->'observations') > 4 THEN
    RAISE EXCEPTION 'mr_spend_release_attested: co-signature needs 1 to 4 observations' USING ERRCODE = 'check_violation';
  END IF;
  FOR o IN SELECT e.value FROM jsonb_array_elements(c->'observations') e LOOP
    i := i + 1;
    IF jsonb_typeof(o) <> 'object' OR (SELECT array_agg(x ORDER BY x) FROM jsonb_object_keys(o) x) <> (SELECT array_agg(x ORDER BY x) FROM unnest(want_obs) x)
       OR o->>'at' !~ iso OR jsonb_typeof(o->'round') <> 'number' OR jsonb_typeof(o->'idxRound') <> 'number' THEN
      RAISE EXCEPTION 'mr_spend_release_attested: co-signature observation % shape', i USING ERRCODE = 'check_violation';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.mr_signer_operator so WHERE so.network = net AND so.operator = o->>'operator')
       OR NOT EXISTS (SELECT 1 FROM public.mr_network_provider np WHERE np.network = net AND np.host = o->>'provider' AND np.operator_id = o->>'operator') THEN
      RAISE EXCEPTION 'mr_spend_release_attested: co-signature observation % operator/provider is not pinned', i USING ERRCODE = 'check_violation';
    END IF;
    IF o->>'operator' = ANY (prim_ops) THEN
      RAISE EXCEPTION 'mr_spend_release_attested: co-signature observation % uses operator % already used by the signer (not independent)', i, o->>'operator' USING ERRCODE = 'check_violation';
    END IF;
    IF (o->>'round')::bigint < (a->>'lastValid')::bigint + margin
       OR (o->>'method' = 'idx404' AND (o->>'idxRound')::bigint < (a->>'lastValid')::bigint + margin)
       OR (o->>'method' = 'blockscan' AND (o->>'idxRound')::bigint <> (a->>'lastValid')::bigint)
       OR o->>'method' NOT IN ('idx404', 'blockscan') THEN
      RAISE EXCEPTION 'mr_spend_release_attested: co-signature observation % round / method', i USING ERRCODE = 'check_violation';
    END IF;
    ts := (o->>'at')::timestamptz;
    IF ts > clock_timestamp() + interval '60 seconds' OR ts < clock_timestamp() - interval '15 minutes' OR ts > exp THEN
      RAISE EXCEPTION 'mr_spend_release_attested: co-signature observation % time', i USING ERRCODE = 'check_violation';
    END IF;
  END LOOP;
  -- the v11 checks (primary signature, row binding, lv_est, 2 operators, 5/24 h limit, nonce) and the release
  SELECT * INTO r FROM public.mr_spend_release_attested_v11(p_store, p_id, p_msg, p_sig, p_label, p_reason);
  IF r.ok THEN
    PERFORM set_config('mr.cosign_fn', 'on', true);
    BEGIN
      INSERT INTO public.mr_release_cosign (nonce, store, spend_id, cosigner_key_id, attest_hash, cosign_msg, cosign_sig)
      VALUES (decode(translate(c->>'nonce', '-_', '+/') || '=', 'base64'), p_store, p_id, ck.key_id, c->>'attestHash', p_cmsg, p_csig);
    EXCEPTION WHEN unique_violation THEN
      PERFORM set_config('mr.cosign_fn', 'off', true);
      RAISE EXCEPTION 'mr_spend_release_attested: co-signature replay' USING ERRCODE = 'unique_violation';
    END;
    PERFORM set_config('mr.cosign_fn', 'off', true);
  END IF;
  RETURN QUERY SELECT r.ok, r.from_status;
END $fn$;
REVOKE ALL ON FUNCTION mr_spend_release_attested(text, text, bytea, bytea, bytea, bytea, text, text) FROM PUBLIC;

-- 6-argument form (no co-signature): only where the quorum is 1 (TestNet dev); refused on MainNet
CREATE OR REPLACE FUNCTION mr_spend_release_attested(p_store text, p_id text, p_msg bytea, p_sig bytea, p_label text, p_reason text)
RETURNS TABLE (ok boolean, from_status text)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
  SELECT * FROM public.mr_spend_release_attested(p_store, p_id, p_msg, p_sig, NULL::bytea, NULL::bytea, p_label, p_reason);
$fn$;
REVOKE ALL ON FUNCTION mr_spend_release_attested(text, text, bytea, bytea, text, text) FROM PUBLIC;
`;
}
