\echo Use "CREATE EXTENSION mr_ed25519" to load this file. \quit
CREATE FUNCTION mr_crypto.mr_ed25519_verify(msg bytea, sig bytea, pk bytea) RETURNS boolean
  AS 'MODULE_PATHNAME', 'mr_ed25519_verify' LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;
REVOKE ALL ON FUNCTION mr_crypto.mr_ed25519_verify(bytea, bytea, bytea) FROM PUBLIC;
