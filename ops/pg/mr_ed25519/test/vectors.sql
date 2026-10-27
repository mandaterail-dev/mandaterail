-- Golden vectors for mr_ed25519 (RFC 8032 §7.1 tests 1-3 + negatives). Run: psql -v ON_ERROR_STOP=1 -f test/vectors.sql
\set ON_ERROR_STOP 1
CREATE SCHEMA IF NOT EXISTS mr_crypto;
CREATE EXTENSION IF NOT EXISTS mr_ed25519 SCHEMA mr_crypto;
CREATE TEMP TABLE v(name text, msg bytea, sig bytea, pk bytea, want boolean);
INSERT INTO v VALUES
 ('rfc8032-1', '\x', '\xe5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b', '\xd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', true),
 ('rfc8032-2', '\x72', '\x92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00', '\x3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', true),
 ('rfc8032-3', '\xaf82', '\x6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a', '\xfc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025', true),
 ('msg-flip', '\x73', '\x92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00', '\x3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', false),
 ('sig-flip', '\x72', '\x93a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00', '\x3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', false),
 ('pk-flip', '\x72', '\x92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00', '\x3c4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', false),
 ('wrong-key', '\x72', '\x92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00', '\xd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', false);
DO $$ DECLARE r record; got boolean; BEGIN
  FOR r IN SELECT * FROM v LOOP
    got := mr_crypto.mr_ed25519_verify(r.msg, r.sig, r.pk);
    IF got IS DISTINCT FROM r.want THEN RAISE EXCEPTION 'vector % : got % want %', r.name, got, r.want; END IF;
  END LOOP;
  -- size errors must RAISE, not return false
  BEGIN PERFORM mr_crypto.mr_ed25519_verify('\x72', '\x00', '\x3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'); RAISE EXCEPTION 'short sig accepted';
  EXCEPTION WHEN invalid_parameter_value THEN NULL; END;
  BEGIN PERFORM mr_crypto.mr_ed25519_verify('\x72', (SELECT sig FROM v WHERE name='rfc8032-2'), '\x3d40'); RAISE EXCEPTION 'short pk accepted';
  EXCEPTION WHEN invalid_parameter_value THEN NULL; END;
  BEGIN PERFORM mr_crypto.mr_ed25519_verify(decode(repeat('00', 4097), 'hex'), (SELECT sig FROM v WHERE name='rfc8032-2'), (SELECT pk FROM v WHERE name='rfc8032-2')); RAISE EXCEPTION 'long msg accepted';
  EXCEPTION WHEN invalid_parameter_value THEN NULL; END;
  IF mr_crypto.mr_ed25519_verify(NULL, '\x00', '\x00') IS NOT NULL THEN RAISE EXCEPTION 'STRICT broken'; END IF;
  IF has_function_privilege('public', 'mr_crypto.mr_ed25519_verify(bytea,bytea,bytea)', 'EXECUTE') THEN RAISE EXCEPTION 'PUBLIC can EXECUTE'; END IF;
  RAISE NOTICE 'mr_ed25519 golden vectors: all passed';
END $$;
