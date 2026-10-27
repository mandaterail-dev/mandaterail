# mr_ed25519 (attested-release-signer §3.1, rev 9)

Verify-only Ed25519 for Postgres 18: `mr_crypto.mr_ed25519_verify(msg bytea, sig bytea, pk bytea) -> boolean`.
libsodium 1.0.20 statically linked (tarball vendored, sha256 pinned in build.sh); no rpath, no LD_LIBRARY_PATH,
`NEEDED` = libc only. Sizes are exact (sig 64, pk 32) and raise; msg ≤ 4096. EXECUTE revoked from PUBLIC.

- Build: `ops/pg/mr_ed25519/build.sh <outdir>` (podman, `postgres:18-bookworm@sha256:9551dd5b…`, pinned
  `postgresql-server-dev-18=18.6-1.pgdg12+2`). Two clean builds on 2026-10-19 gave the identical
  `mr_ed25519.so` sha256 recorded in `SHA256SUMS` (reproducibility gate).
- Test: `ops/pg/mr_ed25519/test/run-local.sh <outdir>`: throwaway PG 18 cluster, RFC 8032 tests 1-3,
  bit-flip negatives, size errors, STRICT, PUBLIC EXECUTE revoked.
- Not installed on any ECS database (v11 is not applied there).
