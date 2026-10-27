#!/usr/bin/env bash
# Start throwaway Postgres + Redis (loopback, random ports, temp dirs), run
# "$@" with MR_TEST_PG_URL / MR_TEST_REDIS_URL set, then tear both down.
# Nothing persists and nothing touches existing local services. Redis runs
# with AOF (appendfsync always) so the restart test can check durability.
# If MR_TEST_PG_URL and MR_TEST_REDIS_URL are already set, just runs "$@".
# R18-P3-1: all output passes through a redactor (no connection strings or
# passwords in test / Vitest output); the exit status is the command's own.
set -euo pipefail

redact() {
  python3 -u -c '
import os, re, sys
lits = [v for k, v in os.environ.items() if k in ("MR_TEST_PG_URL", "MR_TEST_REDIS_URL", "DATABASE_URL", "REDIS_URL") and v]
pat = re.compile(r"\b(postgres(?:ql)?|rediss?)://[^\s\"\x27`<>]+")
pw = re.compile(r"(password|passwd|pwd)=[^\s&]+", re.I)
for line in sys.stdin:
    for v in lits:
        line = line.replace(v, "[redacted-url]")
    line = pat.sub(lambda m: m.group(1) + "://[redacted]", line)
    sys.stdout.write(pw.sub(lambda m: m.group(1) + "=***", line))
'
}

run_redacted() {
  set +e
  "$@" 2>&1 | redact
  local rc=${PIPESTATUS[0]}
  set -e
  return "$rc"
}

if [[ -n "${MR_TEST_PG_URL:-}" && -n "${MR_TEST_REDIS_URL:-}" ]]; then
  run_redacted "$@"
  exit $?
fi

for bin in initdb pg_ctl redis-server redis-cli; do
  command -v "$bin" >/dev/null || { echo "with-state-services: $bin not found" >&2; exit 2; }
done

TMP="$(mktemp -d "${TMPDIR:-/tmp}/mr-state.XXXXXX")"
free_port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'; }
PGPORT="$(free_port)"
RPORT="$(free_port)"

cleanup() {
  pg_ctl -D "$TMP/pg" -m immediate stop >/dev/null 2>&1 || true
  redis-cli -p "$RPORT" shutdown nosave >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

initdb -D "$TMP/pg" -U mr --auth=trust >/dev/null
pg_ctl -D "$TMP/pg" -o "-p $PGPORT -k $TMP -c listen_addresses=127.0.0.1 -c fsync=off" -l "$TMP/pg.log" -w start >/dev/null
# v11: the mr_ed25519 extension (ops/pg/mr_ed25519) must be installed in this PG's extension dir; it is
# created in template1 (and postgres) so every test database has mr_crypto.mr_ed25519_verify.
if [[ -f "$(pg_config --sharedir)/extension/mr_ed25519.control" ]]; then
  for db in template1 postgres; do
    psql -X -q -h "$TMP" -p "$PGPORT" -U mr -d "$db" -v ON_ERROR_STOP=1 \
      -c "CREATE SCHEMA IF NOT EXISTS mr_crypto; GRANT USAGE ON SCHEMA mr_crypto TO PUBLIC; CREATE EXTENSION IF NOT EXISTS mr_ed25519 SCHEMA mr_crypto" >/dev/null
  done
else
  echo "with-state-services: mr_ed25519 extension not installed (ops/pg/mr_ed25519/test/run-local.sh installs it); v11 migrations will refuse" >&2
fi
redis-server --port "$RPORT" --bind 127.0.0.1 --save "" --appendonly yes --appendfsync always --daemonize yes --dir "$TMP" --logfile "$TMP/redis.log"
for _ in $(seq 1 50); do redis-cli -p "$RPORT" ping >/dev/null 2>&1 && break; sleep 0.1; done

export MR_TEST_PG_URL="postgres://mr@127.0.0.1:$PGPORT/postgres"
export MR_TEST_REDIS_URL="redis://127.0.0.1:$RPORT"
# For the restart test (ST-P3-5): it restarts these throwaway services only.
export MR_TEST_PG_DATA="$TMP/pg"
export MR_TEST_REDIS_PORT="$RPORT"
export MR_TEST_REDIS_DIR="$TMP"
echo "with-state-services: postgres + redis on loopback (temp, discarded on exit)"
rc=0
run_redacted "$@" || rc=$?
exit "$rc"
