#!/usr/bin/env bash
# Install a build (default /tmp/b1) into a throwaway local PG 18 cluster and run the golden vectors.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd); b=${1:-/tmp/b1}
PGBIN=/usr/lib/postgresql/18/bin; LIB=$($PGBIN/pg_config --pkglibdir); SHARE=$($PGBIN/pg_config --sharedir)/extension
sudo install -o root -g root -m 0644 "$b/mr_ed25519.so" "$LIB/"
sudo install -o root -g root -m 0644 "$here/mr_ed25519.control" "$here/mr_ed25519--1.0.sql" "$SHARE/"
(cd "$b" && sha256sum -c --ignore-missing SHA256SUMS >/dev/null) && sha256sum "$LIB/mr_ed25519.so" | grep -q "$(awk '/mr_ed25519.so/{print $1}' "$b/SHA256SUMS")"
d=$(mktemp -d); trap 'pg_ctl() { :; }; $PGBIN/pg_ctl -D "$d" -m immediate stop >/dev/null 2>&1; rm -rf "$d"' EXIT
$PGBIN/initdb -D "$d" -A trust -U postgres >/dev/null
$PGBIN/pg_ctl -D "$d" -o "-p 55418 -k $d -c listen_addresses=''" -l "$d/log" start >/dev/null
$PGBIN/psql -X -q -h "$d" -p 55418 -U postgres -d postgres -f "$here/test/vectors.sql"
