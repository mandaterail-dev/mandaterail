#!/usr/bin/env bash
# R25-P3-1 / R26-P3-1: run a deploy step (or a whole deploy) with mr_admin's SET
# membership in the table owner granted only for its duration:
#   deploy/mr-admin-window.sh -- <command> [args...]
# - A holder session takes the advisory lock (26026, 1) for the whole window, so
#   two windows can't overlap (the second refuses, exit 1, and touches nothing).
#   The holder lives only as long as this script: if the script is SIGKILLed or
#   crashes, the lock is released within ~1 s while the membership stays; the
#   monitor reports that as "deploy window left open" (membership + no lock).
# - open refuses if any membership in the owner already exists (a leftover).
# - REVOKE (close) runs in an EXIT trap: on success, error, SIGINT and SIGTERM.
# - The command's own exit code is kept, also on SIGINT/SIGTERM (the trap only
#   records the signal; the command decides how it exits). A failed close exits
#   3 (and is loud) even if the command succeeded.
# MR_PSQL: how to reach the database as a superuser (default: the TestNet host).
set -uo pipefail
PSQL="${MR_PSQL:-sudo -u postgres psql -p 5433 -d mandaterail}"
SQL="${MR_WINDOW_SQL:-$(cd "$(dirname "$0")" && pwd)/sql/r25-admin-window.sql}"
[ "${1:-}" = "--" ] && shift
[ $# -gt 0 ] || { echo "usage: $0 -- <command> [args...]" >&2; exit 2; }

window() { $PSQL -X -q -v ON_ERROR_STOP=1 -v window="$1" -f "$SQL" < /dev/null >&2; }
opened=0
closed=0
holder_pid=""
sig=""
tmp="$(mktemp -d)"
close_window() {
  [ "$opened" = 1 ] || return 0
  [ "$closed" = 1 ] && return 0
  closed=1
  local ok=0
  window close || ok=1
  rm -f "$tmp/run"   # the holder's feeder loop stops within 1 s
  [ -n "$holder_pid" ] && kill "$holder_pid" 2>/dev/null
  if [ "$ok" != 0 ]; then
    echo "ALERT mr-admin-window: REVOKE of the owner membership FAILED; revoke it by hand now (r25-admin-window.sql -v window=close)" >&2
    return 1
  fi
  echo "mr-admin-window: closed (mr_admin is not a member of the owner)" >&2
}
on_exit() {
  local rc=$?
  close_window || rc=3
  rm -rf "$tmp"
  [ -n "$holder_pid" ] && kill "$holder_pid" 2>/dev/null
  exit "$rc"
}
trap on_exit EXIT
trap 'sig=INT' INT
trap 'sig=TERM' TERM

# Lock holder: its stdin stays open while this script (pid $$) is alive and the
# window isn't closed (never `wait` on it: the feeder lives as long as we do).
parent=$$
touch "$tmp/run"
{
  printf '%s\n' "SET application_name = 'mr-admin-window';" \
    "SELECT pg_try_advisory_lock(26026, 1) AS got \\gset" \
    "\\if :got" "\\echo LOCKED" "\\else" "\\echo BUSY" "\\quit" "\\endif"
  while kill -0 "$parent" 2>/dev/null && [ -e "$tmp/run" ]; do sleep 1; done
} | $PSQL -X -q -tA > "$tmp/holder" 2>&1 &
holder_pid=$!
for _ in $(seq 1 150); do
  grep -qE '^(LOCKED|BUSY)$' "$tmp/holder" 2>/dev/null && break
  kill -0 "$holder_pid" 2>/dev/null || break
  sleep 0.1
done
if ! grep -qx LOCKED "$tmp/holder" 2>/dev/null; then
  echo "mr-admin-window: another deploy window holds the advisory lock (or the lock holder failed); refusing to open" >&2
  exit 1
fi
[ -n "$sig" ] && { echo "mr-admin-window: interrupted before open" >&2; exit 130; }
if ! window open; then
  echo "mr-admin-window: open failed (a membership in the owner already exists, or the database refused); nothing granted by this run" >&2
  exit 1
fi
opened=1
echo "mr-admin-window: open (mr_admin may SET ROLE to the owner until this command ends)" >&2
"$@"
rc=$?
[ -n "$sig" ] && echo "mr-admin-window: got SIG$sig; keeping the command's exit code $rc" >&2
exit "$rc"
