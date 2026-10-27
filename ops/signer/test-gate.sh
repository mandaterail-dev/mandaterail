#!/usr/bin/env bash
# Tests mr-peercred-gate: the allowed uid reaches the command over the socket; any other uid is refused.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cc -O2 -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2 -o "$tmp/gate" "$here/peercred-gate.c"
python3 - "$tmp" "$(id -u)" <<'PY'
import os, socket, subprocess, sys
tmp, me = sys.argv[1], int(sys.argv[2])
def trial(allowed):
    p = os.path.join(tmp, "s.sock")
    if os.path.exists(p): os.unlink(p)
    srv = socket.socket(socket.AF_UNIX); srv.bind(p); srv.listen(1)
    cli = socket.socket(socket.AF_UNIX); cli.connect(p)
    conn, _ = srv.accept()
    r = subprocess.run([os.path.join(tmp, "gate"), str(allowed), "/bin/sh", "-c", "echo through"], stdin=conn.fileno(), stdout=conn.fileno(), stderr=subprocess.PIPE)
    conn.close(); cli.settimeout(2)
    data = b""
    try:
        while True:
            d = cli.recv(100)
            if not d: break
            data += d
    except socket.timeout: pass
    return r.returncode, data
rc, out = trial(me); assert rc == 0 and out == b"through\n", (rc, out)
rc, out = trial(me + 1); assert rc == 77 and out == b"", (rc, out)
print("peercred-gate: allowed uid passes, other uid refused (77)")
PY
