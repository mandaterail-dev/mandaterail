#!/usr/bin/env bash
# Rehearsal A3: a REAL other uid (nobody, via sudo) connects to a socket served through mr-peercred-gate that
# allows only the current uid. Expect: the current uid gets through; nobody is refused with exit 77 and 0 bytes.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd); tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT; chmod 755 "$tmp"
cc -O2 -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2 -o "$tmp/gate" "$here/peercred-gate.c"
cat > "$tmp/client.py" <<'PY'
import socket, sys
c = socket.socket(socket.AF_UNIX); c.connect(sys.argv[1]); c.settimeout(3)
c.sendall(b'{"msg":"","confirm":{}}\n'); d = b""
try:
    while True:
        x = c.recv(100)
        if not x: break
        d += x
except (socket.timeout, ConnectionResetError): pass
print(len(d), d.decode(errors="replace").strip())
PY
python3 - "$tmp" "$(id -u)" <<'PY'
import os, socket, subprocess, sys
tmp, me = sys.argv[1], int(sys.argv[2])
def trial(as_nobody):
    p = os.path.join(tmp, "s.sock")
    if os.path.exists(p): os.unlink(p)
    srv = socket.socket(socket.AF_UNIX); srv.bind(p); os.chmod(p, 0o777); srv.listen(1)
    cmd = (["sudo", "-n", "-u", "nobody"] if as_nobody else []) + ["python3", os.path.join(tmp, "client.py"), p]
    cl = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    conn, _ = srv.accept()
    r = subprocess.run([os.path.join(tmp, "gate"), str(me), "/bin/sh", "-c", "head -n 1 >/dev/null; echo through"], stdin=conn.fileno(), stdout=conn.fileno(), stderr=subprocess.PIPE, text=True)
    conn.close(); out = cl.communicate(timeout=10)[0].strip()
    return r.returncode, out, r.stderr.strip()
rc, out, err = trial(False); print(f"A3 uid {me} (allowed): gate exit {rc}, client received: {out!r}"); assert rc == 0 and "through" in out
rc, out, err = trial(True); print(f"A3 uid 65534 nobody (other): gate exit {rc}, client received: {out!r}, gate stderr: {err!r}"); assert rc == 77 and out.startswith("0"), (rc, out)
print("A3 PASS")
PY
