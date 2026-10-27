#!/bin/sh
# rev 24 (§24.8): generate the verifier's Ed25519 co-signing key ON this host, once, at first boot. The private key
# never leaves the host and is never printed. Only the public key is exported (for the DB cosigner pin).
#   key: $MR_KEY_DIR/cosign.key  PKCS#8 PEM, 0600, owner $MR_KEY_OWNER (default root:root; dir 0700)
#   pub: $MR_KEY_DIR/cosign.pub  base64 of the raw 32-byte public key (cosignerPubkeyB64), 0644
# R67-P3-5: the key is root:root. systemd's LoadCredential reads it as root and hands a private copy to
# mr-verifier.service only; no service uid (mr-verifier runs the gcp-token / page units too) can open the source.
# Refuses to overwrite an existing key (a lost key = a new key + a new DB pin, never a silent swap).
# R67-P3-6: every run (and `--check`, the verifier's ExecStartPre) fails closed unless the dir is a real 0700 dir and
# the key a regular, non-symlink, single-link 0600 file, both owned by $MR_KEY_OWNER.
# R67 nit: if the key exists but cosign.pub is missing (crash between the two renames), the pub is re-exported.
set -euf
umask 077
DIR=${MR_KEY_DIR:-/var/lib/mr-verifier-key}
OWNER=${MR_KEY_OWNER:-root}
KEY="$DIR/cosign.key"; PUB="$DIR/cosign.pub"
die() { echo "mr-verifier-keygen: $*" >&2; exit 1; }
check() {
  [ -L "$DIR" ] && die "$DIR is a symlink (refused)"
  [ -d "$DIR" ] || die "$DIR is not a directory"
  [ -L "$KEY" ] && die "$KEY is a symlink (refused)"
  [ -f "$KEY" ] || die "$KEY is not a regular file"
  ou=$(id -u "$OWNER") || die "unknown owner $OWNER"
  [ "$(stat -c '%u %a' "$DIR")" = "$ou 700" ] || die "$DIR must be owned by $OWNER, mode 0700 (refused)"
  [ "$(stat -c '%u %a %h' "$KEY")" = "$ou 600 1" ] || die "$KEY must be owned by $OWNER, mode 0600, one link (refused)"
}
pubout() {
  # raw public key = last 32 bytes of the DER SubjectPublicKeyInfo
  openssl pkey -in "$1" -pubout -outform DER 2>/dev/null | tail -c 32 | base64 -w0 > "$PUB.tmp"
  [ "$(base64 -d "$PUB.tmp" | wc -c)" -eq 32 ] || { rm -f "$PUB.tmp"; die "bad public key length"; }
  chmod 0644 "$PUB.tmp"
}
if [ "${1:-}" = "--check" ]; then check; exit 0; fi
if [ -e "$KEY" ] || [ -L "$KEY" ]; then
  check
  if [ ! -s "$PUB" ]; then
    pubout "$KEY"; mv "$PUB.tmp" "$PUB"; sync
    echo "mr-verifier-keygen: re-exported missing pub; cosignerPubkeyB64=$(cat "$PUB")"
  else
    echo "mr-verifier-keygen: $KEY exists; not regenerating" >&2
  fi
  exit 0
fi
[ -L "$DIR" ] && die "$DIR is a symlink (refused)"
mkdir -p "$DIR"; chmod 0700 "$DIR"
TMP="$DIR/.cosign.key.tmp"
rm -f "$TMP" "$PUB.tmp"
openssl genpkey -algorithm ed25519 -out "$TMP" 2>/dev/null
chmod 0600 "$TMP"
pubout "$TMP" || { rm -f "$TMP"; exit 1; }
if [ "$(id -u)" -eq 0 ]; then chown "$OWNER:$(id -gn "$OWNER")" "$DIR" "$TMP"; fi
mv "$TMP" "$KEY"
mv "$PUB.tmp" "$PUB"
sync
check
echo "mr-verifier-keygen: new key; cosignerPubkeyB64=$(cat "$PUB") (pin this in the DB and config; the private key stays on this host)"
