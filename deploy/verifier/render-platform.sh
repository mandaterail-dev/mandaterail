#!/bin/sh
# R63-P3e: render the verifier's nftables.conf + egress-hosts.conf for one platform:
#   aliyun | aliyun-softkey  (§24.8 rev 24 software key file = the chosen path)
#   R76-P3-6: the AWS co-signer platforms (aws, aliyun-aws-kms) were removed.
# Usage: render-platform.sh <platform> <outdir>. Install the outputs as /etc/nftables.conf and
# /etc/mr-verifier/egress-hosts.conf. The checked-in nftables.conf/egress-hosts.conf are the aliyun render (tested).
set -euf
P=${1:?platform}; OUT=${2:?outdir}; D=$(dirname "$0")
case "$P" in aliyun|aliyun-softkey) ;; *) echo "render-platform: unknown platform $P" >&2; exit 2 ;; esac
mkdir -p "$OUT"
awk -v f="$D/platform/$P.nft" '
  /^# @platform-begin/ { print; while ((getline l < f) > 0) print l; skip = 1; next }
  /^# @platform-end/ { skip = 0 }
  !skip { print }' "$D/nftables.conf" > "$OUT/nftables.conf"
{ sed -n '1,/^# @hosts-begin/p' "$D/egress-hosts.conf"; cat "$D/platform/$P.hosts" "$D/platform/common.hosts"; } > "$OUT/egress-hosts.conf"
