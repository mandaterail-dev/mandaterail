#!/bin/sh
# R51-P3-1 / R52: refresh the verifier's HTTPS allowlist (nftables can't match host names). Resolves every host in
# /etc/mr-verifier/egress-hosts.conf through the local resolver (systemd-resolved stub; DNSSEC is NOT enforced
# here, see §22) and loads the addresses into inet mr @https_allowed4/6.
# R52-P2-1: `nft add element` on an existing element does not reset its timeout, so each run is ONE `nft -f -`
# batch: `add` + `destroy element` + `add element` for the resolved addresses (v4 and v6). The batch is atomic: the
# addresses are never missing, their 2 h expiry restarts, and other elements are kept (nothing is flushed; an
# address that stops resolving just ages out). Exits non-zero (OnFailure= pages) if a host is unfilled or resolves
# to nothing; the addresses that did resolve are still loaded.
set -euf
HOSTS=${MR_EGRESS_HOSTS:-/etc/mr-verifier/egress-hosts.conf}
NFT=${MR_NFT:-/usr/sbin/nft}
fail=0
v4="" v6=""
for h in $(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$HOSTS"); do
  case "$h" in
    *'<'*|*'>'*|*'*'*|*'?'*|*'['*) echo "mr-egress-refresh: unfilled/wildcard host: $h" >&2; fail=1; continue ;;
  esac
  a4=$(getent ahostsv4 "$h" | awk '$2=="STREAM"{print $1}' | sort -u)
  a6=$(getent ahostsv6 "$h" | awk '$2=="STREAM" && $1 !~ /^::ffff:/{print $1}' | sort -u)
  if [ -z "$a4$a6" ]; then echo "mr-egress-refresh: $h did not resolve" >&2; fail=1; continue; fi
  v4="$v4 $a4" v6="$v6 $a6"
done
# one list per family, de-duplicated (front ends share addresses across hosts, §22)
v4=$(printf '%s\n' $v4 | sed '/^$/d' | sort -u | paste -sd, - | sed 's/,/, /g')
v6=$(printf '%s\n' $v6 | sed '/^$/d' | sort -u | paste -sd, - | sed 's/,/, /g')
# add (no-op if present; makes the destroy valid on interval sets, which refuse to destroy a missing element),
# destroy, add again: the fresh element gets the set's full 2 h timeout. All in one atomic transaction.
batch=""
for fam in 4 6; do
  eval "l=\$v$fam"
  [ -n "$l" ] && batch="${batch}add element inet mr https_allowed$fam { $l }
destroy element inet mr https_allowed$fam { $l }
add element inet mr https_allowed$fam { $l }
"
done
[ -n "$batch" ] && printf '%s' "$batch" | "$NFT" -f -
echo "mr-egress-refresh: v4 [$v4] v6 [$v6]"
exit "$fail"
