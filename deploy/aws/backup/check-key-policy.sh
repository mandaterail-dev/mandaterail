#!/usr/bin/env bash
# R75-P2-2: fail (exit 1) if the LIVE key policy of the AWS backup key differs from key-policy.backup-locked.json.
# Read-only (kms:GetKeyPolicy + DescribeKey). Uses ambient AWS creds; prints no secrets.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DEFAULT_KEY="arn:aws:kms:us-east-1:860273388508:key/7b2d2a83-0633-439e-8214-713c449fdd0c"
DEFAULT_POLICY="$HERE/key-policy.backup-locked.json"
# R79-P3-3: overrides are refused unless MR_TEST_MODE=1 (tests only).
if [ "${MR_TEST_MODE:-0}" != "1" ] && { [ -n "${MR_EXPECTED_POLICY:-}" ] || [ -n "${MR_AWS_BACKUP_KEY:-}" ]; }; then
  echo "REFUSED: MR_EXPECTED_POLICY/MR_AWS_BACKUP_KEY overrides require MR_TEST_MODE=1" >&2; exit 3
fi
KEY="${MR_AWS_BACKUP_KEY:-$DEFAULT_KEY}"
POLICY="${MR_EXPECTED_POLICY:-$DEFAULT_POLICY}"
REGION="${AWS_REGION:-us-east-1}"
# Always log what is being compared (stderr, so stdout stays OK/DRIFT).
echo "check-key-policy: policy=$POLICY sha256=$(sha256sum "$POLICY" | cut -d' ' -f1) key=$KEY test_mode=${MR_TEST_MODE:-0}" >&2
live="$(aws kms get-key-policy --region "$REGION" --key-id "$KEY" --policy-name default --query Policy --output text)"
LIVE="$live" python3 - "$POLICY" <<'PY'
import json, os, sys
def norm(x):
    if isinstance(x, dict): return {k: norm(v) for k, v in sorted(x.items())}
    if isinstance(x, list): return sorted((norm(v) for v in x), key=lambda v: json.dumps(v, sort_keys=True))
    return x
# R77-P3-5: the top-level policy "Id" is a label with no effect (renamed in the repo copy); every statement is compared
want = json.load(open(sys.argv[1])); got = json.loads(os.environ["LIVE"])
want.pop("Id", None); got.pop("Id", None)
want = norm(want); got = norm(got)
if want != got:
    print("DRIFT: live key policy differs from key-policy.backup-locked.json"); sys.exit(1)
print("OK: live key policy matches key-policy.backup-locked.json")
PY
