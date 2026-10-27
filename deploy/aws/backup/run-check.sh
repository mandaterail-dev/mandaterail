#!/usr/bin/env bash
# Hourly drift check for MandateRail AWS backup key. Never echoes creds.
set -uo pipefail
unset MR_EXPECTED_POLICY MR_AWS_BACKUP_KEY
LOG=<workdir>/mr-lockdown/drift.log
ENVF="$HOME/.config/mr-lockdown/aws.env"
export PATH=/opt/aws-cli/bin:/usr/local/bin:/usr/bin:/bin AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1
ts(){ date '+%F %T %Z'; }
if [ ! -r "$ENVF" ] || [ "$(stat -c %a "$ENVF")" != 600 ]; then echo "$(ts) ERROR creds file missing/bad perms" >>"$LOG"; exit 2; fi
set -a; while IFS='=' read -r k v; do case "$k" in AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY) export "$k=$v";; esac; done <"$ENVF"; set +a
AWS_PIN=84958b12b8c1d794ba565acec08444cba19704e3e484d38eb45c60c51772460d
AWS_REAL="$(readlink -f /opt/aws-cli/bin/aws 2>/dev/null)"
if [ -z "$AWS_REAL" ] || [ "$(sha256sum "$AWS_REAL" | cut -d' ' -f1)" != "$AWS_PIN" ]; then echo "$(ts) ERROR aws cli hash mismatch/missing at /opt/aws-cli; refusing" >>"$LOG"; exit 3; fi
out="$(bash <workdir>/mr-r51-lockdown/deploy/aws/backup/check-key-policy.sh 2>&1)"; rc=$?
echo "$(ts) rc=$rc $out" | tr '\n' ' ' >>"$LOG"; echo >>"$LOG"
if [ $rc -ne 0 ]; then
  TOPIC=arn:aws:sns:us-east-1:860273388508:mr-kms-backup-alerts
  aws sns publish --topic-arn "$TOPIC" --subject "DRIFT: MandateRail AWS backup key policy" --message "check-key-policy.sh rc=$rc on box at $(ts): $out" --query MessageId --output text >/tmp/mr-sns-mid 2>>"$LOG" && echo "$(ts) published DRIFT to SNS MessageId=$(cat /tmp/mr-sns-mid)" >>"$LOG" || { echo "$(ts) ERROR SNS publish failed" >>"$LOG"; exit 4; }
fi
exit $rc
