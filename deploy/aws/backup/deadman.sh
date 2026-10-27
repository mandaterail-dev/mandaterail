#!/usr/bin/env bash
# NOT EXECUTED. Ready-to-apply off-box dead-man alarm for the MandateRail drift check.
# Requires the owner's approval (creates 1 CloudWatch alarm + 1 custom metric). See docs/ops/drift-deadman.md.
# Run with ADMIN creds. Idempotent (put-* calls overwrite).
set -euo pipefail
[ "${MR_DEADMAN_APPROVED:-}" = yes ] || { echo "refusing: set MR_DEADMAN_APPROVED=yes after the owner approves" >&2; exit 1; }
export AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1
TOPIC=arn:aws:sns:us-east-1:860273388508:mr-kms-backup-alerts
NS=MandateRail/DriftCheck; METRIC=CheckOK
# 1) Alarm: fires if no OK datapoint for 2 consecutive 1h periods; missing data = breaching.
aws cloudwatch put-metric-alarm --alarm-name mr-drift-check-deadman \
  --alarm-description "MandateRail drift check has not reported OK for ~2h (box/cron down?)" \
  --namespace "$NS" --metric-name "$METRIC" --statistic Sum --period 3600 \
  --evaluation-periods 2 --datapoints-to-alarm 2 --threshold 1 \
  --comparison-operator LessThanThreshold --treat-missing-data breaching \
  --alarm-actions "$TOPIC" --ok-actions "$TOPIC"
# 2) Grant mr-drift-check PutMetricData (scoped to namespace via condition).
aws iam put-user-policy --user-name mr-drift-check --policy-name mr-drift-check-min \
  --policy-document file://"$(dirname "$0")"/drift-check-iam-policy.deadman.json
# 3) Then add to run-check.sh after a successful check (rc=0):
#    aws cloudwatch put-metric-data --namespace MandateRail/DriftCheck --metric-name CheckOK --value 1 --unit Count \
#      || { echo "$(ts) ERROR heartbeat put failed" >>"$LOG"; exit 5; }
# 4) SNS topic policy must allow cloudwatch.amazonaws.com to publish (same-account alarms work by default
#    with the default topic policy; verify with: aws sns get-topic-attributes --topic-arn "$TOPIC").
echo "deadman alarm + IAM applied; now apply step 3 to run-check.sh"
