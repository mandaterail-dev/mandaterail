#!/usr/bin/env bash
# R75-P2-2: free alerting for the AWS backup key. EventBridge default bus (CloudTrail management events, no trail)
# -> SNS topic mr-kms-backup-alerts. Free tier: AWS-service events on the default bus are free; SNS email 1,000/mo free.
# Idempotent. The email subscription is OPT-IN (MR_ALERT_EMAIL=...): AWS mails a confirmation link the owner must click.
set -euo pipefail
REGION="${AWS_REGION:-us-east-1}"; ACCT=860273388508
KEY="arn:aws:kms:us-east-1:${ACCT}:key/7b2d2a83-0633-439e-8214-713c449fdd0c"
T=$(aws sns create-topic --region "$REGION" --name mr-kms-backup-alerts --query TopicArn --output text)
aws sns set-topic-attributes --region "$REGION" --topic-arn "$T" --attribute-name Policy --attribute-value "$(cat <<J
{"Version":"2012-10-17","Statement":[{"Sid":"EventBridgePublish","Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sns:Publish","Resource":"$T","Condition":{"StringEquals":{"aws:SourceAccount":"$ACCT"}}}]}
J
)"
pat() { printf '{"source":["aws.kms"],"detail-type":["AWS API Call via CloudTrail"],"detail":{"eventSource":["kms.amazonaws.com"],"eventName":%s,"resources":{"ARN":["%s"]}}}' "$1" "$KEY"; }
# write/admin events (PutKeyPolicy, EnableKey, DisableKey, CreateGrant, ScheduleKeyDeletion)
aws events put-rule --region "$REGION" --name mr-kms-backup-admin --state ENABLED \
  --event-pattern "$(pat '["PutKeyPolicy","EnableKey","DisableKey","CreateGrant","ScheduleKeyDeletion"]')" >/dev/null
# Sign is a read-only management event: needs the ALL_CLOUTRAIL_MANAGEMENT_EVENTS rule state (still no trail)
aws events put-rule --region "$REGION" --name mr-kms-backup-sign --state ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS \
  --event-pattern "$(pat '["Sign"]')" >/dev/null
for r in mr-kms-backup-admin mr-kms-backup-sign; do
  aws events put-targets --region "$REGION" --rule "$r" --targets "Id=sns,Arn=$T" >/dev/null
done
if [ -n "${MR_ALERT_EMAIL:-}" ]; then
  aws sns subscribe --region "$REGION" --topic-arn "$T" --protocol email --notification-endpoint "$MR_ALERT_EMAIL" >/dev/null
  echo "subscription requested: confirm the AWS email sent to $MR_ALERT_EMAIL"
fi
echo "alerts: $T"
