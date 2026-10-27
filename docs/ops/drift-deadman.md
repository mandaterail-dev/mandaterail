# Drift check off-box dead-man alarm (design, NOT applied)

Problem (R80): if the box or cron stops, the hourly drift check silently stops.

Design: `run-check.sh` puts `MandateRail/DriftCheck CheckOK=1` after each rc=0 run.
CloudWatch alarm `mr-drift-check-deadman` (Sum, period 3600s, 2 of 2 periods, threshold <1,
`treat-missing-data=breaching`) publishes to SNS `mr-kms-backup-alerts` on ALARM and OK.
So ~2h with no OK heartbeat => email (once the owner confirms the SNS subscription).
IAM: `cloudwatch:PutMetricData` is resource `*` only (no resource-level support), narrowed by
condition `cloudwatch:namespace = MandateRail/DriftCheck` (`drift-check-iam-policy.deadman.json`).

Apply: `MR_DEADMAN_APPROVED=yes deploy/aws/backup/deadman.sh` (admin creds), then add the
put-metric-data line to run-check.sh (step 3 in the script).

Cost (us-east-1 list, checked 2026-10-22): always-free tier covers 10 custom metrics,
10 standard alarm metrics and 1M API requests/month. This adds 1 metric, 1 alarm, ~720
PutMetricData calls/month => $0.00 while within free tier. Outside free tier: $0.30/metric/mo
+ $0.10/alarm/mo + $0.01 per 1M requests ~= $0.40/mo.
