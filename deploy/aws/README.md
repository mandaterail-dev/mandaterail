# deploy/aws: AWS backup KMS key only (no AWS co-signer)

R76-P3-6 (Oct 22, 2026): the AWS verifier design (`main.tf`, the Lambda forwarder) and the §24 option C root
(`deploy/aws-rolesanywhere/`) were removed from the repo, together with the `aws` / `aliyun-aws-kms` verifier
platforms. The only active MainNet co-signer is `aliyun-softkey` (docs/ops/kms-key-order.md). History keeps the
old files (`git log -- deploy/aws/main.tf`).

What remains here is the lockdown of the existing AWS KMS key (`alias/mandaterail-verifier`, a locked backup):
- `backup/key-policy.backup-locked.json`: root keeps `kms:*`; explicit Deny `kms:Sign` and `kms:ScheduleKeyDeletion` for all.
- `backup/check-key-policy.sh`: read-only drift check (exit 1 on drift).
- `backup/alerts.sh`: EventBridge -> SNS alerts for that key (run only with the owner's approval; it creates cloud resources).

No Terraform in this repo creates or wires an AWS KMS key.
