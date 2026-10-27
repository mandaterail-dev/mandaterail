# deploy/aliyun: mr-verifier (co-signer) on Alibaba Cloud (rev 22, NOT APPLIED)

The OpenTofu equivalent of deploy/aws, for the second verifier on its **own** small ECS instance in its own VPC in
US (Virginia) us-east-1. It never runs on the app ECS (8.221.97.26). See docs/ops/attested-release-signer.md §24.

- RAM role for ECS (`mr-verifier`): may call `kms:AsymmetricSign` / `kms:GetPublicKey` on the one key, only from the
  verifier VPC (`acs:SourceVpc`, via the `kms-vpc` endpoint) and only from the instance private /32 (`acs:VpcSourceIp`, R63-P3c, verify live).
- KMS key (`prevent_destroy`, deletion protection): declared **only** when `kms_instance_id` is set. An asymmetric key
  needs a paid KMS instance (USD 500/mo subscription, ~USD 4.50/day pay-as-you-go), so it needs the owner's approval.
- EIP (`prevent_destroy`, deletion protection): WireGuard ingress and the pinned source address.
- ActionTrail (read + write events) -> SLS -> alerts by webhook to ntfy.sh and Healthchecks (both **outside**
  Alibaba): every AsymmetricSign, every KMS / RAM / ECS-metadata / EIP / trail / alert change, plus a daily heartbeat.
- The ntfy and Healthchecks URLs are capabilities: `TF_VAR_ntfy_webhook_url`, `TF_VAR_healthchecks_url`; the state and
  plans are encrypted (OpenTofu `encryption`, `TF_VAR_state_passphrase`).

    tofu init && tofu validate          # done in the repo
    tofu plan -var account_id=... -var image_id=...   # only with the owner; no apply without approval
