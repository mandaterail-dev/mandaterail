# MainNet key order (decided by the owner, 2026-10-22; signer updated 2026-10-22 19:31 ET)

1. **aliyun-softkey** — the only active co-signer/verifier key (Ed25519 key file on the Alibaba host; see r51).
2. **GCP Cloud KMS** `projects/mandaterail-signer-25615/locations/us-east1/keyRings/mandaterail/cryptoKeys/signer` — **MainNet main signer** (`active.signer = "gcp"` in `deploy/mainnet/kms-keys.json`; config `deploy/gcp/cloudkms.mainnet.json`). Live: version 1 ENABLED, one key-level signerVerifier binding (mr-signer@); the signer VM does not exist yet (see "Live state").
3. **AWS KMS** `alias/mandaterail-verifier` (us-east-1, account 860273388508) — **backup, locked**.

The backup is kept (never delete or schedule deletion) and is **not used** for MandateRail signing. No AWS co-signer wiring exists in this repo (the former `deploy/verifier/awskms.mainnet.json` and `deploy/aws/imports.tf` were removed; R76-P3-6 also removed `deploy/aws/main.tf`, `deploy/aws-rolesanywhere/` and the `aws` / `aliyun-aws-kms` verifier platforms). `AwsKmsBackend` refuses MainNet in its constructor (R77-P3-4).

## Live state (as reported; UNVERIFIED from this repo)
- GCP signer key (reported by ops agent, 2026-10-23): **active signer**; **key version 1 is ENABLED** and the key IAM has **exactly one** key-level binding, `roles/cloudkms.signerVerifier` for `mr-signer@mandaterail-signer-25615.iam.gserviceaccount.com` (= `deploy/gcp/kms-signer-iam.json`). **Open item:** the signer VM does not exist yet (Compute Engine API is disabled in the project), so nothing can use the key yet; creating the VM (attached SA `mr-signer@`, Private Google Access) needs the owner's approval.
- AWS: key policy `deploy/aws/backup/key-policy.backup-locked.json` — account root keeps `kms:*` (no lockout), explicit Deny `kms:Sign` and `kms:ScheduleKeyDeletion` for all principals. To promote the key later, root removes the deny statements. The repo copy's `Id` was renamed to `mandaterail-aws-backup-lockdown` (R77-P3-5); the drift check ignores the top-level `Id`, so the live policy needs no change for that.

## Making the GCP signer usable (steps 1-3 reported DONE 2026-10-23 by ops agent; step 4 open: no signer VM yet)
Project `mandaterail-signer-25615`, key `projects/mandaterail-signer-25615/locations/us-east1/keyRings/mandaterail/cryptoKeys/signer`.
1. Re-enable key version 1 (it must stay version 1: the inventory pins `cryptoKeyVersions/1` and its public key):
   `gcloud kms keys versions enable 1 --key signer --keyring mandaterail --location us-east1 --project mandaterail-signer-25615`
2. Restore the single key-level binding (= `deploy/gcp/kms-signer-iam.json`): `roles/cloudkms.signerVerifier` for
   `serviceAccount:mr-signer@mandaterail-signer-25615.iam.gserviceaccount.com` on the key (not the keyring or project):
   `gcloud kms keys add-iam-policy-binding signer --keyring mandaterail --location us-east1 --project mandaterail-signer-25615 --member serviceAccount:mr-signer@mandaterail-signer-25615.iam.gserviceaccount.com --role roles/cloudkms.signerVerifier`
3. Check afterwards (read-only): `gcloud kms keys versions describe 1 …` shows `state: ENABLED`, algorithm `EC_SIGN_ED25519`, protection `SOFTWARE`; `gcloud kms keys get-iam-policy signer …` shows exactly that one binding; the public key still equals `pubkeyB64` in the inventory.
4. Pre-existing conditions the signer config relies on (verify, not change): the signer VM's attached service account is `mr-signer@…` (CloudKmsBackend checks the metadata email), and the VM reaches Cloud KMS through Private Google Access.
Notes: Project Owner keeps implicit admin on the key. Nothing else (no keyring/project bindings, no new key versions) is needed. The GCP KMS alerts in `deploy/gcp/alerts/main.tf` (every asymmetric sign, version lifecycle, IAM changes) remain the detection path. Once enabled, the live test `MR_KMS_LIVE=1` "GCP signer key" expects a sign to succeed only from the mr-signer identity.

## Drift check and alerts (R75-P2-2 / R75-P3-1)
- AWS drift: `deploy/aws/backup/check-key-policy.sh` (read-only) exits 1 if the live key policy differs from the repo copy (top-level `Id` ignored). Run it before any funding/pinning. Scheduled hourly via `run-check.sh` (see the drift-check section below); overrides refused unless `MR_TEST_MODE=1` (R79-P3-3, 910efb5).
- AWS alerts (reported applied 2026-10-22, free tier, no trail): `deploy/aws/backup/alerts.sh` creates EventBridge rules `mr-kms-backup-admin` (PutKeyPolicy, EnableKey, DisableKey, CreateGrant, ScheduleKeyDeletion) and `mr-kms-backup-sign` (Sign, read-only management events) on the default bus, filtered to this key ARN, targeting SNS topic `mr-kms-backup-alerts`. The email subscription is opt-in: `MR_ALERT_EMAIL=g.davideh@gmail.com deploy/aws/backup/alerts.sh`, then click the AWS confirmation link.
- Residual: root (and any IAM admin, e.g. the `<iam-user>` user, which has AdministratorAccess) can still PutKeyPolicy; the alert + drift check detect it, they don't prevent it.
- GCP alerts: log-based alert policies not applied (billed per condition). Manual check: `gcloud logging read 'protoPayload.serviceName="cloudkms.googleapis.com" AND logName:"activity" AND protoPayload.resourceName:"cryptoKeys/signer"' --project mandaterail-signer-25615 --freshness 7d`.
- No Terraform in the repo creates an AWS KMS key (R76-P3-6, tested in kms-live.test.ts).

## Enforcement (R75-P2-1, R77)
The order above is behaviour, not only data (`packages/signer/src/piv/key-order.ts`):
- Every key loader (Cloud KMS, AWS KMS, softkey) refuses a key marked backup here (list items, numbered or bulleted) or in `deploy/mainnet/kms-keys.json`
  (resource prefix, any key version, or pinned public key), on every network. A built-in mirror of the backups is
  checked against both files by `packages/signer/test/r77-key-order.test.ts`. An active signer that is also marked backup anywhere is refused (fail closed).
- On MainNet the inventory must be present and well formed (fail closed). `MR_KEY_INVENTORY` / `MR_KEY_ORDER_DOC` are refused on MainNet and with `NODE_ENV=production` (R77-P3-1).
- The MainNet verifier accepts only the manifest-gated aliyun-softkey (`platform: aliyun-softkey`; the manifest pin
  `verifierSoftkey.mainnet` stays `false` until the internal reviewer sign-off); awskms, ykcs11 and cloudkms are refused there.
- Signer: `active.signer = "gcp"`. The `CloudKmsBackend` constructor itself (R77-P3-2) refuses, on MainNet, any key that is not that entry (resource and pinned public key); `cloudKmsFromConfig` also refuses a config whose `role` is not `active`.

## Promoting the AWS backup
Requires the owner's approval, a new audit run, removing the lock above, then pinning the key in the DB only after the host-level lockdown (R72-P2-1 ordering).

## AWS backup key drift check (R77-P3-3)

- `deploy/aws/backup/run-check.sh` runs hourly via cron (`deploy/aws/backup/crontab.example`, `7 * * * *`) and calls `check-key-policy.sh`; results go to `<workdir>/mr-lockdown/drift.log`, stderr to `cron.err`.
- It unsets `MR_EXPECTED_POLICY`/`MR_AWS_BACKUP_KEY`, pins the AWS CLI sha256, and publishes drift to the hardcoded SNS topic `arn:aws:sns:us-east-1:860273388508:mr-kms-backup-alerts`.
- Creds: IAM user `mr-drift-check`, inline policy `drift-check-iam-policy.json` (kms:GetKeyPolicy on the key, sns:Publish on the topic). File `~/.config/mr-lockdown/aws.env` mode 0600.
- The box has no init system: after a reboot cron must be restarted (`sudo /usr/sbin/cron`) — verify with `pgrep cron`.
- Email alerts only flow after the subscriber confirms the SNS subscription.

- R80-P2-1 root cause: the cron daemon started 19:39 EDT was alive but never executed jobs (no output; exact cause not determinable, no syslog on box). Replaced with a fresh `sudo cron -L 15`; verified a `* * * * *` test job and a real scheduled run-check.sh (20:31 EDT, rc=0). After any box restart: `sudo cron -L 15`, then `pgrep -a cron`.
