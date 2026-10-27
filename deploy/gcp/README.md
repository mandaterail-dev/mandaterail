# mr-signer on Google Cloud (rev 15). NOTHING HERE IS PROVISIONED.

the owner must first approve the project and the costs (docs/ops/attested-release-signer.md §17.6). Every command
below is a plan to run by hand after that approval. None of them has been run.

## Files
| File | Purpose |
|---|---|
| `gcp/mr-signer.service` | mr-signer on the VM. No WireGuard: the CLI comes in through IAP TCP forwarding. |
| `gcp/mr-piv-sign@.service` (+ `signer/mr-piv-sign.socket`) | The helper with `CloudKmsBackend`. It is the only uid allowed to reach the metadata token endpoint and Cloud KMS. |
| `gcp/nftables.conf` | In-VM firewall: IAP ingress only; metadata server (port 80) open to mr-piv and root only; Private Google Access open to mr-piv; HTTPS allowlist for mr-signer |
| `gcp/cloudkms.example.json` | Helper backend config: pinned key version, public key, protection level and SA |
| `signer/host/chrony.conf` | Unchanged. Add `server metadata.google.internal iburst` as a third, non-NTS source if you want one. |

## 1. Project and org
- Use a **separate project** used only for the signer, e.g. `mr-signer-prod`, with its own billing budget alert.
  The verifier goes on a different provider (Vultr) or, failing that, a different project under a different Google account.
- **Organization policies need an organization.** A personal Gmail account has none: it takes a free Cloud Identity
  org on a domain the owner controls. With an org, set:
  - `iam.disableServiceAccountKeyCreation` and `iam.disableServiceAccountKeyUpload` (attached SA only)
  - `compute.vmExternalIpAccess` (deny all)
  - `compute.requireShieldedVm`
  - `compute.requireOsLogin`
  - `iam.automaticIamGrantsForDefaultServiceAccounts` (no Editor role for the default SA)
  - `gcp.resourceLocations` = `in:us-central1-locations`
  - `compute.restrictVpcPeering`
  - `compute.skipDefaultNetworkCreation`
  - `iam.allowedPolicyMemberDomains`
  Without an org: do the same by hand (no SA keys, no external IP) and check it with the `gcloud` audits in §5.
- **VPC Service Controls** also needs an org (Access Context Manager). Use a perimeter around `cloudkms.googleapis.com`
  and `secretmanager.googleapis.com` for this project. Without an org, rely on the IAM condition plus the
  attached SA instead.

## 2. Key (Cloud KMS)
```
gcloud kms keyrings create mr-signer --location us-central1
gcloud kms keys create attest --keyring mr-signer --location us-central1 \
  --purpose asymmetric-signing --default-algorithm ec-sign-ed25519 --protection-level software
gcloud kms keys versions get-public-key 1 --key attest --keyring mr-signer --location us-central1   # pin in the DB (v11 mr_signer_key)
```
Ed25519 is **SOFTWARE only** in Cloud KMS (HSM offers P-256/P-384/secp256k1). Leave the key without automatic
rotation. A new version means a new key row (v11.x), as before.

## 3. Service account and IAM (least privilege)
- `mr-signer@PROJECT.iam.gserviceaccount.com`, attached to the VM; no keys (the org policy above enforces it).
- Custom role `mrAttestSigner` with **only** `cloudkms.cryptoKeyVersions.useToSign` and
  `cloudkms.cryptoKeyVersions.viewPublicKey`, granted **on the key `attest` only** (not the project), with a
  condition that pins the version:
  `resource.name == "projects/PROJECT/locations/us-central1/keyRings/mr-signer/cryptoKeys/attest/cryptoKeyVersions/1"`.
- `roles/secretmanager.secretAccessor` on the 3 secrets only (ntfy topic, hc ping URL, B2 app key); root reads
  them at boot (`mr-secrets-fetch` oneshot, writes the 0600 env file).
- `roles/logging.logWriter` and `roles/monitoring.metricWriter` (Ops Agent), nothing else. Don't use the
  default compute SA.
- Human admins: the owner only. There is no `roles/owner` for anyone else; break-glass goes through a separate account
  with hardware 2FA.

## 4. VM
```
gcloud compute instances create mr-signer-1 --zone us-central1-a --machine-type e2-micro \
  --no-address --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
  --service-account mr-signer@PROJECT.iam.gserviceaccount.com --scopes cloud-platform \
  --metadata enable-oslogin=TRUE,block-project-ssh-keys=TRUE,serial-port-enable=FALSE \
  --image-family debian-13 --image-project debian-cloud --boot-disk-size 10GB --boot-disk-type pd-standard
```
- **Shielded VM:** Secure Boot, vTPM and integrity monitoring (an alert on `earlyBootReportEvent` /
  `lateBootReportEvent` failures). vTPM keeps the measured-boot notes in `signer/host/README.md` workable:
  `systemd-creds --tpm2-pcrs=7` seals local state. **The custom UKI/dm-verity image needs your own Secure Boot
  keys.** GCE accepts custom keys for a custom image (`--signature-database-file`); until then use the stock Debian
  image + IMA notes.
- **Confidential VM is NOT available on E2** (only on N2D/C2D/C3D/C4D/C3 and up). It costs ≈ $74/month and is
  flagged (>$15).
- **No external IP**. Admin access: IAP TCP forwarding (`gcloud compute ssh --tunnel-through-iap`) + OS Login with
  2FA. The CLI reaches the signer with `gcloud compute start-iap-tunnel mr-signer-1 8787 --local-host-port=localhost:8787`.

## 5. Network
- A custom VPC `mr` with one subnet and Private Google Access **on**. Private DNS zone `googleapis.com` → CNAME
  `private.googleapis.com` (199.36.153.8/30), so KMS/Secret Manager traffic never leaves Google.
- **Cloud NAT** (Public NAT, 1 VM) for internet egress to the providers / ntfy / hc-ping / B2.
- **Network firewall policy** (Cloud NGFW):
  - ingress: allow `35.235.240.0/20` tcp:22,8787 (IAP) only;
  - egress: allow `199.36.153.8/30` tcp:443 (Essentials, free); allow FQDN objects for the pinned hosts on
    tcp:443 (Standard tier, $0.0193/GiB evaluated, cents per month at this traffic); deny all else.
- In-VM `gcp/nftables.conf` repeats this per uid.
- Checks once set up:
  - `gcloud iam service-accounts keys list --managed-by=user` → empty;
  - `gcloud compute instances describe` → no `accessConfigs`;
  - `gcloud projects get-iam-policy`.

## 6. Audit
- Enable **Data Access audit logs, DATA_READ, for `cloudkms.googleapis.com`** (off by default), so every
  `AsymmetricSign` is logged with the caller and key version.
- Log sink → a **locked** Cloud Storage bucket (retention policy locked, e.g. 400 days) in the project.
- **Alerts page outside Google (R48-P2-2, R49)**: `alerts/main.tf` (not applied) replaces the old chain-count metric with
  log-match alert policies → a Pub/Sub notification channel, plus an independent log sink to the same topic →
  `alerts/forwarder` (pinned `package-lock.json`) → ntfy, plus a daily heartbeat that the verifier and Healthchecks
  watch (dead-man, 26 h). The VM gets a **reserved static internal IP** (`google_compute_address`, create the VM with
  `--private-network-ip`); a sign is "from the VM" only if callerIp is that IP and callerNetwork is the pinned VPC.
  The verifier also reconciles every `AsymmetricSign` with a `signed` chain event and pages on any mismatch. They fire on: every `AsymmetricSign`; any sign not by the
  signer SA from the VM; actAs / token minting / attaching the SA to a VM / SA keys; destroy, restore, disable,
  update or create of key versions; auditConfig, IAM, sink, exclusion and alert-policy changes; IAP and OS Login
  admin grants. The ntfy URL is a capability: it lives only in Secret Manager (`mr-ntfy-url`), never in terraform vars or state.
- **No organization (rev 21, §23.3):** the project is under an individual account with no Cloud Identity organization, so
  the org-level items above are replaced by project-level controls: no service-account key creation, restricted IAM,
  Data Access logs on for KMS and IAM.
- **IAP is admin access only.** There is no reset or unlock of the signing helper (rev 21, §23 of
  docs/ops/attested-release-signer.md): its long lock clears by itself after `6 h * 2^(n-1)`, and a tamper pause lifts
  only after the cooldown with a fresh 2-of-2 resume quorum checked by the DB (v16). No human path pauses or unpauses.
- **B2 write key (P3)**: the VM holds a B2 key for the off-host audit. Use an application key restricted to the audit
  bucket and prefix with `writeFiles` only (no delete, no list of other buckets, Object Lock in compliance mode), and
  have the verifier alert on any object not written from the VM's egress IP / not chained. Compromise of the VM can
  append junk but cannot rewrite or delete the history.
- The off-host ChainedAudit (B2 Object Lock) stays. It is now outside Google, and that is deliberate.
