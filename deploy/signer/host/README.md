# Signer / verifier host configuration (rev 12, nothing provisioned)

Files (all under `deploy/`):

| File | Purpose |
|---|---|
| `signer/host/mr-signer.service` | mr-signer, hardened unit, secrets via `EnvironmentFile` (0600 root) |
| `signer/mr-piv-sign.socket`, `signer/mr-piv-sign@.service` | helper, socket activation, peer-uid gate, `PrivateNetwork`, `BindsTo` the YubiKey device |
| `signer/70-mr-yubikey.rules` | udev: `/dev/mr-yubikey` for the pinned serial only, `TAG+="systemd"` |
| `signer/host/usbguard-rules.conf` | block all USB except the pinned YubiKey and root hubs |
| `signer/host/nftables.conf` | default-drop both ways; WireGuard in, signer port from the CLI peer only, HTTPS out only to `@https_allowed` |
| `signer/host/chrony.conf` | NTS-only time, 2 sources minimum |
| `verifier/mr-verifier.service` | the second verifier, on a **different host and cloud account** |

## Egress allowlist
nftables can't match host names. `mr-egress-refresh` (a oneshot timer, every 30 min, not written yet: a 20-line
script) resolves the pinned hosts (providers, `s3.<region>.backblazeb2.com`, `ntfy.sh`, `hc-ping.com`) through the
local resolver (DNSSEC is not enforced; see the design doc §22) and adds the A/AAAA records to `@https_allowed4/6` with a 2 h timeout. The signer
also pins every host in its config, so a wrong DNS answer can at most cause a refusal (TLS + host pin).

## Integrity: dm-verity + IMA (notes; needs the real host to test)
- **Root filesystem read-only with dm-verity.** Build the image (Debian 13 + node + `/opt/mr-signer/<sha>`) as a
  squashfs/erofs root; `veritysetup format` gives the root hash; put it on the kernel command line inside a
  **UKI** (unified kernel image) signed with your own Secure Boot key (`sbctl`/`ukify`), so the root hash itself
  is measured and signed. Mutable state lives only on `/var/lib/{mr-signer,mr-piv,chrony}` (ext4, `nodev,nosuid,noexec`).
- **Measured boot.** TPM2 PCRs 7 (Secure Boot state) + 11 (UKI) seal the PIV PIN credential
  (`systemd-creds encrypt --tpm2-pcrs=7+11`), so a modified kernel/initrd/cmdline can't unseal the PIN.
- **IMA appraisal** for anything executed outside the verity root: `ima_policy=appraise_tcb ima_appraise=enforce`
  with an `evmctl`-signed `/usr/local/bin/mr-peercred-gate`; the IMA log is shipped off-host with the audit events.
- **Updates**: a new image + root hash = a new signed UKI (A/B partitions, `systemd-boot` boot counting).
  The MainNet image build drops everything in `signer/mainnet-image.exclude` and fails if any is present.
- **What this does not cover**: a root compromise at runtime can still use the logged-in PIV session; that's what
  the caps, the second verifier (v12 quorum 2) and the DB limits are for.

## Checks run on the box (no host)
`systemd-analyze verify` on the units (with stub binaries), `nft -c -f nftables.conf`; see `test/host-config.test.ts`.

The verifier host uses the same `nftables.conf` and `chrony.conf` with `mr-signer` → `mr-verifier` and its own
WireGuard peer; it has its own YubiKey (`70-mr-yubikey.rules`/usbguard with that card's serial).
