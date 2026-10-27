# Unlock-key custody (R48-P2-3 / R49-P3)

The helper's only unlock path is a message signed by the owner's Ed25519 **unlock key** (`MR-HELPER-UNLOCK-v1`,
docs/ops/attested-release-signer.md §18.3). Whoever holds it can clear a lock (not sign a payment, not raise caps),
and each use is logged, paged, rate-limited (3 per 10 min at `/v1/unlock`) and moves the counter up.

## Rules
1. **Never on the signer VM, never in Google, never in the verifier's AWS account, never in a cloud password
   manager in plaintext.** It never touches a machine that holds any other MandateRail key.
2. **Pick one, in this order:**
   - **Hardware (preferred):** a YubiKey 5 (fw ≥ 5.7, Ed25519 in PIV, or OpenPGP Ed25519 signing subkey) used only
     for this, PIN + touch required. Key generated ON the device (non-exportable). Backup: a **second** YubiKey with
     its own key, stored in a different building. The helper pins one unlock public key; the backup's public key is recorded
     in the break-glass log, and switching to it is a config change + restart (paged).
   - **Offline:** generated on an offline machine (live USB, no network), stored as an age-encrypted file
     (passphrase ≥ 6 diceware words) on two USB sticks in two places; a paper copy of the passphrase in a sealed
     envelope with the second stick. Signing happens on that offline machine; the signed message is carried by QR
     or USB to the CLI machine.
3. The CLI machine only ever sees the **signed unlock message** (valid ≤ 10 min, single nonce), never the key.
4. Record in the break-glass log: date, key id, where each copy is, who can reach it. Check the copies every
   quarter (sign a TestNet unlock against a dev helper).
5. **Rotation / loss:** a lost or suspected copy → pin the new public key (config change, restart, paged), retire
   the old key id. Until then the helper stays locked: a locked signer is the safe failure.
6. Never paste the key, its passphrase or a signed-unlock message into chat, tickets or email.
