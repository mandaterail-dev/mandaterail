/**
 * mr-piv-sign backends behind one interface. The helper (helper.ts) is the only caller; it runs the checks first.
 *
 * - YubikeyPkcs11Backend (ykcs11.ts): PIV slot 9c Ed25519 (YubiKey 5.7+) via PKCS#11; tested with a mock token.
 *   The PIN comes from the TPM-sealed credential (systemd LoadCredentialEncrypted=), never argv/env/logs.
 *   Touch policy NEVER and PIN policy ONCE for the automated signer (rev 10 §13).
 * - CloudKmsBackend (cloudkms.ts, rev 15): Cloud KMS EC_SIGN_ED25519 key version, attached-SA token from the GCE
 *   metadata server, every signature verified against the pinned key; tested with a mock metadata server + KMS.
 * - AwsKmsBackend (awskms.ts, R48-P2-1): the verifier key outside Google; ECC_NIST_EDWARDS25519 / ED25519_SHA_512 RAW,
 *   IMDSv2 instance-role credentials, SigV4; mock-tested.
 * - SoftkeyFileEd25519Backend (softkey-file.ts, rev 24): the verifier's key as a host-generated file via systemd
 *   LoadCredential; MainNet only behind the manifest-pinned verifierSoftkey gate plus a host opt-in.
 * - SoftwareEd25519Backend (backend-software.ts): TESTNET-ONLY, excluded from the MainNet image
 *   (deploy/signer/mainnet-image.exclude; test/piv.test.ts "MainNet image" checks the MainNet entry never imports it).
 */

export interface SignBackend {
  readonly kind: "yubikey-piv" | "cloudkms" | "awskms" | "softkey-file" | "software-testnet-only";
  publicKey(): Promise<Uint8Array>;
  sign(msg: Uint8Array): Promise<Uint8Array>;
}

/** R45: the real backend is YubikeyPkcs11Backend (ykcs11.ts); this name is kept for the MainNet entry. */
export { YubikeyPkcs11Backend as YubikeyPivBackend } from "./ykcs11.js";
export { CloudKmsBackend } from "./cloudkms.js";
export { AwsKmsBackend } from "./awskms.js";

export class KeyResourceMismatch extends Error {}
/** R50-P3: the DB's key_resource pin must name exactly the key this backend is configured for (and is required on MainNet). */
export function assertKeyResource(network: string, pinned: string | undefined, actual: string): void {
  if (pinned === undefined) {
    if (network === "mainnet") throw new KeyResourceMismatch("keyResource (the v12 key_resource pin) is required on MainNet");
    return;
  }
  if (pinned !== actual) throw new KeyResourceMismatch(`key_resource pin ${pinned} does not name the configured key ${actual}`);
}
