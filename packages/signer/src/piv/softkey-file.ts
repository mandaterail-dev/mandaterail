/**
 * rev 24 (§24.8, CHANGE FROM DAVID Oct 21, 2026): the verifier's co-signing key as a SOFTWARE Ed25519 key file on its
 * Alibaba host (platform aliyun-softkey). No AWS, no KMS, no hardware protection.
 *
 * - The key is generated ON the host at first boot (deploy/verifier/mr-verifier-keygen.sh) and never leaves it:
 *   /var/lib/mr-verifier-key/cosign.key, PKCS#8 PEM, 0600, root:root in a root 0700 dir (R67-P3-5); checked fail-closed by ExecStartPre (R67-P3-6).
 * - systemd hands it to mr-verifier with LoadCredential=cosign.key:...; this backend reads only
 *   $CREDENTIALS_DIRECTORY/<name> (no path in config, no env var holding key material).
 * - The derived public key must equal cosignerPubkeyB64 (the DB pin); a different key refuses to start.
 * - Network gate: TestNet always; MainNet only when BOTH the host config sets allowMainnet AND the integrity manifest
 *   (sha256-pinned in code) has verifierSoftkey.mainnet = true. Today the manifest pins false.
 * - sign(): only attestation / co-sign / resume messages for this backend's network and genesis pin, every call.
 * Never logs key material; errors name the file, not its contents.
 */
import { createPrivateKey, createPublicKey, sign, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { decodeAttestation, decodeCosign, decodeResume, decodeResumeCosign } from "@mandaterail/storage";
import { GENESIS_PINS, type Network } from "../config.js";
import type { SignBackend } from "./backend.js";
import { assertNotBackupKey } from "./key-order.js";

export const SOFTKEY_CREDENTIAL = "cosign.key";

export interface SoftkeyFileOptions {
  network: Network;
  pubkey: Uint8Array; // cosignerPubkeyB64 (the DB pin)
  credentialName?: string;
  /** host config: opt in to MainNet (also needs the manifest pin) */
  allowMainnet?: boolean;
  /** verifierSoftkey[network] from the sha256-pinned integrity manifest */
  manifestAllows: boolean;
}

export class SoftkeyGateError extends Error {}

export function softkeyGate(network: Network, allowMainnet: boolean | undefined, manifestAllows: boolean): void {
  if (!manifestAllows) throw new SoftkeyGateError(`softkey verifier refused on ${network}: the integrity manifest pins verifierSoftkey.${network} = false`);
  if (network === "mainnet" && allowMainnet !== true) throw new SoftkeyGateError("softkey verifier refused on mainnet: softkey.allowMainnet is not set (and the manifest pin must also be true)");
}

export class SoftkeyFileEd25519Backend implements SignBackend {
  readonly kind = "softkey-file" as const;
  /** set only after the gate passed; verifier.ts checks it before accepting this backend on MainNet */
  readonly gatePassed: Network;
  private readonly sk: KeyObject;
  private readonly pk: Uint8Array;
  constructor(private readonly o: SoftkeyFileOptions, env: NodeJS.ProcessEnv = process.env) {
    softkeyGate(o.network, o.allowMainnet, o.manifestAllows);
    const dir = env.CREDENTIALS_DIRECTORY;
    if (!dir) throw new Error("softkey: CREDENTIALS_DIRECTORY is not set (run under systemd with LoadCredential=cosign.key:...)");
    const name = o.credentialName ?? SOFTKEY_CREDENTIAL;
    if (name.includes("/") || name.startsWith(".")) throw new Error("softkey: credentialName must be a bare credential name");
    const file = path.join(dir, name);
    let raw: Buffer;
    try { raw = readFileSync(file); } catch { throw new Error(`softkey: credential ${name} is missing or unreadable`); }
    try {
      this.sk = createPrivateKey({ key: raw, format: "pem" });
    } catch { throw new Error(`softkey: credential ${name} is not a PKCS#8 PEM private key`); } finally { raw.fill(0); }
    if (this.sk.asymmetricKeyType !== "ed25519") throw new Error(`softkey: credential ${name} is not an Ed25519 key`);
    this.pk = new Uint8Array(createPublicKey(this.sk).export({ format: "der", type: "spki" }).subarray(12));
    if (Buffer.compare(Buffer.from(this.pk), Buffer.from(o.pubkey)) !== 0) throw new Error("softkey: the key file's public key differs from cosignerPubkeyB64 (the DB pin)");
    assertNotBackupKey({ network: o.network, what: "softkey", pubkey: this.pk }); // R75-P2-1
    this.gatePassed = o.network;
  }
  async publicKey(): Promise<Uint8Array> { return this.pk; }
  async sign(msg: Uint8Array): Promise<Uint8Array> {
    let b: { network: string; genesisHash: string };
    try { b = decodeAttestation(msg); } catch {
      try { b = decodeCosign(msg); } catch {
        try { b = decodeResume(msg); } catch {
          try { b = decodeResumeCosign(msg); } catch { throw new Error("softkey: not an attestation / co-signature / resume message"); }
        }
      }
    }
    if (b.network !== this.o.network || b.genesisHash !== GENESIS_PINS[this.o.network]) throw new Error(`softkey: refusing a message for ${b.network} (backend is ${this.o.network})`);
    return new Uint8Array(sign(null, Buffer.from(msg), this.sk));
  }
}
