/**
 * TESTNET-ONLY software Ed25519 backend for tests and the TestNet rehearsal. Never in the MainNet image.
 * Construction requires network "testnet" and MR_SIGNER_SOFTWARE_KEY=TESTNET-ONLY; every sign() re-checks the
 * message's network and genesis pin (R43-P2-3); PivHelper refuses this backend for any non-testnet config.
 */
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { decodeAttestation, decodeCosign, decodeResume, decodeResumeCosign } from "@mandaterail/storage";
import { GENESIS_PINS } from "../config.js";
import type { SignBackend } from "./backend.js";

export class SoftwareEd25519Backend implements SignBackend {
  readonly kind = "software-testnet-only" as const;
  private readonly sk: KeyObject;
  private readonly pk: Uint8Array;
  constructor(network: string, pkcs8Der?: Uint8Array) {
    if (network !== "testnet" || process.env.MR_SIGNER_SOFTWARE_KEY !== "TESTNET-ONLY") {
      throw new Error("SoftwareEd25519Backend is TESTNET-ONLY (network must be testnet and MR_SIGNER_SOFTWARE_KEY=TESTNET-ONLY)");
    }
    this.sk = pkcs8Der ? createPrivateKey({ key: Buffer.from(pkcs8Der), format: "der", type: "pkcs8" }) : generateKeyPairSync("ed25519").privateKey;
    this.pk = new Uint8Array(createPublicKey(this.sk).export({ format: "der", type: "spki" }).subarray(12));
  }
  async publicKey(): Promise<Uint8Array> { return this.pk; }
  /** R43-P2-3: refuses unless the message is a TestNet attestation or co-signature (network AND genesis pin), on every call. */
  async sign(msg: Uint8Array): Promise<Uint8Array> {
    let b: { network: string; genesisHash: string };
    try { b = decodeAttestation(msg); } catch {
      try { b = decodeCosign(msg); } catch {
        try { b = decodeResume(msg); } catch {
          try { b = decodeResumeCosign(msg); } catch { throw new Error("SoftwareEd25519Backend: not an attestation / co-signature / resume message"); } // v12 verifier, rev 21 resume
        }
      }
    }
    if (b.network !== "testnet" || b.genesisHash !== GENESIS_PINS.testnet) throw new Error("SoftwareEd25519Backend is TESTNET-ONLY: refusing a non-TestNet message");
    return new Uint8Array(sign(null, Buffer.from(msg), this.sk));
  }
}

