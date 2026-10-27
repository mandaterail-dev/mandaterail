import algosdk from "algosdk";
import {
  canonicalMandateBytes,
  signMandate,
  stableStringify,
} from "@mandaterail/core";
import type {
  Ac2SignResult,
  Ac2Signer,
  UnsignedIntentMandate,
} from "./types.js";

/**
 * Headless ed25519 signer using a local Algorand secret key.
 * This is the Phase-1 path (no phone / OpenClaw required).
 */
export class LocalEd25519Signer implements Ac2Signer {
  readonly address: string;
  readonly publicKeyB64: string;
  private readonly secretKey: Uint8Array;

  constructor(secretKey: Uint8Array) {
    if (secretKey.length !== 64) {
      throw new Error(
        `LocalEd25519Signer expects 64-byte Algorand secretKey (got ${secretKey.length})`,
      );
    }
    this.secretKey = secretKey;
    const pk = secretKey.slice(32);
    this.publicKeyB64 = Buffer.from(pk).toString("base64");
    this.address = algosdk.encodeAddress(pk);
  }

  static fromMnemonic(mnemonic: string): LocalEd25519Signer {
    const account = algosdk.mnemonicToSecretKey(mnemonic.trim());
    return new LocalEd25519Signer(account.sk);
  }

  static fromAccount(account: algosdk.Account): LocalEd25519Signer {
    return new LocalEd25519Signer(account.sk);
  }

  async signIntentMandate(
    unsigned: UnsignedIntentMandate,
  ): Promise<Ac2SignResult> {
    // Touch canonical bytes so callers can rely on the same encoding as verify.
    void canonicalMandateBytes(unsigned);
    void stableStringify(unsigned);
    const signature = signMandate(unsigned, this.secretKey);
    return {
      signature,
      publicKey: this.publicKeyB64,
      address: this.address,
    };
  }
}
