/**
 * YubiKey PIV backend through PKCS#11 (Yubico ykcs11), R45-GATE-1. PIV slot 9c, Ed25519 (YubiKey 5.7+).
 *
 * - The PKCS#11 binding is injected (`Pkcs11Api`, the pkcs11js surface we use) so this file has no native
 *   dependency and is fully testable without hardware (test/ykcs11.test.ts uses a mock token). In the image,
 *   `loadPkcs11js()` loads the `pkcs11js` addon and the ykcs11 module (/usr/lib/x86_64-linux-gnu/libykcs11.so).
 * - Token pinned by serial; key pinned by CKA_ID (ykcs11: 9a=1, 9c=2, 9d=3, 9e=4), key type CKK_EC_EDWARDS, and the
 *   public key read from the token must equal the pinned pubkey (else refuse: wrong / replaced card).
 * - PIN: read once from the systemd credential file ($CREDENTIALS_DIRECTORY/<name>, LoadCredentialEncrypted=, TPM
 *   sealed), never from argv/env, never logged; the buffer is zeroed after C_Login. PIN policy ONCE: one login per
 *   session; touch policy NEVER (the automated signer).
 * - Every sign() checks the message is an attestation / co-signature of the configured network, and verifies the
 *   card's signature against the pinned pubkey before returning it.
 * - A PIN error (CKR_PIN_INCORRECT / CKR_PIN_LOCKED) is never retried automatically (3 tries lock the PIV PIN).
 */
import { assertKeyResource } from "./backend.js";
import { readFileSync, statSync } from "node:fs";
import path from "node:path";
import { decodeAttestation, decodeCosign, verifyAttestation, GENESIS_PIN_ANY } from "./ykcs11-deps.js";
import type { SignBackend } from "./backend.js";

export const CKU_USER = 1;
export const CKF_SERIAL_SESSION = 0x4;
export const CKA_CLASS = 0x0, CKA_KEY_TYPE = 0x100, CKA_ID = 0x102, CKA_EC_POINT = 0x181;
export const CKO_PUBLIC_KEY = 2, CKO_PRIVATE_KEY = 3, CKK_EC_EDWARDS = 0x40, CKM_EDDSA = 0x1057;
export const PIV_SLOT_CKA_ID: Record<"9a" | "9c" | "9d" | "9e", number> = { "9a": 1, "9c": 2, "9d": 3, "9e": 4 };

export interface Attr { type: number; value?: Buffer | number | boolean }
/** The subset of pkcs11js we call. */
export interface Pkcs11Api {
  load(modulePath: string): void;
  C_Initialize(): void;
  C_Finalize(): void;
  C_GetSlotList(tokenPresent: boolean): Buffer[];
  C_GetTokenInfo(slot: Buffer): { serialNumber: string; label: string };
  C_OpenSession(slot: Buffer, flags: number): Buffer;
  C_CloseSession(session: Buffer): void;
  C_Login(session: Buffer, userType: number, pin: string): void;
  C_FindObjectsInit(session: Buffer, template: Attr[]): void;
  C_FindObjects(session: Buffer, max: number): Buffer[];
  C_FindObjectsFinal(session: Buffer): void;
  C_GetAttributeValue(session: Buffer, obj: Buffer, template: Attr[]): Attr[];
  C_SignInit(session: Buffer, mech: { mechanism: number }, key: Buffer): void;
  C_Sign(session: Buffer, data: Buffer, out: Buffer): Buffer;
}
export interface YkcsOptions {
  network: "testnet" | "mainnet";
  pkcs11Module: string; // absolute path to libykcs11.so
  tokenSerial: string; // pinned YubiKey serial
  /** R50-P3: the key_resource pinned in the DB (v12); open() refuses unless it names this backend's key. Required on MainNet. */
  keyResource?: string;
  slot: "9c";
  pinCredential: string; // credential name, read from $CREDENTIALS_DIRECTORY
  pubkey: Uint8Array; // pinned Ed25519 public key (32 bytes)
  credentialsDir?: string; // default process.env.CREDENTIALS_DIRECTORY
}
export class YkcsError extends Error {}

/** CK_ULONG as pkcs11js returns it: an 8-byte (64-bit) or 4-byte little-endian buffer, or a number. */
export function ckUlong(v: Attr["value"]): number {
  if (typeof v === "number") return v;
  if (!Buffer.isBuffer(v)) return NaN;
  if (v.length === 8) return Number(v.readBigUInt64LE(0));
  if (v.length === 4) return v.readUInt32LE(0);
  return NaN;
}

/** DER OCTET STRING (04 20 <32>) or raw 32 bytes, as ykcs11 returns CKA_EC_POINT for Ed25519. */
export function ecPointToRaw(b: Buffer): Uint8Array {
  if (b.length === 34 && b[0] === 0x04 && b[1] === 0x20) return new Uint8Array(b.subarray(2));
  if (b.length === 32) return new Uint8Array(b);
  throw new YkcsError("unexpected CKA_EC_POINT encoding");
}

export class YubikeyPkcs11Backend implements SignBackend {
  readonly kind = "yubikey-piv" as const;
  private session: Buffer | null = null;
  private key: Buffer | null = null;
  private pinFailed = false;
  constructor(private readonly o: YkcsOptions, private readonly p: Pkcs11Api) {
    if (o.pubkey.length !== 32) throw new YkcsError("pinned pubkey must be 32 bytes");
    if (!path.isAbsolute(o.pkcs11Module)) throw new YkcsError("pkcs11Module must be an absolute path");
    if (!/^[0-9]{6,12}$/.test(o.tokenSerial)) throw new YkcsError("tokenSerial must be the YubiKey's decimal serial");
    if (!/^[a-z0-9-]{1,64}$/.test(o.pinCredential)) throw new YkcsError("pinCredential name");
  }

  private readPin(): Buffer {
    const dir = this.o.credentialsDir ?? process.env.CREDENTIALS_DIRECTORY;
    if (!dir) throw new YkcsError("no CREDENTIALS_DIRECTORY (LoadCredentialEncrypted= missing)");
    const f = path.join(dir, this.o.pinCredential);
    const st = statSync(f);
    if ((st.mode & 0o077) !== 0) throw new YkcsError("PIN credential is readable by group/other");
    const pin = readFileSync(f);
    let end = pin.length;
    while (end > 0 && (pin[end - 1] === 0x0a || pin[end - 1] === 0x0d)) end--;
    if (end < 6 || end > 8) { pin.fill(0); throw new YkcsError("PIN credential length (PIV PIN is 6-8 characters)"); }
    return pin.subarray(0, end);
  }

  private find(s: Buffer, template: Attr[]): Buffer[] {
    this.p.C_FindObjectsInit(s, template);
    try { return this.p.C_FindObjects(s, 4); } finally { this.p.C_FindObjectsFinal(s); }
  }

  /** Opens the pinned token, checks the pinned key, logs in once. Idempotent. */
  async open(): Promise<void> {
    if (this.session) return;
    assertKeyResource(this.o.network, this.o.keyResource, `piv:${this.o.tokenSerial.replace(/^0+/, "")}:${this.o.slot}`);
    if (this.pinFailed) throw new YkcsError("a previous PIN attempt failed; not retrying (3 tries lock the PIV PIN)");
    this.p.load(this.o.pkcs11Module);
    this.p.C_Initialize();
    try { await this.openInitialized(); } catch (e) {
      // R46-P3: never leave the module initialized after a failed open (next C_Initialize would fail)
      try { this.p.C_Finalize(); } catch { /* */ }
      throw e;
    }
  }

  private async openInitialized(): Promise<void> {
    const slot = this.p.C_GetSlotList(true).find((sl) => this.p.C_GetTokenInfo(sl).serialNumber.trim().replace(/^0+/, "") === this.o.tokenSerial.replace(/^0+/, ""));
    if (!slot) throw new YkcsError("pinned YubiKey (by serial) is not present");
    const s = this.p.C_OpenSession(slot, CKF_SERIAL_SESSION);
    try {
      const id = Buffer.from([PIV_SLOT_CKA_ID[this.o.slot]]);
      const pubs = this.find(s, [{ type: CKA_CLASS, value: CKO_PUBLIC_KEY }, { type: CKA_ID, value: id }]);
      if (pubs.length !== 1) throw new YkcsError(`expected one public key in slot ${this.o.slot}, found ${pubs.length}`);
      const [kt, pt] = this.p.C_GetAttributeValue(s, pubs[0]!, [{ type: CKA_KEY_TYPE }, { type: CKA_EC_POINT }]);
      const ktv = ckUlong(kt?.value);
      if (ktv !== CKK_EC_EDWARDS) throw new YkcsError("slot key is not Ed25519");
      const raw = ecPointToRaw(pt!.value as Buffer);
      if (!Buffer.from(raw).equals(Buffer.from(this.o.pubkey))) throw new YkcsError("the card's slot key is not the pinned public key");
      const pin = this.readPin();
      try {
        // the Buffer is zeroed below; pkcs11js takes a JS string, and that copy cannot be zeroed (GC-managed)
        this.p.C_Login(s, CKU_USER, pin.toString("latin1"));
      } catch (e) {
        this.pinFailed = true;
        throw new YkcsError(`C_Login failed (${/PIN_LOCKED/.test(String((e as Error).message)) ? "PIN locked" : "PIN refused"}); not retrying`);
      } finally {
        pin.fill(0);
      }
      const privs = this.find(s, [{ type: CKA_CLASS, value: CKO_PRIVATE_KEY }, { type: CKA_ID, value: id }]);
      if (privs.length !== 1) throw new YkcsError(`expected one private key in slot ${this.o.slot}, found ${privs.length}`);
      this.session = s;
      this.key = privs[0]!;
    } catch (e) {
      try { this.p.C_CloseSession(s); } catch { /* */ }
      throw e;
    }
  }

  async publicKey(): Promise<Uint8Array> { return this.o.pubkey; }

  async sign(msg: Uint8Array): Promise<Uint8Array> {
    let b: { network: string; genesisHash: string };
    try { b = decodeAttestation(msg); } catch {
      try { b = decodeCosign(msg); } catch { throw new YkcsError("refusing to sign: not an attestation / co-signature message"); }
    }
    if (b.network !== this.o.network || b.genesisHash !== GENESIS_PIN_ANY[this.o.network]) throw new YkcsError("refusing to sign: message network / genesis is not this backend's");
    await this.open();
    let sig: Uint8Array;
    try {
      this.p.C_SignInit(this.session!, { mechanism: CKM_EDDSA }, this.key!);
      sig = new Uint8Array(this.p.C_Sign(this.session!, Buffer.from(msg), Buffer.alloc(64)));
    } catch (e) {
      // R46-P3 / R47-P3: ANY sign failure drops the session (a failed C_Sign can leave the operation active ->
      // OPERATION_ACTIVE on the next C_SignInit); the NEXT request re-opens and logs in again. This one fails.
      this.close();
      throw new YkcsError(`card sign failed: ${(e as Error).message}`);
    }
    if (sig.length !== 64 || !verifyAttestation(msg, sig, this.o.pubkey)) throw new YkcsError("card signature does not verify against the pinned key");
    return sig;
  }

  close(): void {
    if (this.session) { try { this.p.C_CloseSession(this.session); } catch { /* */ } this.session = null; this.key = null; }
    try { this.p.C_Finalize(); } catch { /* */ }
  }
}

/** Loads the pkcs11js native addon (installed only in the signer image). */
export async function loadPkcs11js(): Promise<Pkcs11Api> {
  const name = "pkcs11js";
  const m = (await import(name)) as { PKCS11: new () => Pkcs11Api };
  return new m.PKCS11();
}
