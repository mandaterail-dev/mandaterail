/** YubiKey PKCS#11 backend against a mock ykcs11 token (no hardware on the box). */
import { describe, expect, it } from "vitest";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";
import { encodeAttestation, isoSeconds, verifyAttestation } from "@mandaterail/storage";
import { CKA_CLASS, CKA_EC_POINT, CKA_ID, CKA_KEY_TYPE, CKK_EC_EDWARDS, CKM_EDDSA, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, YubikeyPkcs11Backend, type Attr, type Pkcs11Api } from "../src/piv/ykcs11.js";
import { GENESIS_PINS } from "../src/config.js";

function token(o: { serial?: string; pin?: string; keyType?: number; locked?: boolean; removed?: () => boolean } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = new Uint8Array(publicKey.export({ format: "der", type: "spki" }).subarray(12));
  const log: string[] = [];
  let loggedIn = false, findTpl: Attr[] = [], signKey: KeyObject | null = null, pinAttempts = 0;
  const objs = [
    { h: Buffer.from([1]), cls: CKO_PUBLIC_KEY, id: 2 },
    { h: Buffer.from([2]), cls: CKO_PRIVATE_KEY, id: 2 },
    { h: Buffer.from([3]), cls: CKO_PUBLIC_KEY, id: 1 },
  ];
  const api: Pkcs11Api = {
    load: (m) => { log.push(`load ${m}`); },
    C_Initialize: () => log.push("init") as never, C_Finalize: () => log.push("fin") as never,
    C_GetSlotList: () => [Buffer.from([0])],
    C_GetTokenInfo: () => ({ serialNumber: (o.serial ?? "12345678").padStart(16, " "), label: "YubiKey PIV #12345678" }),
    C_OpenSession: () => Buffer.from([9]), C_CloseSession: () => log.push("close") as never,
    C_Login: (_s, _u, pin) => { pinAttempts++; log.push("login"); if (o.locked) throw new Error("CKR_PIN_LOCKED"); if (pin !== (o.pin ?? "123456")) throw new Error("CKR_PIN_INCORRECT"); loggedIn = true; },
    C_FindObjectsInit: (_s, t) => { findTpl = t; },
    C_FindObjects: () => objs.filter((x) => x.cls === findTpl.find((a) => a.type === CKA_CLASS)!.value && (findTpl.find((a) => a.type === CKA_ID)!.value as Buffer)[0] === x.id && (x.cls === CKO_PUBLIC_KEY || loggedIn)).map((x) => x.h),
    C_FindObjectsFinal: () => {},
    C_GetAttributeValue: (_s, _o, t) => t.map((a) => a.type === CKA_KEY_TYPE ? { type: a.type, value: Buffer.from([o.keyType ?? CKK_EC_EDWARDS, 0, 0, 0, 0, 0, 0, 0]) }
      : a.type === CKA_EC_POINT ? { type: a.type, value: Buffer.concat([Buffer.from([4, 32]), Buffer.from(pub)]) } : a),
    C_SignInit: (_s, mech) => { if (!loggedIn) throw new Error("CKR_USER_NOT_LOGGED_IN"); if (mech.mechanism !== CKM_EDDSA) throw new Error("CKR_MECHANISM_INVALID"); signKey = privateKey; },
    C_Sign: (_s, data) => { if (o.removed?.()) throw new Error("CKR_DEVICE_REMOVED"); log.push("sign"); return sign(null, data, signKey!); },
  };
  return { api, pub, log, pinAttempts: () => pinAttempts };
}
function creds(pin = "123456\n", mode = 0o600) {
  const d = mkdtempSync(path.join(tmpdir(), "creds-"));
  writeFileSync(path.join(d, "piv-pin"), pin); chmodSync(path.join(d, "piv-pin"), mode);
  return d;
}
const opts = (pub: Uint8Array, dir: string, network: "testnet" | "mainnet" = "mainnet") => ({ network, pkcs11Module: "/usr/lib/x86_64-linux-gnu/libykcs11.so", tokenSerial: "12345678", slot: "9c" as const, pinCredential: "piv-pin", pubkey: pub, credentialsDir: dir, keyResource: "piv:12345678:9c" });
const att = (network: "testnet" | "mainnet") => encodeAttestation({ v: 1, network, genesisHash: GENESIS_PINS[network], keyId: "0".repeat(32), store: "s", spendId: "a", txId: "A".repeat(52), sender: "A".repeat(58),
  groupId: "", firstValid: 1, lastValid: 2, round: 20, nonce: randomBytes(32).toString("base64url"), expiry: isoSeconds(Date.now() + 60_000), observations: [] });

describe("YubikeyPkcs11Backend (mock ykcs11 token)", () => {
  it("pins serial + slot 9c key, logs in once with the credential PIN, signs with CKM_EDDSA, self-verifies", async () => {
    const t = token();
    const be = new YubikeyPkcs11Backend(opts(t.pub, creds()), t.api);
    const m = att("mainnet");
    const s1 = await be.sign(m);
    expect(verifyAttestation(m, s1, t.pub)).toBe(true);
    await be.sign(att("mainnet"));
    expect(t.log.filter((x) => x === "login").length).toBe(1); // PIN policy ONCE
    expect(t.log.filter((x) => x === "sign").length).toBe(2);
    be.close();
  });

  it("refuses: other network message, arbitrary bytes, wrong serial, replaced card key, non-Ed25519 slot, group/other-readable PIN file", async () => {
    const t = token();
    const be = new YubikeyPkcs11Backend(opts(t.pub, creds()), t.api);
    await expect(be.sign(att("testnet"))).rejects.toThrow(/network \/ genesis/);
    await expect(be.sign(Buffer.from("hello"))).rejects.toThrow(/not an attestation/);
    expect(t.log).not.toContain("login");
    await expect(new YubikeyPkcs11Backend({ ...opts(t.pub, creds()), tokenSerial: "87654321", keyResource: "piv:87654321:9c" }, t.api).sign(att("mainnet"))).rejects.toThrow(/not present/);
    await expect(new YubikeyPkcs11Backend(opts(new Uint8Array(32).fill(7), creds()), t.api).sign(att("mainnet"))).rejects.toThrow(/not the pinned public key/);
    const t2 = token({ keyType: 3 });
    await expect(new YubikeyPkcs11Backend(opts(t2.pub, creds()), t2.api).sign(att("mainnet"))).rejects.toThrow(/not Ed25519/);
    await expect(new YubikeyPkcs11Backend(opts(t.pub, creds("123456", 0o640)), t.api).sign(att("mainnet"))).rejects.toThrow(/readable by group/);
    await expect(new YubikeyPkcs11Backend(opts(t.pub, creds("12")), t.api).sign(att("mainnet"))).rejects.toThrow(/PIN credential length/);
  });

  it("a wrong or locked PIN is tried exactly once, never retried; the PIN never appears in the error", async () => {
    const t = token({ pin: "654321" });
    const be = new YubikeyPkcs11Backend(opts(t.pub, creds("123456")), t.api);
    const e = await be.sign(att("mainnet")).catch((x: Error) => x);
    expect((e as Error).message).toMatch(/PIN refused\); not retrying/);
    expect((e as Error).message).not.toContain("123456");
    await expect(be.sign(att("mainnet"))).rejects.toThrow(/not retrying/);
    expect(t.pinAttempts()).toBe(1);
    const tl = token({ locked: true });
    await expect(new YubikeyPkcs11Backend(opts(tl.pub, creds()), tl.api).sign(att("mainnet"))).rejects.toThrow(/PIN locked/);
  });

  it("R46-P3: a failed open finalizes the module (the next open can C_Initialize again)", async () => {
    const t = token();
    const be = new YubikeyPkcs11Backend({ ...opts(t.pub, creds()), tokenSerial: "87654321", keyResource: "piv:87654321:9c" }, t.api);
    await expect(be.sign(att("mainnet"))).rejects.toThrow(/not present/);
    expect(t.log.filter((x) => x === "init" || x === "fin")).toEqual(["init", "fin"]);
  });

  it("R46-P3: card removed mid-sign -> that request fails, the session is dropped, the next request re-opens and signs", async () => {
    let gone = false;
    const t = token({ removed: () => gone });
    const be = new YubikeyPkcs11Backend(opts(t.pub, creds()), t.api);
    await be.sign(att("mainnet"));
    gone = true;
    await expect(be.sign(att("mainnet"))).rejects.toThrow(/DEVICE_REMOVED/);
    gone = false;
    const m = att("mainnet");
    expect(verifyAttestation(m, await be.sign(m), t.pub)).toBe(true);
    expect(t.log.filter((x) => x === "login").length).toBe(2);
  });
});
