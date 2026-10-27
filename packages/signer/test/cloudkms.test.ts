/** CloudKmsBackend against a mock GCE metadata server + mock Cloud KMS (no GCP account touched). */
import { describe, expect, it } from "vitest";
import { generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";
import { encodeAttestation, isoSeconds, verifyAttestation } from "@mandaterail/storage";
import { CloudKmsBackend, crc32c } from "../src/piv/cloudkms.js";
import { GENESIS_PINS } from "../src/config.js";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const VER = "projects/mr-signer-prod/locations/us-central1/keyRings/mr/cryptoKeys/attest/cryptoKeyVersions/1";
const SA = "mr-signer@mr-signer-prod.iam.gserviceaccount.com";
const TOKEN = "ya29.SECRET-TOKEN-must-never-leak";
const att = (network: "testnet" | "mainnet") => encodeAttestation({ v: 1, network, genesisHash: GENESIS_PINS[network], keyId: "0".repeat(32), store: "s", spendId: "a", txId: "A".repeat(52), sender: "A".repeat(58),
  groupId: "", firstValid: 1, lastValid: 2, round: 20, nonce: randomBytes(32).toString("base64url"), expiry: isoSeconds(Date.now() + 60_000), observations: [] });

function gcp(o: { flavor?: string | null; email?: string; alg?: string; level?: string; otherKey?: boolean; badSig?: boolean; badCrc?: boolean; noVerified?: boolean; name?: string; dropPkLevel?: boolean; dropPkName?: boolean; dropSigLevel?: boolean } = {}) {
  const k = generateKeyPairSync("ed25519"), other = generateKeyPairSync("ed25519");
  const pubOf = (x: KeyObject) => new Uint8Array(x.export({ format: "der", type: "spki" }).subarray(12));
  const calls: { url: string; auth?: string; body?: Record<string, string> }[] = [];
  let tokens = 0;
  const res = (status: number, body: unknown, flavor: string | null = null) => ({ status, headers: { get: (n: string) => (n.toLowerCase() === "metadata-flavor" ? flavor : null) }, json: async () => body, text: async () => (typeof body === "string" ? body : JSON.stringify(body)) });
  const f = async (url: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}) => {
    calls.push({ url, auth: init.headers?.authorization, body: init.body ? JSON.parse(init.body) : undefined });
    const fl = o.flavor === undefined ? "Google" : o.flavor;
    if (url.startsWith("http://metadata.google.internal/")) {
      if (init.headers?.["Metadata-Flavor"] !== "Google") return res(403, "missing flavor", fl);
      if (url.endsWith("/email")) return res(200, o.email ?? SA, fl);
      if (url.endsWith("/token")) { tokens++; return res(200, { access_token: TOKEN, expires_in: 3599, token_type: "Bearer" }, fl); }
    }
    if (init.headers?.authorization !== `Bearer ${TOKEN}`) return res(401, {});
    if (url === `https://cloudkms.googleapis.com/v1/${VER}/publicKey`) {
      return res(200, { pem: (o.otherKey ? other.publicKey : k.publicKey).export({ format: "pem", type: "spki" }), algorithm: o.alg ?? "EC_SIGN_ED25519", protectionLevel: o.dropPkLevel ? undefined : o.level ?? "SOFTWARE", name: o.dropPkName ? undefined : VER });
    }
    if (url === `https://cloudkms.googleapis.com/v1/${VER}:asymmetricSign`) {
      const b = JSON.parse(init.body!) as { data: string; dataCrc32c: string };
      const data = Buffer.from(b.data, "base64");
      const verified = String(crc32c(data)) === b.dataCrc32c && !o.noVerified;
      const sig = sign(null, data, o.badSig ? other.privateKey : k.privateKey);
      return res(200, { signature: sig.toString("base64"), signatureCrc32c: String(o.badCrc ? 1 : crc32c(sig)), verifiedDataCrc32c: verified, name: o.name ?? VER, protectionLevel: o.dropSigLevel ? undefined : o.level ?? "SOFTWARE" });
    }
    return res(404, {});
  };
  return { f, pub: pubOf(k.publicKey), calls, tokens: () => tokens };
}
// R77-P3-2: the constructor enforces the MainNet active signer; these mock keys are made active through a test inventory (code-level paths)
const INV = (() => { const d = mkdtempSync(path.join(tmpdir(), "inv-")); const p = path.join(d, "kms-keys.json"); writeFileSync(p, JSON.stringify({ order: ["aliyun-softkey"], active: { cosigner: "aliyun-softkey", signer: "s1" }, s1: { role: "active", keyVersionName: VER } })); return p; })();
const keyOrderFiles = { inventoryPath: INV };
const opts = (pub: Uint8Array, network: "testnet" | "mainnet" = "mainnet") => ({ network, keyVersionName: VER, pubkey: pub, protectionLevel: "SOFTWARE" as const, serviceAccountEmail: SA, keyResource: VER, keyOrderFiles });

describe("CloudKmsBackend (mock metadata server + Cloud KMS)", () => {
  it("crc32c matches the Castagnoli check value", () => {
    expect(crc32c(new TextEncoder().encode("123456789"))).toBe(0xe3069283);
  });

  it("gets the attached-SA token from the metadata server, checks the pinned key version, signs raw data with dataCrc32c, verifies", async () => {
    const g = gcp();
    const be = new CloudKmsBackend(opts(g.pub), g.f as never);
    expect(be.kind).toBe("cloudkms");
    const m = att("mainnet");
    const s = await be.sign(m);
    expect(verifyAttestation(m, s, g.pub)).toBe(true);
    await be.sign(att("mainnet"));
    expect(g.tokens()).toBe(1); // cached
    const signCall = g.calls.find((c) => c.url.endsWith(":asymmetricSign"))!;
    expect(signCall.body).toEqual({ data: Buffer.from(m).toString("base64"), dataCrc32c: String(crc32c(m)) });
    expect(g.calls.filter((c) => c.url.includes("metadata")).every((c) => c.url.startsWith("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/"))).toBe(true);
  });

  it("refuses: other network, arbitrary bytes, unpinned version name, wrong key, wrong algorithm/level, wrong SA, fake metadata server", async () => {
    const g = gcp();
    const be = new CloudKmsBackend(opts(g.pub), g.f as never);
    await expect(be.sign(att("testnet"))).rejects.toThrow(/network/);
    await expect(be.sign(new Uint8Array([1, 2, 3]))).rejects.toThrow(/not an attestation/);
    expect(() => new CloudKmsBackend({ ...opts(g.pub), keyVersionName: VER.replace(/\/cryptoKeyVersions\/1$/, "") }, g.f as never)).toThrow(/pinned/);
    const cases: [Parameters<typeof gcp>[0], RegExp][] = [
      [{ otherKey: true }, /not the pinned public key/], [{ alg: "EC_SIGN_P256_SHA256" }, /not EC_SIGN_ED25519/], [{ level: "HSM" }, /protection level/],
      [{ email: "default-compute@developer.gserviceaccount.com" }, /not the pinned signer service account/], [{ flavor: null }, /Metadata-Flavor/],
    ];
    for (const [o, re] of cases) { const h = gcp(o); await expect(new CloudKmsBackend(opts(o?.otherKey ? h.pub : h.pub), h.f as never).sign(att("mainnet"))).rejects.toThrow(re); }
  });

  it("refuses a bad response: signature from another key, CRC mismatch, request CRC not verified, other version name", async () => {
    for (const [o, re] of [[{ badSig: true }, /does not verify/], [{ badCrc: true }, /CRC32C mismatch/], [{ noVerified: true }, /did not verify the request CRC32C/], [{ name: VER.replace(/1$/, "2") }, /another key version/], [{ dropPkLevel: true }, /protection level/], [{ dropPkName: true }, /another key version/], [{ dropSigLevel: true }, /protection level/]] as const) {
      const g = gcp(o);
      await expect(new CloudKmsBackend(opts(g.pub), g.f as never).sign(att("mainnet"))).rejects.toThrow(re);
    }
  });

  it("errors never contain the access token", async () => {
    const g = gcp({ badSig: true });
    const e = await new CloudKmsBackend(opts(g.pub), g.f as never).sign(att("mainnet")).catch((x: Error) => x);
    expect(String((e as Error).message)).not.toContain(TOKEN);
    const g2 = gcp();
    const bad = async (u: string, i: never) => { if (u.includes("cloudkms")) throw new Error(`boom ${TOKEN}`); return g2.f(u, i); };
    const e2 = await new CloudKmsBackend(opts(g2.pub), bad as never).sign(att("mainnet")).catch((x: Error) => x);
    expect(String((e2 as Error).message)).not.toContain(TOKEN);
  });
});

describe("cloudKmsFromConfig", () => {
  it("R77-P3-2: the constructor refuses a MainNet key that is not the active signer (gcp); role must be active; SA + metadata pins", async () => {
    const { cloudKmsFromConfig } = await import("../src/piv/cloudkms.js");
    const { readFileSync } = await import("node:fs");
    const base = { network: "mainnet" as const, keyVersionName: VER, pubkeyB64: Buffer.alloc(32, 1).toString("base64"), protectionLevel: "SOFTWARE" as const };
    expect(() => cloudKmsFromConfig({ ...base, serviceAccountEmail: SA })).toThrow(/not the active signer key gcp/);
    expect(() => new CloudKmsBackend({ network: "mainnet", keyVersionName: VER, pubkey: new Uint8Array(32).fill(1), protectionLevel: "SOFTWARE", serviceAccountEmail: SA })).toThrow(/not the active signer key gcp/);
    const ck = JSON.parse(readFileSync(path.join(__dirname, "../../../deploy/gcp/cloudkms.mainnet.json"), "utf8"));
    expect(ck.role).toBe("active");
    expect(cloudKmsFromConfig(ck).kind).toBe("cloudkms");
    expect(() => cloudKmsFromConfig({ ...ck, role: "backup" })).toThrow(/role backup/);
    expect(() => cloudKmsFromConfig({ ...ck, serviceAccountEmail: undefined })).toThrow(/serviceAccountEmail/);
    expect(() => cloudKmsFromConfig({ ...ck, metadataBase: "http://evil.example" })).toThrow(/metadata server/);
    expect(() => cloudKmsFromConfig({ ...ck, pubkeyB64: Buffer.alloc(32, 2).toString("base64") })).toThrow(/not the active signer key gcp/);
  });
});
