/** AwsKmsBackend against a mock IMDSv2 + mock AWS KMS (JSON 1.1, SigV4 checked). No AWS account touched. */
import { describe, expect, it } from "vitest";
import { createHmac, createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { encodeAttestation, isoSeconds, verifyAttestation } from "@mandaterail/storage";
import { AwsKmsBackend, awsKmsFromConfig } from "../src/piv/awskms.js";
import { GENESIS_PINS } from "../src/config.js";

const ARN = "arn:aws:kms:eu-central-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab";
const ROLE = "mr-verifier";
const SECRET = "SECRETACCESSKEY-must-never-leak", STOKEN = "SESSIONTOKEN-must-never-leak";
const att = (network: "testnet" | "mainnet") => encodeAttestation({ v: 1, network, genesisHash: GENESIS_PINS[network], keyId: "0".repeat(32), store: "s", spendId: "a", txId: "A".repeat(52), sender: "A".repeat(58),
  groupId: "", firstValid: 1, lastValid: 2, round: 20, nonce: randomBytes(32).toString("base64url"), expiry: isoSeconds(Date.now() + 60_000), observations: [] });

function aws(o: { roles?: string; spec?: string; usage?: string; otherKey?: boolean; badSig?: boolean; keyId?: string; alg?: string; imdsV1Only?: boolean } = {}) {
  const k = generateKeyPairSync("ed25519"), other = generateKeyPairSync("ed25519");
  const pub = new Uint8Array(k.publicKey.export({ format: "der", type: "spki" }).subarray(12));
  const log: string[] = [];
  let credFetches = 0;
  const res = (status: number, body: unknown) => ({ status, json: async () => body, text: async () => (typeof body === "string" ? body : JSON.stringify(body)) });
  const f = async (url: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}) => {
    const h = init.headers ?? {};
    if (url.startsWith("http://169.254.169.254/")) {
      if (url.endsWith("/latest/api/token")) { if (init.method !== "PUT" || !h["X-aws-ec2-metadata-token-ttl-seconds"] || o.imdsV1Only) return res(403, ""); return res(200, "IMDSTOKEN"); }
      if (h["X-aws-ec2-metadata-token"] !== "IMDSTOKEN") return res(401, "");
      if (url.endsWith("/security-credentials/")) return res(200, o.roles ?? ROLE);
      if (url.endsWith(`/security-credentials/${ROLE}`)) { credFetches++; return res(200, { Code: "Success", AccessKeyId: "ASIAEXAMPLE", SecretAccessKey: SECRET, Token: STOKEN, Expiration: new Date(Date.now() + 3600_000).toISOString() }); }
      return res(404, "");
    }
    if (url !== "https://kms.eu-central-1.amazonaws.com/") return res(404, "");
    // SigV4 check (service kms, region, session token signed)
    const auth = h.authorization ?? "";
    const m = /^AWS4-HMAC-SHA256 Credential=ASIAEXAMPLE\/(\d{8})\/eu-central-1\/kms\/aws4_request, SignedHeaders=([^,]+), Signature=([0-9a-f]{64})$/.exec(auth);
    if (!m || !m[2]!.split(";").includes("x-amz-security-token") || !m[2]!.split(";").includes("x-amz-target") || h["x-amz-security-token"] !== STOKEN) return res(403, { __type: "InvalidSignatureException" });
    const names = m[2]!.split(";");
    const canonical = ["POST", "/", "", names.map((n) => `${n}:${String(h[n]).trim()}\n`).join(""), m[2], createHash("sha256").update(init.body!).digest("hex")].join("\n");
    const toSign = ["AWS4-HMAC-SHA256", h["x-amz-date"], `${m[1]}/eu-central-1/kms/aws4_request`, createHash("sha256").update(canonical).digest("hex")].join("\n");
    const hm = (key: string | Buffer, d: string) => createHmac("sha256", key).update(d).digest();
    const want = createHmac("sha256", hm(hm(hm(hm("AWS4" + SECRET, m[1]!), "eu-central-1"), "kms"), "aws4_request")).update(toSign).digest("hex");
    if (want !== m[3]) return res(403, { __type: "InvalidSignatureException" });
    const b = JSON.parse(init.body!);
    log.push(h["x-amz-target"]!);
    if (h["x-amz-target"] === "TrentService.GetPublicKey") {
      return res(200, { KeyId: o.keyId ?? ARN, KeySpec: o.spec ?? "ECC_NIST_EDWARDS25519", KeyUsage: o.usage ?? "SIGN_VERIFY", SigningAlgorithms: ["ED25519_SHA_512", "ED25519_PH_SHA_512"],
        PublicKey: (o.otherKey ? other.publicKey : k.publicKey).export({ format: "der", type: "spki" }).toString("base64") });
    }
    if (h["x-amz-target"] === "TrentService.Sign") {
      if (b.MessageType !== "RAW" || b.SigningAlgorithm !== "ED25519_SHA_512" || b.KeyId !== ARN) return res(400, { __type: "ValidationException" });
      return res(200, { KeyId: o.keyId ?? ARN, SigningAlgorithm: o.alg ?? "ED25519_SHA_512", Signature: sign(null, Buffer.from(b.Message, "base64"), o.badSig ? other.privateKey : k.privateKey).toString("base64") });
    }
    return res(400, { __type: "UnknownOperationException" });
  };
  return { f, pub, log, credFetches: () => credFetches };
}
const opts = (pub: Uint8Array) => ({ network: "testnet" as const, region: "eu-central-1", keyArn: ARN, pubkey: pub, roleName: ROLE, keyResource: ARN });

describe("AwsKmsBackend (mock IMDSv2 + AWS KMS)", () => {
  it("IMDSv2 role credentials, SigV4 (kms), GetPublicKey pin check, Sign RAW ED25519_SHA_512, verified against the pin", async () => {
    const a = aws();
    const be = new AwsKmsBackend(opts(a.pub), a.f as never);
    expect(be.kind).toBe("awskms");
    const m = att("testnet");
    expect(verifyAttestation(m, await be.sign(m), a.pub)).toBe(true);
    await be.sign(att("testnet"));
    expect(a.log).toEqual(["TrentService.GetPublicKey", "TrentService.Sign", "TrentService.Sign"]);
    expect(a.credFetches()).toBe(1);
  });
  it("refuses: alias / region mismatch, other network, IMDSv1-only, wrong role, wrong spec/usage/key, other KeyId or algorithm, bad signature", async () => {
    const a = aws();
    expect(() => new AwsKmsBackend({ ...opts(a.pub), keyArn: "alias/mr" }, a.f as never)).toThrow(/ARN/);
    expect(() => new AwsKmsBackend({ ...opts(a.pub), region: "us-east-1" }, a.f as never)).toThrow(/region/);
    await expect(new AwsKmsBackend(opts(a.pub), a.f as never).sign(att("mainnet"))).rejects.toThrow(/network/);
    const cases: [Parameters<typeof aws>[0], RegExp][] = [
      [{ imdsV1Only: true }, /IMDSv2 token status 403/], [{ roles: "admin-role" }, /pinned verifier role/], [{ spec: "ECC_NIST_P256" }, /not ECC_NIST_EDWARDS25519/],
      [{ usage: "ENCRYPT_DECRYPT" }, /SIGN_VERIFY/], [{ otherKey: true }, /not the pinned public key/], [{ keyId: ARN.replace(/ab$/, "cd") }, /another key/],
      [{ alg: "ED25519_PH_SHA_512" }, /another algorithm/], [{ badSig: true }, /does not verify/],
    ];
    for (const [o, re] of cases) { const x = aws(o); await expect(new AwsKmsBackend(opts(x.pub), x.f as never).sign(att("testnet"))).rejects.toThrow(re); }
  });
  it("errors never contain the secret key or session token", async () => {
    const a = aws({ badSig: true });
    const e = (await new AwsKmsBackend(opts(a.pub), a.f as never).sign(att("testnet")).catch((x: Error) => x)) as Error;
    for (const s of [SECRET, STOKEN]) expect(e.message).not.toContain(s);
    const b = aws();
    const boom = async (u: string, i: never) => { if (u.includes("kms.")) throw new Error(`net ${SECRET} ${STOKEN}`); return b.f(u, i); };
    const e2 = (await new AwsKmsBackend(opts(b.pub), boom as never).sign(att("testnet")).catch((x: Error) => x)) as Error;
    for (const s of [SECRET, STOKEN]) expect(e2.message).not.toContain(s);
  });
  it("awsKmsFromConfig", () => {
    expect(awsKmsFromConfig({ network: "testnet", region: "eu-central-1", keyArn: ARN, pubkeyB64: Buffer.alloc(32, 1).toString("base64"), roleName: ROLE }).kind).toBe("awskms");
  });
  it("R77-P3-4: refused on MainNet in the constructor (and via awsKmsFromConfig); Roles Anywhere is gone", () => {
    const a = aws();
    expect(() => new AwsKmsBackend({ ...opts(a.pub), network: "mainnet" }, a.f as never)).toThrow(/awskms is refused on mainnet/);
    expect(() => awsKmsFromConfig({ network: "mainnet", region: "eu-central-1", keyArn: ARN, pubkeyB64: Buffer.alloc(32, 1).toString("base64"), roleName: ROLE })).toThrow(/refused on mainnet/);
    expect(() => new AwsKmsBackend({ ...opts(a.pub), network: "betanet" as never }, a.f as never)).toThrow(/refused on betanet/);
  });
});
