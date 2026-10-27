import { createHash, createPrivateKey, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import algosdk from "algosdk";
import {
  RollingWindowRateLimiter,
  OperatorChallengeStore,
  SignedChallengeOperatorVerifier,
  arc60SignedBytes,
  encodeAttestationHeader,
} from "./operator-challenge.js";

const op = algosdk.generateAccount();
const OP = op.addr.toString();
const DOMAIN = "mandaterail.pages.dev";

function arc60(
  store: OperatorChallengeStore,
  opts: { siwaDomain?: string; rpId?: string },
) {
  const ch = store.issue("approve", "p-1");
  const siwa: Record<string, string> = {
    account_address: OP, statement: ch.message, nonce: ch.nonce,
    version: "1", chain_id: "283", type: "ed25519",
  };
  if (opts.siwaDomain !== undefined) siwa.domain = opts.siwaDomain;
  const data = new TextEncoder().encode(JSON.stringify(siwa));
  const authData = new Uint8Array([
    ...createHash("sha256").update(opts.rpId ?? "").digest(), 1, 0, 0, 0, 0,
  ]);
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(op.sk.slice(0, 32)),
  ]);
  const key = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const sig = sign(null, arc60SignedBytes(data, authData), key);
  return encodeAttestationHeader({
    nonce: ch.nonce, address: OP, format: "arc60",
    signature: sig.toString("base64"),
    data: Buffer.from(data).toString("base64"),
    authenticatorData: Buffer.from(authData).toString("base64"),
  });
}

const verify = (v: SignedChallengeOperatorVerifier, evidence: string) =>
  v.verify({ kind: "signed-challenge", evidence }, { action: "approve", subjectId: "p-1" });

describe("P1-A ARC-60 domain enforcement when OPERATOR_SIGNDATA_DOMAIN is set", () => {
  it("accepts matching siwa.domain + rpIdHash", async () => {
    const store = new OperatorChallengeStore();
    const v = new SignedChallengeOperatorVerifier(store, [OP], { domain: DOMAIN });
    expect((await verify(v, arc60(store, { siwaDomain: DOMAIN, rpId: DOMAIN }))).ok).toBe(true);
  });
  it("rejects phishing-origin siwa.domain", async () => {
    const store = new OperatorChallengeStore();
    const v = new SignedChallengeOperatorVerifier(store, [OP], { domain: DOMAIN });
    const r = await verify(v, arc60(store, { siwaDomain: "evil.example", rpId: "evil.example" }));
    expect(r.ok).toBe(false);
  });
  it("rejects missing siwa.domain", async () => {
    const store = new OperatorChallengeStore();
    const v = new SignedChallengeOperatorVerifier(store, [OP], { domain: DOMAIN });
    expect((await verify(v, arc60(store, { rpId: DOMAIN }))).ok).toBe(false);
  });
  it("rejects matching siwa.domain with wrong rpIdHash", async () => {
    const store = new OperatorChallengeStore();
    const v = new SignedChallengeOperatorVerifier(store, [OP], { domain: DOMAIN });
    const r = await verify(v, arc60(store, { siwaDomain: DOMAIN, rpId: "evil.example" }));
    expect(r.ok).toBe(false);
  });
});

describe("OA-P2-G RollingWindowRateLimiter", () => {
  it("caps per key over a rolling window", () => {
    const now = { t: 0 };
    const l = new RollingWindowRateLimiter({ windowMs: 1000, perKey: 2, global: 100, now: () => now.t });
    expect(l.take("a")).toBe(true);
    expect(l.take("a")).toBe(true);
    expect(l.take("a")).toBe(false);
    expect(l.take("b")).toBe(true);
    now.t = 1000;
    expect(l.take("a")).toBe(true);
  });
  it("does not allow 2x across a window boundary", () => {
    const now = { t: 0 };
    const l = new RollingWindowRateLimiter({ windowMs: 1000, perKey: 5, global: 100, now: () => now.t });
    now.t = 999;
    for (let i = 0; i < 5; i++) expect(l.take("a")).toBe(true);
    now.t = 1001; // a fixed window would have reset here
    expect(l.take("a")).toBe(false);
    now.t = 2000;
    expect(l.take("a")).toBe(true);
  });
  it("enforces a rolling global cap across keys", () => {
    const now = { t: 0 };
    const l = new RollingWindowRateLimiter({ windowMs: 1000, perKey: 10, global: 3, now: () => now.t });
    expect(["a", "b", "c", "d"].map((k) => l.take(k))).toEqual([true, true, true, false]);
    now.t = 500;
    expect(l.take("e")).toBe(false);
    now.t = 1001;
    expect(l.take("e")).toBe(true);
  });
  it("keeps tracked keys bounded by the global limit", () => {
    const now = { t: 0 };
    const l = new RollingWindowRateLimiter({ windowMs: 10, perKey: 1, global: 5, now: () => now.t });
    for (let i = 0; i < 1000; i++) {
      now.t = i * 3;
      l.take(`k${i}`);
    }
    expect(l.trackedKeys).toBeLessThanOrEqual(6 + 1);
  });
});
