import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import algosdk from "algosdk";
import {
  OperatorChallengeStore,
  SignedChallengeOperatorVerifier,
  encodeAttestationHeader,
  arc60SignedBytes,
  parseOperatorAllowlist,
  resolveOperatorAttestationMode,
  type OperatorAction,
} from "./operator-challenge.js";

const op = algosdk.generateAccount();
const other = algosdk.generateAccount();
const OP = op.addr.toString();
const OTHER = other.addr.toString();

function setup(now = { t: 1_000_000 }) {
  const store = new OperatorChallengeStore({ ttlMs: 60_000, now: () => now.t });
  const v = new SignedChallengeOperatorVerifier(store, [OP]);
  return { store, v, now };
}

function algosdkEvidence(acct: algosdk.Account, nonce: string, message: string) {
  const sig = algosdk.signBytes(new TextEncoder().encode(message), acct.sk);
  return encodeAttestationHeader({
    nonce,
    address: acct.addr.toString(),
    format: "algosdk",
    signature: Buffer.from(sig).toString("base64"),
  });
}

const check = (v: SignedChallengeOperatorVerifier, evidence: string, action: OperatorAction, subjectId: string) =>
  v.verify({ kind: "signed-challenge", evidence }, { action, subjectId });

describe("SignedChallengeOperatorVerifier", () => {
  it("accepts a valid algosdk signature from an allowlisted operator", async () => {
    const { store, v } = setup();
    const ch = store.issue("approve", "p-1");
    const r = await check(v, algosdkEvidence(op, ch.nonce, ch.message), "approve", "p-1");
    expect(r).toEqual({ ok: true, kind: "signed-challenge", subject: OP });
  });

  it("rejects wrong signer (signature by another key, claimed allowlisted address)", async () => {
    const { store, v } = setup();
    const ch = store.issue("approve", "p-1");
    const sig = algosdk.signBytes(new TextEncoder().encode(ch.message), other.sk);
    const ev = encodeAttestationHeader({ nonce: ch.nonce, address: OP, format: "algosdk", signature: Buffer.from(sig).toString("base64") });
    const r = await check(v, ev, "approve", "p-1");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toBe("invalid_signature");
  });

  it("rejects a non-allowlisted signer", async () => {
    const { store, v } = setup();
    const ch = store.issue("approve", "p-1");
    const r = await check(v, algosdkEvidence(other, ch.nonce, ch.message), "approve", "p-1");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toBe("operator_not_allowlisted");
    expect(OTHER).not.toBe(OP);
  });

  it("rejects an expired nonce", async () => {
    const { store, v, now } = setup();
    const ch = store.issue("reject", "p-2");
    now.t += 61_000;
    const r = await check(v, algosdkEvidence(op, ch.nonce, ch.message), "reject", "p-2");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toBe("expired_nonce");
  });

  it("rejects a replayed nonce", async () => {
    const { store, v } = setup();
    const ch = store.issue("approve", "p-1");
    const ev = algosdkEvidence(op, ch.nonce, ch.message);
    expect((await check(v, ev, "approve", "p-1")).ok).toBe(true);
    const r = await check(v, ev, "approve", "p-1");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toBe("replayed_nonce");
  });

  it("rejects unknown nonce", async () => {
    const { v } = setup();
    const r = await check(v, algosdkEvidence(op, "nope", "x"), "approve", "p-1");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toBe("unknown_nonce");
  });

  it("rejects action mismatch (approve challenge used for reject)", async () => {
    const { store, v } = setup();
    const ch = store.issue("approve", "p-1");
    const r = await check(v, algosdkEvidence(op, ch.nonce, ch.message), "reject", "p-1");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toBe("challenge_binding_mismatch");
  });

  it("rejects pending id mismatch", async () => {
    const { store, v } = setup();
    const ch = store.issue("approve", "p-1");
    const r = await check(v, algosdkEvidence(op, ch.nonce, ch.message), "approve", "p-OTHER");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toBe("challenge_binding_mismatch");
  });

  it("rejects malformed evidence", async () => {
    const { v } = setup();
    const r = await check(v, "not-base64-json", "approve", "p-1");
    expect(r.ok).toBe(false);
  });

  it("accepts ARC-60 style signData evidence and binds domain", async () => {
    const store = new OperatorChallengeStore();
    const domain = "mandaterail.pages.dev";
    const v = new SignedChallengeOperatorVerifier(store, [OP], { domain });
    const ch = store.issue("approve", "p-9");
    const data = JSON.stringify({
      domain, account_address: OP, uri: `https://${domain}`, version: "1",
      statement: ch.message, nonce: ch.nonce, chain_id: "283", type: "ed25519",
    });
    const dataBytes = new TextEncoder().encode(data);
    const authData = new Uint8Array([...createHash("sha256").update(domain).digest(), 1, 0, 0, 0, 0]);
    const toSign = arc60SignedBytes(dataBytes, authData);
    const sig = algosdk.signBytes(toSign, op.sk); // wrong: MX prefix — must fail
    const bad = encodeAttestationHeader({ nonce: ch.nonce, address: OP, format: "arc60", signature: Buffer.from(sig).toString("base64"), data: Buffer.from(dataBytes).toString("base64"), authenticatorData: Buffer.from(authData).toString("base64") });
    expect((await check(v, bad, "approve", "p-9")).ok).toBe(false);

    const ch2 = store.issue("approve", "p-9");
    const data2 = new TextEncoder().encode(data.replace(ch.message.replace(/\n/g, "\\n"), ch2.message.replace(/\n/g, "\\n")).replace(ch.nonce, ch2.nonce));
    const { sign } = await import("node:crypto");
    const { createPrivateKey } = await import("node:crypto");
    const seed = op.sk.slice(0, 32);
    const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seed)]);
    const key = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
    const sig2 = sign(null, arc60SignedBytes(data2, authData), key);
    const good = encodeAttestationHeader({ nonce: ch2.nonce, address: OP, format: "arc60", signature: sig2.toString("base64"), data: Buffer.from(data2).toString("base64"), authenticatorData: Buffer.from(authData).toString("base64") });
    expect(await check(v, good, "approve", "p-9")).toEqual({ ok: true, kind: "signed-challenge", subject: OP });
  });
});

describe("mode + allowlist helpers", () => {
  it("defaults signed-challenge on MainNet, token-lab otherwise; refuses unknown", () => {
    expect(resolveOperatorAttestationMode(true, undefined)).toBe("signed-challenge");
    expect(resolveOperatorAttestationMode(false, undefined)).toBe("token-lab");
    expect(resolveOperatorAttestationMode(true, "token-lab")).toBe("token-lab");
    expect(resolveOperatorAttestationMode(false, "bogus")).toBeNull();
  });
  it("parses allowlist and drops invalid addresses", () => {
    expect(parseOperatorAllowlist(`${OP}, junk ,${OTHER}`)).toEqual([OP, OTHER]);
  });
});
