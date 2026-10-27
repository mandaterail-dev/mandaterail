import { describe, expect, it } from "vitest";
import algosdk from "algosdk";
import {
  OperatorChallengeStore,
  parseRequesterAllowlist,
  RequesterKeyVerifier,
  signRequesterRequest,
  SignedChallengeOperatorVerifier,
  encodeAttestationHeader,
} from "./index.js";

const req = algosdk.generateAccount();
const ADDR = req.addr.toString();
const AUD = "mandaterail-ac2-bridge";
const BODY = JSON.stringify({ message: "pay 0.01" });

function setup(now = () => 1_000_000) {
  const store = new OperatorChallengeStore({ audience: AUD, now });
  const v = new RequesterKeyVerifier(store, [ADDR], { audience: AUD });
  return { store, v, now };
}
const ts = (ms: number) => new Date(ms).toISOString();

describe("T8 requester-key auth", () => {
  it("accepts a correctly signed request once; replay refused", async () => {
    const { store, v, now } = setup();
    const ch = store.issue("request.sign", ADDR);
    const header = signRequesterRequest({ sk: req.sk, address: ADDR, nonce: ch.nonce, audience: AUD, body: BODY, timestamp: ts(now()) });
    expect(await v.verify({ header, method: "POST", path: "/sign", body: BODY, nowMs: now() })).toEqual({ ok: true, address: ADDR });
    expect(await v.verify({ header, method: "POST", path: "/sign", body: BODY, nowMs: now() })).toMatchObject({ ok: false, error: "replayed_nonce" });
  });
  it("hashes bytes: Uint8Array and string bodies agree; one changed byte fails", async () => {
    const { store, v, now } = setup();
    const bytes = new TextEncoder().encode(BODY);
    const ch = store.issue("request.sign", ADDR);
    const header = signRequesterRequest({ sk: req.sk, address: ADDR, nonce: ch.nonce, audience: AUD, body: bytes, timestamp: ts(now()) });
    expect(await v.verify({ header, method: "POST", path: "/sign", body: BODY, nowMs: now() })).toMatchObject({ ok: true });
    const ch2 = store.issue("request.sign", ADDR);
    const h2 = signRequesterRequest({ sk: req.sk, address: ADDR, nonce: ch2.nonce, audience: AUD, body: bytes, timestamp: ts(now()) });
    const other = bytes.slice(); other[0] = 0x20;
    expect(await v.verify({ header: h2, method: "POST", path: "/sign", body: other, nowMs: now() })).toMatchObject({ ok: false, error: "requester_auth_failed" });
  });

  it("binds the exact body, method and path", async () => {
    const { store, v, now } = setup();
    for (const tamper of [{ body: BODY + " " }, { method: "PUT" }, { path: "/sign2" }]) {
      const ch = store.issue("request.sign", ADDR);
      const header = signRequesterRequest({ sk: req.sk, address: ADDR, nonce: ch.nonce, audience: AUD, body: BODY, timestamp: ts(now()) });
      const r = await v.verify({ header, method: "POST", path: "/sign", body: BODY, nowMs: now(), ...tamper });
      expect(r).toMatchObject({ ok: false, error: "requester_auth_failed" });
    }
  });
  it("rejects stale / future timestamps", async () => {
    const { store, v, now } = setup();
    for (const skew of [-61_000, 61_000]) {
      const ch = store.issue("request.sign", ADDR);
      const header = signRequesterRequest({ sk: req.sk, address: ADDR, nonce: ch.nonce, audience: AUD, body: BODY, timestamp: ts(now() + skew) });
      expect(await v.verify({ header, method: "POST", path: "/sign", body: BODY, nowMs: now() })).toMatchObject({ ok: false, error: "stale_timestamp" });
    }
  });
  it("non-allowlisted key denied and its nonce burned", async () => {
    const { store, v, now } = setup();
    const other = algosdk.generateAccount();
    const ch = store.issue("request.sign", other.addr.toString());
    const header = signRequesterRequest({ sk: other.sk, address: other.addr.toString(), nonce: ch.nonce, audience: AUD, body: BODY, timestamp: ts(now()) });
    expect(await v.verify({ header, method: "POST", path: "/sign", body: BODY, nowMs: now() })).toMatchObject({ ok: false, error: "requester_auth_failed" });
    expect(store.consume(ch.nonce)).toMatchObject({ ok: false, error: "replayed_nonce" });
  });
  it("nonce bound to requester + action: other address / operator nonce refused, and vice versa", async () => {
    const { store, v, now } = setup();
    const other = algosdk.generateAccount();
    const ch1 = store.issue("request.sign", other.addr.toString());
    const h1 = signRequesterRequest({ sk: req.sk, address: ADDR, nonce: ch1.nonce, audience: AUD, body: BODY, timestamp: ts(now()) });
    expect(await v.verify({ header: h1, method: "POST", path: "/sign", body: BODY, nowMs: now() })).toMatchObject({ error: "challenge_binding_mismatch" });
    const ch2 = store.issue("approve", ADDR);
    const h2 = signRequesterRequest({ sk: req.sk, address: ADDR, nonce: ch2.nonce, audience: AUD, body: BODY, timestamp: ts(now()) });
    expect(await v.verify({ header: h2, method: "POST", path: "/sign", body: BODY, nowMs: now() })).toMatchObject({ error: "challenge_binding_mismatch" });
    // a requester nonce can't be used as operator evidence
    const ch3 = store.issue("request.sign", ADDR);
    const op = new SignedChallengeOperatorVerifier(store, [ADDR]);
    const sig = algosdk.signBytes(new TextEncoder().encode(ch3.message), req.sk);
    const ev = encodeAttestationHeader({ nonce: ch3.nonce, address: ADDR, format: "algosdk", signature: Buffer.from(sig).toString("base64") });
    expect(await op.verify({ kind: "signed-challenge", evidence: ev }, { action: "approve", subjectId: ADDR })).toMatchObject({ ok: false, error: "challenge_binding_mismatch" });
  });
  it("audience binding and expiry", async () => {
    let t = 1_000_000;
    const { store, v } = setup(() => t);
    const other = new OperatorChallengeStore({ audience: "mandaterail-console", now: () => t });
    const ch = other.issue("request.sign", ADDR);
    const v2 = new RequesterKeyVerifier(other, [ADDR], { audience: AUD });
    const h = signRequesterRequest({ sk: req.sk, address: ADDR, nonce: ch.nonce, audience: "mandaterail-console", body: BODY, timestamp: ts(t) });
    expect(await v2.verify({ header: h, method: "POST", path: "/sign", body: BODY, nowMs: t })).toMatchObject({ error: "challenge_binding_mismatch" });
    const ch2 = store.issue("request.sign", ADDR);
    t += 200_000;
    const h2 = signRequesterRequest({ sk: req.sk, address: ADDR, nonce: ch2.nonce, audience: AUD, body: BODY, timestamp: ts(t) });
    expect(await v.verify({ header: h2, method: "POST", path: "/sign", body: BODY, nowMs: t })).toMatchObject({ error: "expired_nonce" });
  });
  it("malformed header and allowlist parsing", async () => {
    const { v } = setup();
    expect(await v.verify({ header: "%%%", method: "POST", path: "/sign", body: BODY, nowMs: 0 })).toMatchObject({ error: "requester_auth_malformed" });
    expect(parseRequesterAllowlist(` ${ADDR} ,`)).toEqual([ADDR]);
    expect(() => parseRequesterAllowlist("NOTANADDRESS")).toThrow();
    expect(parseRequesterAllowlist(undefined)).toEqual([]);
  });
});
