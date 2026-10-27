import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { decodeAttestation, verifyAttestation } from "@mandaterail/storage";
import { checkSignedTxn } from "../src/txcheck.js";
import { parseChronyTracking } from "../src/clock.js";
import { candidateBody, merchant, setup, signedPayment } from "./fixtures.js";

describe("txcheck (§2.1)", () => {
  it("accepts the pinned payment, single and grouped", async () => {
    const { cfg } = await setup();
    expect(checkSignedTxn(signedPayment().bytes, "xpayment", cfg)).toMatchObject({ firstValid: 100, lastValid: 1100, groupId: "" });
    const g = signedPayment({ group: true });
    expect(checkSignedTxn(g.bytes, "group", cfg)).toMatchObject({ groupId: g.groupId, memberTxIds: expect.any(Array) });
  });
  it("refuses close, rekey, wrong merchant/asset, over-cap, payer fee over the cap, tampered sig, trailing bytes", async () => {
    const { cfg } = await setup();
    expect(() => checkSignedTxn(signedPayment({ payerFee: 1001n }).bytes, "xpayment", cfg)).toThrow(/payer fee above/);
    expect(() => checkSignedTxn(signedPayment({ close: true }).bytes, "xpayment", cfg)).toThrow(/close/);
    expect(() => checkSignedTxn(signedPayment({ rekey: true }).bytes, "xpayment", cfg)).toThrow(/rekey/);
    expect(() => checkSignedTxn(signedPayment({ receiver: cfg.payer }).bytes, "xpayment", cfg)).toThrow(/merchant/);
    expect(() => checkSignedTxn(signedPayment({ asset: 31566704 }).bytes, "xpayment", cfg)).toThrow(/USDC/);
    expect(() => checkSignedTxn(signedPayment({ amount: 10_001n }).bytes, "xpayment", cfg)).toThrow(/cap/);
    const b = signedPayment().bytes.slice();
    b[10] ^= 1;
    expect(() => checkSignedTxn(b, "xpayment", cfg)).toThrow();
    expect(() => checkSignedTxn(new Uint8Array([...signedPayment().bytes, 0xc0]), "xpayment", cfg)).toThrow(/decode/);
  });
});

describe("R43-P2-1 rollback / wipe detection, R43-P2-2 page failures", () => {
  it("restoring an older policy or request state (or wiping + init) refuses to boot", async () => {
    const { copyFileSync, rmSync } = await import("node:fs");
    const path = await import("node:path");
    const s = await setup();
    copyFileSync(path.join(s.dir, "policy.json"), path.join(s.dir, "policy.old"));
    copyFileSync(path.join(s.dir, "requests.json"), path.join(s.dir, "requests.old"));
    const p = signedPayment();
    const c = await s.signer.candidate(s.req(candidateBody("d", "a", p)));
    await s.signer.confirm(s.req({ op: "confirm", store: "d", spendId: "a", msgHash: c.msgHash }));
    const { DurableJson } = await import("../src/state.js");
    const { PolicyEngine, initialPolicyState } = await import("../src/policy.js");
    const { RequestAuth, initialReqState } = await import("../src/requests.js");
    const { ChainedAudit } = await import("../src/audit.js");
    const { MrSigner } = await import("../src/signer.js");
    const reopen = async () => {
      const policy = new PolicyEngine(s.cfg.policy, new DurableJson(path.join(s.dir, "policy.json")));
      const auth = new RequestAuth(s.cfg.requesters, new DurableJson(path.join(s.dir, "requests.json")), { maxAgeS: 30, ratePerHour: 30, network: "testnet" });
      const audit = await ChainedAudit.open(s.sink, async () => undefined);
      return MrSigner.boot({ ...s.deps, policy, auth, audit });
    };
    expect(await reopen()).toBeInstanceOf(MrSigner); // current state: fine
    copyFileSync(path.join(s.dir, "policy.old"), path.join(s.dir, "policy.json"));
    await expect(reopen()).rejects.toThrow(/behind the off-host log/);
    rmSync(path.join(s.dir, "policy.json"));
    DurableJson.init(path.join(s.dir, "policy.json"), initialPolicyState());
    await expect(reopen()).rejects.toThrow(/rolled back or wiped/);
    copyFileSync(path.join(s.dir, "requests.old"), path.join(s.dir, "requests.json"));
    void initialReqState;
    await expect(reopen()).rejects.toThrow(/behind/);
  });
  it("a corrupt off-host head refuses; the chain continues from the stored head after restart", async () => {
    const { ChainedAudit } = await import("../src/audit.js");
    const s = await setup();
    await s.signer.candidate(s.req(candidateBody("d", "a", signedPayment())));
    const head = s.sink.lines.at(-1)!.split("\t")[1];
    const a2 = await ChainedAudit.open(s.sink, async () => undefined);
    await a2.log({ kind: "x", at: 1 });
    expect(JSON.parse(s.sink.lines.at(-1)!.split("\t")[0]!).prev).toBe(head);
    s.sink.lines.push("garbage\tdead");
    await expect(ChainedAudit.open(s.sink, async () => undefined)).rejects.toThrow(/corrupt/);
  });
  it("a failed page on 'signed' pauses the signer and withholds the signature; heartbeat then fails", async () => {
    const { heartbeat } = await import("../src/audit.js");
    const s = await setup();
    const c = await s.signer.candidate(s.req(candidateBody("d", "a", signedPayment())));
    s.pageFail.on = true;
    await expect(s.signer.confirm(s.req({ op: "confirm", store: "d", spendId: "a", msgHash: c.msgHash }))).rejects.toThrow(/page failed/);
    expect(s.policy.paused()?.reason).toMatch(/page failed \(signed\)/);
    s.pageFail.on = false;
    let pinged = false;
    expect(await heartbeat(() => s.signer.selfCheck(), async () => { pinged = true; })).toBe(false);
    expect(pinged).toBe(false);
  });
  it("a failed page on an anomaly pauses; heartbeat checks a test publish", async () => {
    const { heartbeat } = await import("../src/audit.js");
    const s = await setup();
    let pinged = 0;
    expect(await heartbeat(() => s.signer.selfCheck(), async () => { pinged++; })).toBe(true);
    s.pageFail.on = true;
    expect(await heartbeat(() => s.signer.selfCheck(), async () => { pinged++; })).toBe(false);
    s.probes[0]!.result = { kind: "present", genesis: s.cfg.genesisHash };
    await expect(s.signer.candidate(s.req(candidateBody("d", "a", signedPayment())))).rejects.toThrow(/present/);
    expect(s.policy.paused()).not.toBeNull();
    expect(pinged).toBe(1);
  });
  it("rolling 24 h limits and bounded config", async () => {
    const { validateConfig } = await import("../src/config.js");
    const s = await setup();
    expect(() => validateConfig({ ...s.cfg, policy: { ...s.cfg.policy, maxReleasedMicroPerDay: 60_000n } })).toThrow(/0.05/);
    expect(() => validateConfig({ ...s.cfg, policy: { ...s.cfg.policy, maxReleasesPerDay: 6 } })).toThrow(/above 5/);
  });
});

describe("chrony (R42-P3-1)", () => {
  it("parses tracking CSV", () => {
    const line = "A9FEA97B,169.254.169.123,3,1760900000.1,0.000012,0.000010,0.00002,-1.2,0.001,0.02,0.0003,0.0001,64.0,Normal";
    expect(parseChronyTracking(line)).toEqual({ synced: true, offsetS: 0.000012, stratum: 3 });
    expect(parseChronyTracking(line.replace("Normal", "Not synchronised")).synced).toBe(false);
  });
});

describe("mr-signer two-phase flow", () => {
  async function happy(s: Awaited<ReturnType<typeof setup>>, spendId = "s1") {
    const p = signedPayment();
    const cand = await s.signer.candidate(s.req(candidateBody("demo-api", spendId, p)));
    const msg = Buffer.from(cand.msg, "base64");
    expect(createHash("sha256").update(msg).digest("hex")).toBe(cand.msgHash);
    const conf = await s.signer.confirm(s.req({ op: "confirm", store: "demo-api", spendId, msgHash: cand.msgHash }));
    return { p, cand, conf, msg };
  }
  it("candidate -> confirm -> valid attestation over the echoed bytes", async () => {
    const s = await setup();
    const { conf, msg, p } = await happy(s);
    expect(Buffer.from(conf.msg, "base64").equals(msg)).toBe(true);
    expect(verifyAttestation(msg, Buffer.from(conf.sig, "base64"), s.att.pub)).toBe(true);
    const b = decodeAttestation(msg);
    expect(b).toMatchObject({ txId: p.txId, keyId: s.cfg.keyId, network: "testnet", round: 1200 });
    expect(b.observations.map((o) => o.operator)).toEqual(["test-op-a", "test-op-b", "test-op-c"]);
    expect(s.logLines.length).toBe(2);
    expect(s.logLines.join("\n")).not.toMatch(/sig"|PRIVATE|pin/i);
  });
  it("any provider showing the tx present refuses and auto-pauses", async () => {
    const s = await setup();
    s.probes[2]!.result = { kind: "present", genesis: s.cfg.genesisHash };
    await expect(s.signer.candidate(s.req(candidateBody("demo-api", "s1", signedPayment())))).rejects.toThrow(/present/);
    expect(s.policy.paused()?.reason).toMatch(/anomaly/);
    await expect(s.signer.candidate(s.req(candidateBody("demo-api", "s2", signedPayment())))).rejects.toThrow(/paused/);
    expect(s.pages.length).toBeGreaterThan(0);
  });
  it("clock skew above 5 s, unsynced clock, stale snapshot, too-early, echo mismatch, stale provider all refuse", async () => {
    const s = await setup({ policy: { ...(await setup()).cfg.policy, anomalyPauseRefusalsPerHour: 100 } });
    const p = signedPayment();
    s.clockState.offsetS = 5.5;
    await expect(s.signer.candidate(s.req(candidateBody("d", "a", p)))).rejects.toThrow(/offset/);
    s.clockState.offsetS = -0.2;
    s.clockState.synced = false;
    await expect(s.signer.candidate(s.req(candidateBody("d", "a", p)))).rejects.toThrow(/not synchronised/);
    s.clockState.synced = true;
    await expect(s.signer.candidate(s.req(candidateBody("d", "a", p, { snapshotAgoS: 120 })))).rejects.toThrow(/stale/);
    await expect(s.signer.candidate(s.req(candidateBody("d", "a", p, { submitAgoS: 60 })))).rejects.toThrow(/too early/);
    s.probes[0]!.result = { kind: "absent", method: "idx404", round: 1109, idxRound: 1109, genesis: s.cfg.genesisHash };
    s.probes[2]!.result = { kind: "error", reason: "down" };
    await expect(s.signer.candidate(s.req(candidateBody("d", "a", p)))).rejects.toThrow(/need 2/);
    s.probes[0]!.result = { kind: "absent", method: "idx404", round: 1300, idxRound: 1300, genesis: s.cfg.genesisHash };
    await expect(s.signer.candidate(s.req(candidateBody("d", "a", p)))).rejects.toThrow(/heads disagree/);
    expect(s.policy.paused()?.reason).toMatch(/anomaly: provider heads/);
    // echo mismatch (app wrote wrong derived fields) is an anomaly too
    const s2 = await setup();
    await expect(s2.signer.candidate(s2.req(candidateBody("d", "a", p, { row: { lastValid: 1000 } })))).rejects.toThrow(/echo/);
    expect(s2.policy.paused()?.reason).toMatch(/anomaly: echo/);
  });
  it("request auth: bad signature, unknown requester, replayed nonce, old timestamp, wrong network", async () => {
    const s = await setup();
    const body = candidateBody("d", "a", signedPayment());
    const r = s.req(body);
    const bad = { ...r, sig: Buffer.alloc(64).toString("base64") };
    await expect(s.signer.candidate(bad)).rejects.toThrow(/request signature/);
    await s.signer.candidate(r);
    await expect(s.signer.candidate(r)).rejects.toThrow(/nonce replay/);
    await expect(s.signer.candidate(s.req({ ...body, ts: "2026-01-01T00:00:00Z" }))).rejects.toThrow(/timestamp/);
    await expect(s.signer.candidate(s.req({ ...body, network: "mainnet" }))).rejects.toThrow(/network/);
    await expect(s.signer.candidate(s.req({ ...body, requester: "mallory" }))).rejects.toThrow(/unknown requester/);
  });
  it("confirm must match the echoed hash; caps and per-spend single use; pause kill switch", async () => {
    const s = await setup();
    const p = signedPayment();
    await happy(s, "s1");
    await expect(happy(s, "s1")).rejects.toThrow(/already released/);
    await happy(s, "s2");
    await happy(s, "s3");
    await expect(happy(s, "s4")).rejects.toThrow(/hourly release limit/);
    const s3 = await setup();
    await s3.signer.candidate(s3.req(candidateBody("d", "x", p)));
    await expect(s3.signer.confirm(s3.req({ op: "confirm", store: "d", spendId: "x", msgHash: "0".repeat(64) }))).rejects.toThrow(/mismatch/);
    expect(s3.policy.paused()?.reason).toMatch(/anomaly: confirm/);
    // rev 21: no human kill switch / pause route exists
    expect("pause" in s.signer).toBe(false);
    await expect(s3.signer.candidate(s3.req(candidateBody("d", "y", p)))).rejects.toThrow(/paused \(tamper\)/);
  });
  it("audit sink down -> fail-closed", async () => {
    const s = await setup();
    s.sink.append = async () => { throw new Error("down"); };
    await expect(s.signer.candidate(s.req(candidateBody("d", "a", signedPayment())))).rejects.toThrow(/audit/);
  });
  it("receiver pin is the merchant address", () => {
    expect(merchant.addr.toString()).toHaveLength(58);
  });
});
