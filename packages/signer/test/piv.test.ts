import { afterEach, describe, expect, it } from "vitest";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, readFileSync, rmSync, writeFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { encodeAttestation, isoSeconds, verifyAttestation, type AttestBody } from "@mandaterail/storage";
import { SoftwareEd25519Backend } from "../src/piv/backend-software.js";
import { YubikeyPivBackend } from "../src/piv/backend.js";
import { UsedStore } from "../src/piv/used-store.js";
import { signRequest } from "../src/requests.js";
import { edKey, realHelper, TN, payer, GENESIS_MN } from "./fixtures.js";

const prevEnv = process.env.MR_SIGNER_SOFTWARE_KEY;
afterEach(() => { process.env.MR_SIGNER_SOFTWARE_KEY = prevEnv; });

async function mk() {
  const requester = edKey();
  let t = Date.now();
  const w = await realHelper("testnet", requester.pub, undefined, () => t);
  const body = (o: Partial<AttestBody> = {}): AttestBody => ({
    v: 1, network: "testnet", genesisHash: TN, keyId: w.keyId, store: "d", spendId: "s1", txId: "A".repeat(52), sender: payer.addr.toString(),
    groupId: "", firstValid: 100, lastValid: 1100, round: 1200, nonce: randomBytes(32).toString("base64url"), expiry: isoSeconds(t + 300_000),
    observations: [
      { at: isoSeconds(t), idxRound: 1200, method: "idx404", operator: "test-op-a", provider: "idx-a.example", round: 1200 },
      { at: isoSeconds(t), idxRound: 1100, method: "blockscan", operator: "test-op-b", provider: "algod-b.example", round: 1201 },
    ], ...o,
  });
  const confirm = (m: Buffer, b: AttestBody, over: Record<string, string> = {}) => signRequest({
    op: "confirm", requester: "cli-david", network: "testnet", ts: isoSeconds(t), reqNonce: randomBytes(32).toString("base64url"),
    store: b.store, spendId: b.spendId, msgHash: createHash("sha256").update(m).digest("hex"), ...over,
  }, requester.priv);
  // rev 21: no unlock; `cool` lets the soft lock and the 1 h lockout window lapse (what time does in production)
  return { ...w, requester, body, confirm, adv: (ms: number) => { t += ms; }, cool: () => { t += 61 * 60_000; } };
}

describe("R43-P2-3 SoftwareEd25519Backend is TESTNET-ONLY at construction, at every sign, and in the helper", () => {
  it("construction and per-sign refusals; helper refuses it for mainnet; hardware backend refuses", async () => {
    process.env.MR_SIGNER_SOFTWARE_KEY = "TESTNET-ONLY";
    expect(() => new SoftwareEd25519Backend("mainnet")).toThrow(/TESTNET-ONLY/);
    const be = new SoftwareEd25519Backend("testnet");
    const w = await mk();
    const mn = encodeAttestation({ ...w.body(), network: "mainnet", genesisHash: GENESIS_MN });
    await expect(be.sign(mn)).rejects.toThrow(/TESTNET-ONLY/);
    const wrongGenesis = encodeAttestation({ ...w.body(), genesisHash: GENESIS_MN });
    await expect(be.sign(wrongGenesis)).rejects.toThrow(/TESTNET-ONLY/);
    await expect(be.sign(Buffer.from("arbitrary bytes"))).rejects.toThrow(/not an attestation/);
    await expect(realHelper("mainnet", edKey().pub, be)).rejects.toThrow(/software backend is refused/);
    delete process.env.MR_SIGNER_SOFTWARE_KEY;
    expect(() => new SoftwareEd25519Backend("testnet")).toThrow(/TESTNET-ONLY/);
    expect(() => new YubikeyPivBackend({ network: "mainnet", pkcs11Module: "x", tokenSerial: "12345678", slot: "9c", pinCredential: "piv-pin", pubkey: new Uint8Array(32) }, {} as never)).toThrow(/absolute path/);
  });
});

describe("R43-P2-4 mr-piv-sign verifies the requester's confirm itself; checks 1-5c; caps; single use; lockout", () => {
  it("signs a valid confirmed message once; a second sign for the spend is refused even with a new nonce", async () => {
    const w = await mk();
    const b = w.body();
    const m = encodeAttestation(b);
    const sig = await w.helper.sign(m, w.confirm(m, b));
    expect(verifyAttestation(m, sig, await w.backend.publicKey())).toBe(true);
    const b2 = w.body();
    const m2 = encodeAttestation(b2);
    await expect(w.helper.sign(m2, w.confirm(m2, b2))).rejects.toThrow(/already signed/);
  });
  it("mr-signer alone cannot get a signature: forged, replayed, stale or mismatched confirms are refused", async () => {
    const w = await mk();
    const fresh = () => { const b = w.body(); return { b, m: encodeAttestation(b) }; };
    let { b, m } = fresh();
    const forged = signRequest({ ...w.confirm(m, b).body }, edKey().priv); // signed by a key the helper doesn't pin
    await expect(w.helper.sign(m, forged)).rejects.toThrow(/confirm: request signature/);
    await expect(w.helper.sign(m, w.confirm(m, b, { msgHash: "0".repeat(64) }))).rejects.toThrow(/^4:/);
    await expect(w.helper.sign(m, w.confirm(m, b, { spendId: "other" }))).rejects.toThrow(/^4:/); // 3rd miss: soft lock
    w.cool(); // the soft lock lapses by itself (no unlock)
    ({ b, m } = fresh());
    await expect(w.helper.sign(m, w.confirm(m, b, { ts: isoSeconds(Date.now() - 120_000) }))).rejects.toThrow(/timestamp/);
    w.cool();
    ({ b, m } = fresh());
    const ok = w.confirm(m, b);
    await w.helper.sign(m, ok);
    const b2 = w.body({ spendId: "s2" });
    const m2 = encodeAttestation(b2);
    await expect(w.helper.sign(m2, { ...ok })).rejects.toThrow(/nonce replay/);
  });
  it("each check refuses its tampered vector", async () => {
    const w = await mk();
    const cases: [Partial<AttestBody>, RegExp][] = [
      [{ network: "mainnet" }, /^2:/], [{ keyId: "0".repeat(32) }, /^2:/], [{ sender: "B".repeat(58) }, /^3:/],
      [{ genesisHash: "x".repeat(43) + "=" }, /^5a:/], [{ round: 1105 }, /^5b:/],
      [{ observations: [w.body().observations[0]!, { ...w.body().observations[1]!, idxRound: 1099 }] }, /^5b:/],
      [{ observations: [w.body().observations[0]!, { ...w.body().observations[1]!, operator: "test-op-a" }] }, /^5c:/],
      [{ observations: [w.body().observations[0]!, { ...w.body().observations[1]!, operator: "evil" }] }, /^5c:/],
      [{ expiry: isoSeconds(Date.now() + 3_600_000) }, /^5:/],
    ];
    for (const [o, re] of cases) {
      w.cool();
      const b = w.body(o);
      const m = encodeAttestation(b);
      await expect(w.helper.sign(m, w.confirm(m, b)), String(re)).rejects.toThrow(re);
    }
    w.cool();
    const b = w.body();
    const m = encodeAttestation(b);
    await expect(w.helper.sign(Buffer.from(m.toString().replace("{", "{ ")), w.confirm(m, b))).rejects.toThrow(/^1:/);
  });
  it("the helper's own cap counter: 3 per hour, 5 per 24 h", async () => {
    const w = await mk();
    const one = (id: string) => { const b = w.body({ spendId: id }); const m = encodeAttestation(b); return w.helper.sign(m, w.confirm(m, b)); };
    for (const id of ["a", "b", "c"]) await one(id);
    await expect(one("d")).rejects.toThrow(/signs per hour/);
    w.adv(3_700_000);
    await one("d");
    await one("e");
    await expect(one("f")).rejects.toThrow(/signs per hour|per 24 h/);
    w.adv(3_700_000);
    await expect(one("f")).rejects.toThrow(/per 24 h/);
  });
  it("rev 21: lockout is persisted; > 2 lockouts in 1 h is a LONG lock (6 h, then 12 h) that clears by itself; no unlock exists", async () => {
    const w = await mk();
    const bad = () => { const b = w.body({ network: "mainnet" }); const m = encodeAttestation(b); return w.helper.sign(m, w.confirm(m, b)); };
    const good = (id: string) => { const b = w.body({ spendId: id }); const m = encodeAttestation(b); return w.helper.sign(m, w.confirm(m, b)); };
    const longLock = () => {
      for (let k = 0; k < 3; k++) {
        for (let i = 0; i < 3; i++) void bad().catch(() => undefined);
        if (k < 2) { w.adv(11 * 60_000); expect(w.helper.status().locked).toBe(false); }
      }
    };
    longLock();
    expect(w.helper.status()).toEqual({ locked: true, hard: true });
    const st = JSON.parse(readFileSync(path.join(w.dir, "helper.json"), "utf8"));
    expect(st.hard).toBe(true); // survives a restart
    expect(st.longLocks).toBe(1);
    expect("unlock" in w.helper).toBe(false);
    await expect(good("g1")).rejects.toThrow(/long-locked/);
    w.adv(6 * 3_600_000 - 60_000);
    await expect(good("g1")).rejects.toThrow(/long-locked/);
    w.adv(61_000);
    expect(w.helper.status().locked).toBe(false);
    const c0 = w.helper.statusWithCounter().counter;
    await good("g1");
    expect(w.helper.statusWithCounter().counter).toBe(c0 + 1); // the counter only goes up
    w.cool();
    longLock(); // second long lock: 12 h
    w.adv(6 * 3_600_000 + 60_000);
    await expect(good("g2")).rejects.toThrow(/long-locked/);
    w.adv(6 * 3_600_000);
    await good("g2");
  });
  it("used journal: missing refuses; rebuild must cover the DB list; corrupt refuses", async () => {
    const w = await mk();
    const b = w.body();
    const m = encodeAttestation(b);
    await w.helper.sign(m, w.confirm(m, b));
    const copy = readFileSync(w.usedFile, "utf8");
    rmSync(w.usedFile);
    expect(() => UsedStore.open(w.usedFile)).toThrow(/missing/);
    const r = UsedStore.rebuild(w.usedFile, [copy], ["d/s1", "d/s9"]);
    expect(r.has("d/s1") && r.has("d/s9")).toBe(true);
    const bad = path.join(w.dir, "bad.log");
    writeFileSync(bad, '{"spendKey":"x"}\tdeadbeefdeadbeef\n');
    expect(() => UsedStore.open(bad)).toThrow(/corrupt/);
    expect(existsSync(w.usedFile)).toBe(true);
  });
});

describe("MainNet image excludes the software backend (R43-P2-3)", () => {
  it("main-mainnet.ts import graph never reaches backend-software.ts; exclude list names it", () => {
    const src = path.resolve(__dirname, "../src");
    const seen = new Set<string>();
    const walk = (f: string) => {
      if (seen.has(f)) return;
      seen.add(f);
      const text = readFileSync(f, "utf8");
      for (const m of text.matchAll(/from "(\.[^"]+)"/g)) walk(path.resolve(path.dirname(f), m[1]!.replace(/\.js$/, ".ts")));
      for (const m of text.matchAll(/import\("(\.[^"]+)"\)/g)) walk(path.resolve(path.dirname(f), m[1]!.replace(/\.js$/, ".ts")));
    };
    walk(path.join(src, "piv/main-mainnet.ts"));
    walk(path.join(src, "index.ts"));
    expect([...seen].some((f) => f.endsWith("backend-software.ts"))).toBe(false);
    expect(readdirSync(path.join(src, "piv"))).toContain("backend-software.ts");
    const ex = readFileSync(path.resolve(__dirname, "../../../deploy/signer/mainnet-image.exclude"), "utf8");
    expect(ex).toMatch(/packages\/signer\/src\/piv\/backend-software\.ts/);
  });
});

describe("helper over the unix socket, end to end with mr-signer (one line per connection)", () => {
  it("signer -> socket -> helper (verifies the requester confirm) -> software backend", async () => {
    const { mkdtempSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { helperSocketServer, HelperSocketClient } = await import("../src/piv/socket.js");
    const { setup, candidateBody, signedPayment } = await import("./fixtures.js");
    const { MrSigner } = await import("../src/signer.js");
    const pre = await setup();
    const w = await realHelper("testnet", pre.requester.pub);
    const sock = path.join(mkdtempSync(path.join(tmpdir(), "mr-sock-")), "sign.sock");
    const srv = helperSocketServer(w.helper, sock);
    const signer = MrSigner.boot({ ...pre.deps, cfg: { ...pre.cfg, keyId: w.keyId }, helper: new HelperSocketClient(sock), backend: w.backend });
    try {
      const c = await signer.candidate(pre.req(candidateBody("d", "s1", signedPayment())));
      const r = await signer.confirm(pre.req({ op: "confirm", store: "d", spendId: "s1", msgHash: c.msgHash }));
      expect(verifyAttestation(Buffer.from(r.msg, "base64"), Buffer.from(r.sig, "base64"), await w.backend.publicKey())).toBe(true);
    } finally {
      srv.close();
    }
  });
});
