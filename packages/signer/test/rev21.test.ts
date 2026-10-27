/**
 * rev 21 (§23): fully automatic. Rate pauses clear when the window rolls; tamper pauses resume only after the
 * cooldown (backoff) with a fresh 2-of-2 resume quorum; no unlock / pause route; every pause and resume is in the
 * B2 chain and paged. Plus the end-to-end driver against Postgres 18 (v16).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { randomBytes, sign as edSign } from "node:crypto";
import pg from "pg";
import { decodeResume, encodeResumeCosign, isoSeconds, keyIdOf, migratePostgres } from "@mandaterail/storage";
import { DurableJson } from "../src/state.js";
import { PolicyEngine, initialPolicyState, type PolicyState } from "../src/policy.js";
import { RequestAuth, initialReqState, type ReqState } from "../src/requests.js";
import { SecondVerifier, initialVerifierState, type VerifierState } from "../src/verifier/verifier.js";
import { resumeAppliedAfter, verifyChainHead } from "../src/verifier/reconcile.js";
import { signerServer } from "../src/server.js";
import { autoResumeOnce } from "../src/cli/resume.js";
import { candidateBody, edKey, realHelper, setup, signedPayment, TN } from "./fixtures.js";

const kinds = (lines: string[]) => lines.map((l) => JSON.parse(l.split("\t")[0]!).kind as string);

/** signer (real helper, software key) + verifier (own software key, chain check over the signer's sink), one fake clock. */
async function world(o: { baseS?: number; verifierChecks?: (seq: number, head: string) => Promise<void>; observedHook?: () => Promise<void> } = {}) {
  let t = Date.now();
  const now = () => t;
  const pre = await setup({ policy: { ...(await setup()).cfg.policy, tamperBaseCooldownS: o.baseS ?? 21_600 } }, () => ({ sign: async () => new Uint8Array() }));
  const h = await realHelper("testnet", pre.requester.pub, undefined, now);
  const cfg = { ...pre.cfg, keyId: h.keyId };
  const pj = path.join(mkdtempSync(path.join(tmpdir(), "mr-r21-")), "policy.json");
  DurableJson.init<PolicyState>(pj, initialPolicyState());
  const policy = new PolicyEngine(cfg.policy, new DurableJson<PolicyState>(pj), now);
  const { MrSigner } = await import("../src/signer.js");
  process.env.MR_SIGNER_SOFTWARE_KEY = "TESTNET-ONLY";
  const { SoftwareEd25519Backend } = await import("../src/piv/backend-software.js");
  const vb = new SoftwareEd25519Backend("testnet");
  const vpub = await vb.publicKey();
  const rj = path.join(path.dirname(pj), "requests.json");
  DurableJson.init<ReqState>(rj, initialReqState());
  const auth = new RequestAuth(cfg.requesters, new DurableJson<ReqState>(rj), { maxAgeS: 30, ratePerHour: 1000, network: "testnet" }, now);
  const signer = MrSigner.boot({ ...pre.deps, cfg, auth, policy, helper: h.helper, backend: h.backend, now, cosignerPubkey: vpub });
  await pre.audit.log({ kind: "boot", reason: "config sha256 test", at: t });
  const vdir = mkdtempSync(path.join(tmpdir(), "mr-r21v-"));
  DurableJson.init<VerifierState>(path.join(vdir, "v.json"), initialVerifierState());
  DurableJson.init<ReqState>(path.join(vdir, "r.json"), initialReqState());
  const vst = new DurableJson<VerifierState>(path.join(vdir, "v.json"));
  const vpages: string[] = [];
  const verifier = new SecondVerifier({ signer: cfg, primaryPubkey: await h.backend.publicKey(), cosignerKeyId: keyIdOf(vpub), providers: [], maxPerHour: 3, maxPer24h: 5, attestTtlS: 300 },
    { auth: new RequestAuth(cfg.requesters, new DurableJson<ReqState>(path.join(vdir, "r.json")), { maxAgeS: 30, ratePerHour: 1000, network: "testnet" }, now),
      probes: [], backend: vb, st: vst, clock: async () => ({ synced: true, offsetS: 0, stratum: 2 }), page: async (x) => { vpages.push(x); }, now,
      tamperBaseCooldownS: o.baseS ?? 21_600, resumeChecks: o.verifierChecks ?? ((seq, head) => verifyChainHead(pre.sink, seq, head).then(() => undefined)),
      resumeObservedCheck: async (seq, h) => { const r = await resumeAppliedAfter(pre.sink, seq, h); await o.observedHook?.(); return r; } });
  const req = (body: Record<string, unknown>) => signRequest(body);
  function signRequest(body: Record<string, unknown>) { return pre.req({ ...body, ts: isoSeconds(t) }); }
  return { ...pre, cfg, h, policy, signer, verifier, vst, vpages, vb, vpub, req, adv: (ms: number) => { t += ms; }, now };
}

async function quorum(w: Awaited<ReturnType<typeof world>>, db = { seq: 1, cnt: 1 }) {
  const c = await w.signer.resumeCandidate(w.req({ op: "resume-candidate", dbPauseSeq: db.seq, dbTamperCount: db.cnt }));
  const s = await w.signer.resumeConfirm(w.req({ op: "resume-confirm", msgHash: c.msgHash }));
  const co = await w.verifier.resumeCosign(w.req({ op: "resume-cosign", resumeMsg: s.msg, resumeSig: s.sig }));
  return { c, s, co };
}

describe("rev 21 pauses: automatic only", () => {
  it("rate pause (too many refusals) clears by itself when the 1 h window rolls; logged + paged", async () => {
    const w = await world();
    for (let i = 0; i < 6; i++) await expect(w.signer.candidate(w.req(candidateBody("d", `x${i}`, signedPayment(), { snapshotAgoS: 3600 })))).rejects.toThrow();
    expect(w.policy.paused()?.kind).toBe("rate");
    expect(kinds(w.logLines)).toContain("pause-rate");
    w.adv(3_600_001);
    await w.signer.selfCheck();
    expect(w.policy.paused()).toBeNull();
    expect(kinds(w.logLines)).toContain("auto-resume-rate");
    expect(w.pages).toEqual(expect.arrayContaining(["[signer] pause-rate", "[signer] auto-resume-rate"]));
  });

  it("tamper pause: refused before the cooldown; then a 2-of-2 resume; backoff doubles; counter anchored; everything in the chain", async () => {
    const w = await world();
    w.policy.tamper("test: chain mismatch");
    await expect(w.signer.resumeCandidate(w.req({ op: "resume-candidate", dbPauseSeq: 1, dbTamperCount: 1 }))).rejects.toThrow(/cooldown not over/);
    w.adv(6 * 3_600_000);
    const c0 = w.h.helper.stateCounter();
    const q = await quorum(w);
    expect(w.h.helper.stateCounter()).toBe(c0 + 1); // counter-anchor bump on resume
    expect(decodeResume(Buffer.from(q.c.msg, "base64")).chainSeq).toBeGreaterThan(0);
    // a forged / mismatched co-signature can't lift it
    const forged = encodeResumeCosign({ ...JSON.parse(Buffer.from(q.co.msg, "base64").toString().slice(20)) });
    await expect(w.signer.resumeApply(w.req({ op: "resume-apply", cosignMsg: forged.toString("base64"), cosignSig: Buffer.from(edSign(null, forged, edKey().priv)).toString("base64") }))).rejects.toThrow(/does not verify/);
    expect(w.policy.paused()?.kind).toBe("tamper");
    await w.signer.resumeApply(w.req({ op: "resume-apply", cosignMsg: q.co.msg, cosignSig: q.co.sig }));
    expect(w.policy.paused()).toBeNull();
    // second tamper within 30 days: 12 h
    w.policy.tamper("test: provider drift");
    expect(w.policy.tamperCount()).toBe(2);
    w.adv(6 * 3_600_000 + 1000);
    await expect(w.signer.resumeCandidate(w.req({ op: "resume-candidate", dbPauseSeq: 2, dbTamperCount: 2 }))).rejects.toThrow(/cooldown not over/);
    w.adv(6 * 3_600_000);
    const q2 = await quorum(w, { seq: 2, cnt: 2 });
    await w.signer.resumeApply(w.req({ op: "resume-apply", cosignMsg: q2.co.msg, cosignSig: q2.co.sig }));
    expect(w.policy.tamperCount()).toBe(2); // never lowered by a resume
    expect(kinds(w.logLines).filter((k) => /boot|resume|pause/.test(k))).toEqual(["boot", "resume-candidate", "resume-attested", "auto-resume-tamper", "resume-candidate", "resume-attested", "auto-resume-tamper"]);
    expect(w.pages).toEqual(expect.arrayContaining(["[signer] resume-attested", "[signer] auto-resume-tamper"]));
  });

  it("anomalies on the live path are tamper pauses, logged as pause-tamper and paged", async () => {
    const w = await world();
    w.probes[0]!.result = { kind: "present", genesis: TN };
    await expect(w.signer.candidate(w.req(candidateBody("d", "a", signedPayment())))).rejects.toThrow(/present/);
    expect(w.policy.paused()?.kind).toBe("tamper");
    expect(kinds(w.logLines)).toContain("pause-tamper");
    expect(w.pages).toContain("[signer] pause-tamper");
  });

  it("the verifier runs its OWN chain check: a head it can't confirm (fork / wrong head) refuses and pauses it", async () => {
    const w = await world({ verifierChecks: async () => { throw new Error("chain line 3 does not hash to the signer's head"); } });
    w.policy.tamper("x"); w.adv(6 * 3_600_000);
    await expect(quorum(w)).rejects.toThrow(/resume check/);
    expect(w.vst.get().paused).not.toBeNull();
    expect(w.policy.paused()?.kind).toBe("tamper");
  });

  it("R62-P3-2: the verifier's own pause lifts only after the resume is observed applied in the signer chain", async () => {
    const w = await world();
    w.vst.put({ ...w.vst.get(), counter: w.vst.get().counter + 1, paused: { at: w.now(), reason: "test anomaly" }, tamperCount: 1 });
    w.policy.tamper("x"); w.adv(6 * 3_600_000);
    await expect(w.verifier.resumeObserved(w.req({ op: "resume-observed" }))).rejects.toThrow(/no co-signed resume pending/);
    const q = await quorum(w);
    expect(w.vst.get().paused).not.toBeNull(); // co-signing alone does not lift it
    await expect(w.verifier.resumeObserved(w.req({ op: "resume-observed" }))).rejects.toThrow(/not observed/);
    expect(w.vst.get().paused).not.toBeNull();
    await w.signer.resumeApply(w.req({ op: "resume-apply", cosignMsg: q.co.msg, cosignSig: q.co.sig }));
    w.adv(20 * 60_000); // R63-P2-2: the pending marker does not expire; a later tick still lifts it
    expect((await w.verifier.status(w.req({ op: "status" }))).pendingResume).not.toBeNull();
    expect(await w.verifier.resumeObserved(w.req({ op: "resume-observed" }))).toEqual({ resumed: true });
    expect(w.vst.get().paused).toBeNull();
    expect(w.vpages).toContain("[verifier] auto-resume (own pause lifted after the observed resume)");
  });

  it("R65-P3-2: an anomaly after the co-signed resume supersedes it; the older resume does not lift the newer pause", async () => {
    const w = await world();
    w.vst.put({ ...w.vst.get(), counter: w.vst.get().counter + 1, paused: { at: w.now(), reason: "test anomaly" }, tamperCount: 1 });
    w.policy.tamper("x"); w.adv(6 * 3_600_000);
    const q = await quorum(w);
    const pend = w.vst.get().pendingResume!;
    w.adv(1_000);
    await expect(w.verifier.resumeCosign(w.req({ op: "resume-cosign", resumeMsg: Buffer.from("x").toString("base64"), resumeSig: Buffer.alloc(64).toString("base64") }))).rejects.toThrow(/does not verify/);
    const st = await w.verifier.status(w.req({ op: "status" }));
    expect(st.paused!.at).toBeGreaterThan(pend.at);
    expect(st.paused!.reason).toMatch(/anomaly: resume attestation signature does not verify/);
    // R66-P3-2: the supersede clears the marker and does not count the pause twice
    expect(st.tamperCount).toBe(1);
    expect(st.pendingResume).toBeNull();
    expect(w.vpages).toContain("[verifier] pause-tamper (supersedes the co-signed resume)");
    await w.signer.resumeApply(w.req({ op: "resume-apply", cosignMsg: q.co.msg, cosignSig: q.co.sig }));
    await expect(w.verifier.resumeObserved(w.req({ op: "resume-observed" }))).rejects.toThrow(/no co-signed resume pending/);
    expect(w.vst.get().paused).not.toBeNull();
    // a further anomaly while paused (no marker) changes nothing: same pause, same count
    const p1 = w.vst.get().paused!;
    w.adv(1_000);
    await expect(w.verifier.resumeCosign(w.req({ op: "resume-cosign", resumeMsg: Buffer.from("y").toString("base64"), resumeSig: Buffer.alloc(64).toString("base64") }))).rejects.toThrow(/does not verify/);
    expect(w.vst.get().paused).toEqual(p1);
    expect(w.vst.get().tamperCount).toBe(1);
  });

  it("R66-P3-2: resumeObserved re-reads after its await: an anomaly meanwhile supersedes the marker and the pause stays", async () => {
    let hook: (() => Promise<void>) | undefined;
    const w = await world({ observedHook: async () => { await hook?.(); } });
    w.vst.put({ ...w.vst.get(), counter: w.vst.get().counter + 1, paused: { at: w.now(), reason: "test anomaly" }, tamperCount: 1 });
    w.policy.tamper("x"); w.adv(6 * 3_600_000);
    const q = await quorum(w);
    await w.signer.resumeApply(w.req({ op: "resume-apply", cosignMsg: q.co.msg, cosignSig: q.co.sig }));
    w.adv(1_000);
    hook = async () => { // another request lands while the chain is being read
      hook = undefined;
      await expect(w.verifier.resumeCosign(w.req({ op: "resume-cosign", resumeMsg: Buffer.from("z").toString("base64"), resumeSig: Buffer.alloc(64).toString("base64") }))).rejects.toThrow(/does not verify/);
    };
    await expect(w.verifier.resumeObserved(w.req({ op: "resume-observed" }))).rejects.toThrow(/marker changed while it was being observed/);
    expect(w.vst.get().paused?.reason).toMatch(/anomaly: resume attestation signature does not verify/);
    expect(w.vst.get().pendingResume ?? null).toBeNull();
    expect(w.vst.get().tamperCount).toBe(1);
  });

  it("R66-P3-2: resumeCosign re-reads after its chain check: a pause that landed meanwhile has a fresh cooldown, no marker is written", async () => {
    let w!: Awaited<ReturnType<typeof world>>;
    let once = true;
    w = await world({ verifierChecks: async (seq, head) => {
      await verifyChainHead(w.sink, seq, head);
      if (once) { once = false; await expect(w.verifier.resumeCosign(w.req({ op: "resume-cosign", resumeMsg: Buffer.from("q").toString("base64"), resumeSig: Buffer.alloc(64).toString("base64") }))).rejects.toThrow(/does not verify/); }
    } });
    w.policy.tamper("x"); w.adv(6 * 3_600_000);
    await expect(quorum(w)).rejects.toThrow(/verifier cooldown not over/);
    expect(w.vst.get().pendingResume ?? null).toBeNull();
    expect(w.vst.get().paused).not.toBeNull();
    expect(w.vst.get().tamperCount).toBe(1);
  });

  it("stale or replayed resume material is refused (issuedAt +-60 s, single-use nonces)", async () => {
    const w = await world();
    w.policy.tamper("x"); w.adv(6 * 3_600_000);
    const c = await w.signer.resumeCandidate(w.req({ op: "resume-candidate", dbPauseSeq: 1, dbTamperCount: 1 }));
    const s = await w.signer.resumeConfirm(w.req({ op: "resume-confirm", msgHash: c.msgHash }));
    await w.verifier.resumeCosign(w.req({ op: "resume-cosign", resumeMsg: s.msg, resumeSig: s.sig }));
    await expect(w.verifier.resumeCosign(w.req({ op: "resume-cosign", resumeMsg: s.msg, resumeSig: s.sig }))).rejects.toThrow(/nonce already co-signed/);
    const c2 = await w.signer.resumeCandidate(w.req({ op: "resume-candidate", dbPauseSeq: 1, dbTamperCount: 1 }));
    const s2 = await w.signer.resumeConfirm(w.req({ op: "resume-confirm", msgHash: c2.msgHash }));
    w.adv(61_000);
    await expect(w.verifier.resumeCosign(w.req({ op: "resume-cosign", resumeMsg: s2.msg, resumeSig: s2.sig }))).rejects.toThrow(/issuedAt/);
  });

  it("no human path: no /v1/unlock, /v1/pause, /v1/helper-status; MainNet needs the verifier key and a >= 6 h cooldown", async () => {
    const w = await world();
    const srv = signerServer(w.signer, { allowIps: ["127.0.0.1"] });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const port = (srv.address() as { port: number }).port;
    for (const p of ["/v1/unlock", "/v1/pause", "/v1/helper-status", "/v1/config", "/v1/caps"]) {
      expect(await fetch(`http://127.0.0.1:${port}${p}`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }).then((r) => r.status)).toBe(404);
    }
    srv.close();
    for (const m of ["unlock", "pause", "unpause", "helperStatus"]) expect(m in w.signer).toBe(false);
    expect("unpause" in w.policy).toBe(false);
    const { validateConfig } = await import("../src/config.js");
    const { GENESIS_PINS } = await import("../src/config.js");
    expect(() => validateConfig({ ...w.cfg, network: "mainnet", genesisHash: GENESIS_PINS.mainnet, attestTtlS: 600, policy: { ...w.cfg.policy, tamperBaseCooldownS: 3600 } })).toThrow(/MainNet floor of 6 h/);
    const src = readFileSync(path.resolve(__dirname, "../src/main.ts"), "utf8");
    expect(src).toMatch(/MainNet requires cosignerPubkeyB64/);
    expect(src).not.toMatch(/unlockPubkey/);
  });
});

const PG_URL = process.env.MR_TEST_PG_URL;
const SQL = path.resolve(__dirname, "../../../deploy/sql/t11-mr-reconcile-role.sql");
describe.skipIf(!PG_URL)("rev 21 automatic resume driver end to end [postgres]", () => {
  let admin: pg.Pool, own: pg.Pool, rel: pg.Pool, dbName = "";
  beforeAll(async () => {
    admin = new pg.Pool({ connectionString: PG_URL, max: 2 });
    dbName = `mr_r21_${randomBytes(4).toString("hex")}`;
    await admin.query(`CREATE DATABASE ${dbName}`);
    const url = PG_URL!.replace(/\/[^/]*$/, `/${dbName}`);
    own = new pg.Pool({ connectionString: url, max: 4 });
    await migratePostgres(own, { network: "testnet", verifyNetwork: async (p) => ({ genesisHash: p.caip2.slice(9) }) });
    await promisify(execFile)("psql", ["-X", "-q", "-v", "ON_ERROR_STOP=1", "-v", "pw=t-rec-pw", "-v", "mon_pw=t-mon-pw", "-v", "rel_pw=t-rel-pw", "-d", url, "-f", SQL]);
    await own.query("SELECT mr_set_tamper_cooldown_base(2)"); // R66-P3-1: the setter is the only path
    const u = new URL(url); u.username = "mr_release"; u.password = "t-rel-pw";
    rel = new pg.Pool({ connectionString: u.toString(), max: 2 }); rel.on("error", () => undefined);
  });
  afterAll(async () => { await rel?.end(); await own?.end(); if (dbName) await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`); await admin?.end(); });

  it("signer tamper -> DB pause recorded -> waits out the cooldown -> 2-of-2 -> DB and signer resumed; DB counter persisted", async () => {
    const w = await world({ baseS: 1 });
    // real clock here (the DB has its own); the helper / verifier clocks follow Date.now via adv(0)
    const pub = await w.h.backend.publicKey();
    await own.query("INSERT INTO mr_signer_key (key_id, pubkey, network, margin_rounds, trust_domain, key_resource) VALUES ($1, $2, 'testnet', 10, 'gcp:mr-signer-test', 'projects/mr-signer-test/locations/us-east1/keyRings/mr/cryptoKeys/attest/cryptoKeyVersions/1')", [w.h.keyId, Buffer.from(pub)]);
    await own.query("INSERT INTO mr_cosigner_key (key_id, pubkey, network, trust_domain, key_resource) VALUES ($1, $2, 'testnet', 'aws:000000000000', 'arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000')", [keyIdOf(w.vpub), Buffer.from(w.vpub)]);
    const pages: string[] = [];
    const sync = () => w.adv(Date.now() - w.now());
    const deps = { db: rel, network: "testnet" as const, requesterId: "cli-david", requesterKey: w.requester.priv, signer: w.signer, verifier: w.verifier, page: async (s: string) => { pages.push(s); } };
    expect(await autoResumeOnce(deps)).toBe("running");
    w.policy.tamper("test: audit chain mismatch");
    expect(await autoResumeOnce(deps)).toBe("waiting");
    expect((await own.query("SELECT paused, tamper_count FROM mr_pause_state WHERE network = 'testnet'")).rows[0]).toEqual({ paused: true, tamper_count: 1 });
    expect(pages).toContain("[resume] DB pause recorded");
    await new Promise((r) => setTimeout(r, 2200));
    sync();
    expect(await autoResumeOnce(deps)).toBe("resumed");
    expect(w.policy.paused()).toBeNull();
    expect((await own.query("SELECT paused, tamper_count, pause_seq::int AS seq FROM mr_pause_state WHERE network = 'testnet'")).rows[0]).toEqual({ paused: false, tamper_count: 1, seq: 1 });
    expect((await own.query("SELECT count(*)::int AS n FROM mr_resume_nonce")).rows[0].n).toBe(2);
    expect(pages).toContain("[resume] AUTO-RESUMED after tamper pause");
    // a DB-only pause (monitor drift) also resumes only through the quorum; the second one backs off (4 s)
    await own.query("SET ROLE mr_monitor; SELECT * FROM mr_tamper_pause('monitor: manifest drift'); RESET ROLE;").catch(async () => { await rel.query("SELECT * FROM mr_tamper_pause('monitor: manifest drift')"); });
    await new Promise((r) => setTimeout(r, 2200)); sync();
    expect(await autoResumeOnce(deps)).toBe("waiting");
    await new Promise((r) => setTimeout(r, 2000)); sync();
    expect(await autoResumeOnce(deps)).toBe("resumed");
    expect((await own.query("SELECT tamper_count FROM mr_pause_state WHERE network = 'testnet'")).rows[0].tamper_count).toBe(2);
    // R63-P2-2: a verifier-only tamper pause is mirrored into the DB, then lifted by the same quorum; the verifier lifts
    // its own pause once it observes the applied resume (here on the same tick)
    w.vst.put({ ...w.vst.get(), counter: w.vst.get().counter + 1, paused: { at: Date.now() - 10 * 86_400_000, reason: "verifier: reconcile mismatch" }, tamperCount: 1 });
    sync();
    expect(await autoResumeOnce(deps)).toBe("waiting");
    expect((await own.query("SELECT paused, reason FROM mr_pause_state WHERE network = 'testnet'")).rows[0]).toEqual({ paused: true, reason: "verifier: verifier: reconcile mismatch" });
    expect(pages).toContain("[resume] DB pause recorded (verifier pause mirrored)");
    await new Promise((r) => setTimeout(r, 8200)); sync(); // third tamper: 2 s * 2^2
    expect(await autoResumeOnce(deps)).toBe("resumed");
    expect(w.vst.get().paused).toBeNull();
    expect((await own.query("SELECT paused, tamper_count FROM mr_pause_state WHERE network = 'testnet'")).rows[0]).toEqual({ paused: false, tamper_count: 3 });
  }, 60_000);
});

describe("R64-P3-1: no re-pause while the verifier's marker names the current pause_seq", () => {
  const fake = (seq: number, paused: boolean) => {
    const calls: string[] = [];
    const db = { query: async (q: string) => { calls.push(q); if (/mr_tamper_pause/.test(q)) return { rows: [{}] }; return { rows: [{ paused, seq: String(seq), cnt: 1, nb: null, dbnow: new Date() }] }; } };
    return { calls, db };
  };
  const run = async (markerSeq: number, dbSeq: number, ageMin: number, o: { pausedAfterMs?: number; dbPaused?: boolean } = {}) => {
    const { calls, db } = fake(dbSeq, o.dbPaused ?? false);
    const pages: string[] = [], bodies: string[] = [];
    const t0 = 1_800_000_000_000;
    const out = await autoResumeOnce({
      db: db as unknown as pg.Pool, network: "testnet", requesterId: "cli", requesterKey: edKey().priv,
      signer: { status: async () => ({ paused: null, tamperCount: 1, resumeNotBefore: null }), resumeCandidate: async () => { throw new Error("x"); }, resumeConfirm: async () => { throw new Error("x"); }, resumeApply: async () => { throw new Error("x"); } },
      verifier: {
        resumeCosign: async () => { throw new Error("x"); },
        resumeObserved: async () => { throw new Error("not observed"); },
        status: async () => ({ paused: { at: t0 + (o.pausedAfterMs ?? 0), reason: "reconcile mismatch" }, pendingResume: { pauseSeq: markerSeq, at: t0 } }),
      },
      page: async (s, b) => { pages.push(s); bodies.push(b); }, now: () => t0 + ageMin * 60_000,
    }).catch((e: Error) => `error: ${e.message}`); // (a paused DB goes on to the resume steps, stubbed to throw)
    return { out, pages, bodies, repaused: calls.some((q) => /mr_tamper_pause/.test(q)) };
  };
  it("marker = current seq, older than 15 min: pages 'observation stuck', never mr_tamper_pause (no backoff loop)", async () => {
    for (let tick = 0; tick < 3; tick++) {
      const r = await run(7, 7, 20 + tick);
      expect(r.repaused).toBe(false);
      expect(r.pages).toEqual(["[resume] verifier observation stuck (not re-pausing)"]);
      expect(r.out).toBe("running");
    }
  });
  it("R65-P3-2: a verifier pause newer than the marker is mirrored at once; the stuck page needs an unpaused DB and names the reason", async () => {
    for (const age of [5, 20]) {
      const r = await run(7, 7, age, { pausedAfterMs: 60_000 });
      expect(r.repaused).toBe(true);
      expect(r.pages).toEqual(["[resume] DB pause recorded (verifier pause mirrored)"]);
    }
    const stuck = await run(7, 7, 20);
    expect(stuck.bodies[0]).toMatch(/verifier pause: reconcile mismatch/);
    const dbPaused = await run(7, 7, 20, { dbPaused: true });
    expect(dbPaused.pages.filter((p) => /stuck|mirrored/.test(p))).toEqual([]);
    expect(dbPaused.repaused).toBe(false);
  });
  it("marker younger than 15 min: silent wait; marker for an OLDER pause: the verifier pause is mirrored", async () => {
    const young = await run(7, 7, 5);
    expect(young.repaused).toBe(false);
    expect(young.pages).toEqual([]);
    const old = await run(6, 7, 20);
    expect(old.repaused).toBe(true);
    expect(old.pages).toEqual(["[resume] DB pause recorded (verifier pause mirrored)"]);
  });
});
