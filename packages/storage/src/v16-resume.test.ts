/** v16: automatic tamper pause / 2-of-2 resume with backoff, and DB-enforced caps, on real Postgres 18 + mr_ed25519. */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import path from "node:path";
import { promisify } from "node:util";
import algosdk from "algosdk";
import pg from "pg";
import { TESTNET_PROFILE, toMicro } from "@mandaterail/core";
import { migratePostgres, PgSpendStore } from "./pg.js";
import { PG_URL, seedTestProviders } from "./test-helpers.js";
import { encodeAttestation, isoSeconds, keyIdOf, type AttestBody } from "./attest.js";
import { encodeCosign, type CosignBody } from "./cosign.js";
import { encodeResume, encodeResumeCosign, type ResumeBody, type ResumeCosignBody } from "./resume.js";
import { tamperCooldownS } from "./v16-resume.js";
import { driftStatus, pauseFacts, pauseReasons } from "./spend-ops.js";
import { integrityReasons, loadIntegrityManifest } from "./monitor.js";

const run = promisify(execFile);
const SQL = path.resolve(__dirname, "../../../deploy/sql/t11-mr-reconcile-role.sql");
const TN = TESTNET_PROFILE.caip2.slice(9);
const REL8 = "SELECT * FROM mr_spend_release_attested($1, $2, $3, $4, $5, $6, 'auto', 'test release')";
const RESUME = "SELECT * FROM mr_tamper_resume($1, $2, $3, $4)";
const key = () => { const { publicKey, privateKey } = generateKeyPairSync("ed25519"); const pub = new Uint8Array(publicKey.export({ format: "der", type: "spki" }).subarray(12)); return { pub, priv: privateKey, keyId: keyIdOf(pub) }; };
const payer = algosdk.generateAccount(), merchant = algosdk.generateAccount();
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
let own: pg.Pool, rel: pg.Pool, mon: pg.Pool, admin: pg.Pool;
const prim = key(), co = key(), sameProv = key();
let n = 0, dbName = "";

describe.skipIf(!PG_URL)("v16 automatic resume + DB caps [postgres]", () => {
  beforeAll(async () => {
    admin = new pg.Pool({ connectionString: PG_URL, max: 2 });
    dbName = `mr_v16_${randomBytes(4).toString("hex")}`;
    await admin.query(`CREATE DATABASE ${dbName}`);
    const url = PG_URL!.replace(/\/[^/]*$/, `/${dbName}`);
    own = new pg.Pool({ connectionString: url, max: 4 });
    await migratePostgres(own, { network: "testnet", verifyNetwork: async (p) => ({ genesisHash: p.caip2.slice(9) }) });
    await seedTestProviders(own);
    await run("psql", ["-X", "-q", "-v", "ON_ERROR_STOP=1", "-v", "pw=t-rec-pw", "-v", "mon_pw=t-mon-pw", "-v", "rel_pw=t-rel-pw", "-d", url, "-f", SQL]);
    const u = new URL(url); u.username = "mr_release"; u.password = "t-rel-pw";
    rel = new pg.Pool({ connectionString: u.toString(), max: 2 }); rel.on("error", () => undefined);
    const m = new URL(url); m.username = "mr_monitor"; m.password = "t-mon-pw";
    mon = new pg.Pool({ connectionString: m.toString(), max: 1 }); mon.on("error", () => undefined);
    await own.query("INSERT INTO mr_signer_key (key_id, pubkey, network, margin_rounds, trust_domain, key_resource) VALUES ($1, $2, 'testnet', 10, 'gcp:mr-signer-test', 'projects/mr-signer-test/locations/us-east1/keyRings/mr/cryptoKeys/attest/cryptoKeyVersions/1')", [prim.keyId, Buffer.from(prim.pub)]);
    await own.query("INSERT INTO mr_cosigner_key (key_id, pubkey, network, trust_domain, key_resource) VALUES ($1, $2, 'testnet', 'aws:000000000000', 'arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000')", [co.keyId, Buffer.from(co.pub)]);
    await own.query("INSERT INTO mr_cosigner_key (key_id, pubkey, network, trust_domain, key_resource) VALUES ($1, $2, 'testnet', 'gcp:other-project', 'projects/other-project/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1')", [sameProv.keyId, Buffer.from(sameProv.pub)]);
    await own.query("UPDATE mr_release_quorum SET required_m = 2 WHERE network = 'testnet'");
    await own.query("SELECT mr_set_tamper_cooldown_base(3)"); // test only; MainNet CHECK >= 6 h (R66-P3-1: setter only)
  });
  afterAll(async () => { await rel?.end(); await mon?.end(); await own?.end(); if (dbName) await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`); await admin?.end(); });

  const asWriter = async (q: string) => {
    const c = await own.connect();
    try { await c.query("BEGIN"); await c.query("SET LOCAL ROLE mr_pause_writer"); await c.query(q); await c.query("COMMIT"); }
    catch (e) { await c.query("ROLLBACK"); throw e; } finally { c.release(); }
  };
  const windowed = async (q: string) => { // a superuser run inside the t11 deploy window (mr.ddl_window = open)
    const c = await own.connect();
    try { await c.query("BEGIN"); await c.query("SET LOCAL mr.ddl_window = 'open'"); await c.query(q); await c.query("COMMIT"); }
    catch (e) { await c.query("ROLLBACK"); throw e; } finally { c.release(); }
  };
  const state = async () => (await own.query("SELECT paused, pause_seq::int AS seq, tamper_count AS cnt FROM mr_pause_state WHERE network = 'testnet'")).rows[0] as { paused: boolean; seq: number; cnt: number };
  function quorum(o: { seq: number; cnt: number }, a: Partial<ResumeBody> = {}, c: Partial<ResumeCosignBody> = {}, ck = co) {
    const now = Date.now();
    const sb: ResumeBody = { v: 1, network: "testnet", genesisHash: TN, keyId: prim.keyId, pauseSeq: o.seq, tamperCount: o.cnt, chainSeq: 42, chainHead: "ab".repeat(32),
      nonce: randomBytes(32).toString("base64url"), issuedAt: isoSeconds(now), expiry: isoSeconds(now + 300_000), ...a };
    const sm = encodeResume(sb);
    const cb: ResumeCosignBody = { v: 1, network: "testnet", genesisHash: TN, keyId: ck.keyId, attestHash: createHash("sha256").update(sm).digest("hex"), pauseSeq: sb.pauseSeq,
      chainSeq: sb.chainSeq, chainHead: sb.chainHead, nonce: randomBytes(32).toString("base64url"), issuedAt: isoSeconds(now), expiry: isoSeconds(now + 300_000), ...c };
    const cm = encodeResumeCosign(cb);
    return [sm, sign(null, sm, prim.priv), cm, sign(null, cm, ck.priv)] as Buffer[];
  }

  async function spend(amount = "0.01") {
    const store = `v16-${++n}`;
    const s = new PgSpendStore(own, { store });
    const amt = toMicro(amount);
    await s.reserve({ id: "a", payer: payer.addr.toString(), amountMicro: amt, caps: { perPaymentMicro: toMicro("100"), perDayMicro: toMicro("500") }, nowMs: Date.now() });
    const t = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({ sender: payer.addr, receiver: merchant.addr, amount: amt, assetIndex: 10458941,
      suggestedParams: { fee: 1000n, minFee: 1000n, firstValid: 100n, lastValid: 1100n, genesisHash: Buffer.from(TN, "base64"), genesisID: "testnet-v1.0", flatFee: true } });
    const d = await s.attachSignedTxn("a", { signedTxn: t.signTxn(payer.sk), kind: "xpayment", payer: payer.addr.toString(), submitRound: 1100, nowMs: Date.now() } as never);
    await s.finalize("a", "ambiguous", Date.now());
    await sleep(1100);
    const now = Date.now();
    const body: AttestBody = { v: 1, network: "testnet", genesisHash: TN, keyId: prim.keyId, store, spendId: "a", txId: d!.txId, sender: payer.addr.toString(), groupId: "",
      firstValid: 100, lastValid: 1100, round: 1200, nonce: randomBytes(32).toString("base64url"), expiry: isoSeconds(now + 300_000),
      observations: [
        { at: isoSeconds(now), idxRound: 1200, method: "idx404", operator: "test-op-a", provider: "idx-a.example", round: 1200 },
        { at: isoSeconds(now), idxRound: 1100, method: "blockscan", operator: "test-op-b", provider: "algod-b.example", round: 1201 },
      ] };
    const m = encodeAttestation(body);
    const cb: CosignBody = { v: 1, network: "testnet", genesisHash: TN, keyId: co.keyId, attestHash: createHash("sha256").update(m).digest("hex"), store, spendId: "a",
      txId: d!.txId, lastValid: 1100, round: 1205, nonce: randomBytes(32).toString("base64url"), expiry: isoSeconds(now + 300_000),
      observations: [{ at: isoSeconds(now), idxRound: 1205, method: "idx404", operator: "test-op-c", provider: "idx-c.example", round: 1205 }] };
    const cm = encodeCosign(cb);
    return [store, "a", m, sign(null, m, prim.priv), cm, sign(null, cm, co.priv)] as Buffer[];
  }

  it("backoff mirror: 6 h, 12 h, 24 h ... capped", () => {
    expect([1, 2, 3, 4, 7, 20].map((c) => tamperCooldownS(21_600, c) / 3600)).toEqual([6, 12, 24, 48, 384, 384]);
  });

  it("a tamper pause blocks releases; nothing but a fresh 2-of-2 after the cooldown lifts it; backoff doubles; counter persisted", async () => {
    const p = (await mon.query("SELECT * FROM mr_tamper_pause('test: chain mismatch')")).rows[0];
    expect(p).toMatchObject({ pause_seq: "1", tamper_count: 1 });
    expect((await mon.query("SELECT * FROM mr_tamper_pause('second detector')")).rows[0].tamper_count).toBe(1); // idempotent while paused
    await expect(rel.query(REL8, await spend())).rejects.toThrow(/paused \(tamper\/integrity: test: chain mismatch\)/);
    // no hand unpause: not mr_release, not even the owner
    await expect(rel.query("UPDATE mr_pause_state SET paused = false")).rejects.toThrow(/permission denied/);
    await expect(own.query("UPDATE mr_pause_state SET paused = false")).rejects.toThrow(/only through mr_tamper_pause \/ mr_tamper_resume/);
    await expect(own.query("UPDATE mr_pause_state SET tamper_count = 0")).rejects.toThrow(/only through/);
    let s = await state();
    // cooldown (3 s base in this test DB)
    await expect(rel.query(RESUME, quorum(s))).rejects.toThrow(/cooldown not over/);
    await sleep(3100);
    // every quorum defect
    await expect(rel.query(RESUME, quorum(s, { pauseSeq: 0 }))).rejects.toThrow(/not for the current pause/);
    await expect(rel.query(RESUME, quorum(s, { tamperCount: 9 }))).rejects.toThrow(/not for the current pause/);
    await expect(rel.query(RESUME, quorum(s, {}, { chainHead: "cd".repeat(32) }))).rejects.toThrow(/chain checks disagree/);
    await expect(rel.query(RESUME, quorum(s, {}, { attestHash: "0".repeat(64) }))).rejects.toThrow(/not bound/);
    await expect(rel.query(RESUME, quorum(s, {}, {}, sameProv))).rejects.toThrow(/different trust domains/);
    await expect(rel.query(RESUME, quorum(s, { issuedAt: isoSeconds(Date.now() - 120_000) }))).rejects.toThrow(/issuedAt not within 60 s/);
    const q = quorum(s);
    const bad = Buffer.from(q[3]); bad[0]! ^= 1;
    await expect(rel.query(RESUME, [q[0], q[1], q[2], bad])).rejects.toThrow(/verifier signature does not verify/);
    await expect(rel.query(RESUME, [q[0], q[1], q[0], q[1]])).rejects.toThrow(/prefix/); // the signer alone can't be both
    expect((await rel.query(RESUME, q)).rows[0]).toEqual({ resumed: true, pause_seq: "1" });
    await expect(rel.query(RESUME, q)).rejects.toThrow(/not paused/);
    expect((await rel.query(REL8, await spend())).rows[0]).toEqual({ ok: true, from_status: "ambiguous" });
    // second tamper: count 2, cooldown doubles (6 s); the old quorum (seq 1) can't be replayed
    await rel.query("SELECT * FROM mr_tamper_pause('test: manifest drift')");
    s = await state();
    expect(s).toEqual({ paused: true, seq: 2, cnt: 2 });
    await expect(rel.query(RESUME, q)).rejects.toThrow(/cooldown not over|not for the current pause/);
    await sleep(3500);
    await expect(rel.query(RESUME, quorum(s))).rejects.toThrow(/cooldown not over/); // 3 s would have been enough for tamper 1
    await sleep(2700);
    await expect(rel.query(RESUME, [q[0], q[1], q[2], q[3]])).rejects.toThrow(/not for the current pause/);
    const q2 = quorum(s, { nonce: JSON.parse(q[0].toString().slice(20)).nonce });
    await expect(rel.query(RESUME, q2)).rejects.toThrow(/nonce replay/);
    expect((await rel.query(RESUME, quorum(s))).rows[0].resumed).toBe(true);
    expect((await state()).cnt).toBe(2); // persisted, never reset by a resume
  });

  it("caps are enforced in the DB: per release and rolling 24 h amount; owner-only and audited", async () => {
    // R64-P2-1: caps belong to mr_pause_writer; a change is a superuser migration acting as that role
    await expect(own.query("UPDATE mr_release_caps SET max_release_micro = 30000, max_day_micro = 60000 WHERE network = 'testnet'")).rejects.toThrow(/owner only/);
    await asWriter("UPDATE mr_release_caps SET max_release_micro = 30000, max_day_micro = 60000 WHERE network = 'testnet'");
    expect((await own.query("SELECT op, tbl FROM mr_config_audit WHERE tbl = 'mr_release_caps' ORDER BY seq DESC LIMIT 1")).rows[0]).toEqual({ op: "UPDATE", tbl: "mr_release_caps" });
    await expect(rel.query(REL8, await spend("0.04"))).rejects.toThrow(/above the per-release cap/);
    // 0.01 released in the previous test; + 0.03 + 0.03 > 0.06
    expect((await rel.query(REL8, await spend("0.03"))).rows[0].ok).toBe(true);
    await expect(rel.query(REL8, await spend("0.03"))).rejects.toThrow(/rolling 24 h released amount would be/);
    await expect(rel.query("UPDATE mr_release_caps SET max_day_micro = 999999999")).rejects.toThrow(/permission denied/);
    await expect(own.query("DELETE FROM mr_release_caps")).rejects.toThrow(/refused/);
    await expect(own.query("DELETE FROM mr_config_audit")).rejects.toThrow(/refused/);
    await expect(own.query("UPDATE mr_pause_state SET base_cooldown_s = 60 WHERE network = 'mainnet'")).rejects.toThrow(/only through mr_tamper_pause \/ mr_tamper_resume \/ mr_set_tamper_cooldown_base/);
    await expect(rel.query("SELECT * FROM mr_spend_release_attested_v12($1, $2, $3, $4, $5, $6, 'x', 'y')", await spend())).rejects.toThrow(/permission denied/);
  });

  it("R62-P2-1: the old SET LOCAL mr.v16_fn bypass no longer unpauses; a forged unpause / rolled-back counter / disabled guard pages", async () => {
    await mon.query("SELECT * FROM mr_tamper_pause('test: R62 bypass attempt')");
    const s = await state();
    expect(s.paused).toBe(true);
    // the run-62 reproduction: an owner session sets the GUC the functions used to set, then unpauses by hand
    const c = await own.connect();
    try {
      await c.query("BEGIN");
      await c.query("SET LOCAL mr.v16_fn = 'on'");
      await expect(c.query("UPDATE mr_pause_state SET paused = false, resumed_at = now() WHERE network = 'testnet'")).rejects.toThrow(/only through mr_tamper_pause \/ mr_tamper_resume/);
      await c.query("ROLLBACK");
      await c.query("BEGIN");
      await c.query("SELECT set_config('mr.v16_fn', 'on', true)");
      await expect(c.query("INSERT INTO mr_resume_nonce (nonce, network, pause_seq, role, tamper_count, key_id, msg, sig) VALUES ($1, 'testnet', $2, 'signer', $3, 'k', '\\x00', $4)", [randomBytes(32), s.seq, s.cnt, randomBytes(64)])).rejects.toThrow(/written only by/);
      await c.query("ROLLBACK");
      // the owner can't become the writer role or replace its functions (a superuser test owner can; skip then)
      const sup = (await c.query("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")).rows[0].rolsuper as boolean;
      if (!sup) await expect(c.query("SET ROLE mr_pause_writer")).rejects.toThrow(/permission denied/);
      if (!sup) await expect(c.query("CREATE OR REPLACE FUNCTION mr_tamper_resume(p_smsg bytea, p_ssig bytea, p_cmsg bytea, p_csig bytea) RETURNS TABLE (resumed boolean, pause_seq bigint) LANGUAGE sql AS 'SELECT true, 0::bigint'")).rejects.toThrow(/must be owner/);
    } finally { c.release(); }
    expect((await state()).paused).toBe(true);
    expect(pauseReasons(await pauseFacts(mon))).toEqual([]);
    // what the monitor sees if the guard is disabled and the row edited (the owner can do that; it is drift + pages)
    // (R63: DDL on the pause objects needs a superuser with the t11 window open; the test owner is a superuser)
    const w = await own.connect();
    await w.query("SET mr.ddl_window = 'open'");
    await w.query("ALTER TABLE mr_pause_state DISABLE TRIGGER mr_pause_state_guard");
    await w.query("UPDATE mr_pause_state SET paused = false, tamper_count = tamper_count - 1 WHERE network = 'testnet'");
    const { integrityStatus } = await import("./spend-ops.js");
    const st = await integrityStatus(mon);
    expect(st.triggers["mr_pause_state.mr_pause_state_guard"]).toBe("D");
    const why = pauseReasons(st.pause);
    expect(why).toEqual(expect.arrayContaining([expect.stringMatching(/unpaused without the 2-of-2 resume/), expect.stringMatching(/tamper_count changed outside mr_tamper_pause/)]));
    await w.query("UPDATE mr_pause_state SET pause_seq = pause_seq - 1 WHERE network = 'testnet'");
    expect(pauseReasons(await pauseFacts(mon))).toEqual(expect.arrayContaining([expect.stringMatching(/pause_seq went down/)]));
    // restore (test DB only) so later tests see a consistent row
    await w.query("UPDATE mr_pause_state SET paused = true, pause_seq = pause_seq + 1, tamper_count = tamper_count + 1 WHERE network = 'testnet'");
    await w.query("ALTER TABLE mr_pause_state ENABLE TRIGGER mr_pause_state_guard");
    await w.query("RESET mr.ddl_window");
    w.release();
    expect(pauseReasons(await pauseFacts(mon))).toEqual([]);
  });

  it("R62-P3-1: a release under REPEATABLE READ / SERIALIZABLE is refused (the 24 h sum is only race-free under READ COMMITTED)", async () => {
    const c = await rel.connect();
    try {
      for (const iso of ["REPEATABLE READ", "SERIALIZABLE"]) {
        const args = await spend();
        await c.query(`BEGIN ISOLATION LEVEL ${iso}`);
        await expect(c.query(REL8, args)).rejects.toThrow(/must run under READ COMMITTED/);
        await c.query("ROLLBACK");
      }
    } finally { c.release(); }
  });

  it("R63-P2-1: the deploy-window forged unpause (DISABLE TRIGGER + fake nonces + unpause, one txn) is refused, and a superuser forgery is paged", async () => {
    // the pause objects belong to the member-less NOLOGIN mr_pause_writer, not to the app owner
    const owners = (await own.query("SELECT tablename, tableowner FROM pg_tables WHERE tablename IN ('mr_pause_state', 'mr_resume_nonce', 'mr_pause_log') ORDER BY 1")).rows;
    expect(owners.map((r) => r.tableowner)).toEqual(["mr_pause_writer", "mr_pause_writer", "mr_pause_writer"]);
    const fnOwners = (await own.query("SELECT DISTINCT pg_get_userbyid(proowner) AS o FROM pg_proc WHERE proname IN ('mr_tamper_pause', 'mr_tamper_resume', 'mr_v16_guard', 'mr_v16_parse', 'mr_v16_cooldown', 'mr_jcs')")).rows;
    expect(fnOwners).toEqual([{ o: "mr_pause_writer" }]);
    expect((await own.query("SELECT count(*)::int AS n FROM pg_auth_members WHERE roleid = 'mr_pause_writer'::regrole")).rows[0].n).toBe(0);
    if ((await state()).paused === false) await mon.query("SELECT * FROM mr_tamper_pause('test: R63 attack')");
    const s = await state();
    const forge = async (c: pg.PoolClient) => {
      await c.query("BEGIN");
      await c.query("ALTER TABLE mr_pause_state DISABLE TRIGGER mr_pause_state_guard");
      await c.query("ALTER TABLE mr_resume_nonce DISABLE TRIGGER mr_resume_nonce_guard");
      for (const role of ["signer", "verifier"]) {
        await c.query("INSERT INTO mr_resume_nonce (nonce, network, pause_seq, role, tamper_count, key_id, msg, sig) VALUES ($1, 'testnet', $2, $3, $4, $5, $6, $7)",
          [randomBytes(32), s.seq, role, s.cnt, role === "signer" ? prim.keyId : co.keyId, Buffer.from("MR-RESUME-ATTEST-v1\n{}"), randomBytes(64)]);
      }
      await c.query("UPDATE mr_pause_state SET paused = false, resumed_at = now() WHERE network = 'testnet'");
      await c.query("ALTER TABLE mr_pause_state ENABLE TRIGGER mr_pause_state_guard");
      await c.query("ALTER TABLE mr_resume_nonce ENABLE TRIGGER mr_resume_nonce_guard");
      await c.query("COMMIT");
    };
    // 1. without the superuser t11 window (the app owner's case, and any session that has not opened it): refused
    const c1 = await own.connect();
    try {
      await expect(forge(c1)).rejects.toThrow(/mr_v16_ddl_guard: ALTER TABLE on public\.mr_pause_state refused|must be owner/);
      await c1.query("ROLLBACK");
    } finally { c1.release(); }
    expect((await state()).paused).toBe(true);
    expect(pauseReasons(await pauseFacts(mon))).toEqual([]);
    // 2. a superuser who opens the window CAN forge the rows, but can't forge the keys: the monitor re-verifies and pages
    const c2 = await own.connect();
    try { await c2.query("SET mr.ddl_window = 'open'"); await forge(c2); await c2.query("RESET mr.ddl_window"); } finally { c2.release(); }
    expect((await state()).paused).toBe(false);
    const why = pauseReasons(await pauseFacts(mon));
    expect(why).toEqual(expect.arrayContaining([expect.stringMatching(/forged or broken resume record: pause_seq \d+: signer resume signature does not verify/), expect.stringMatching(/verifier resume signature does not verify/)]));
    // the event trigger itself: disabling it pages too
    const c3 = await own.connect();
    try {
      await c3.query("ALTER EVENT TRIGGER mr_v16_ddl_guard DISABLE");
      expect(pauseReasons(await pauseFacts(mon))).toEqual(expect.arrayContaining([expect.stringMatching(/event trigger mr_v16_ddl_guard is not enabled/)]));
      await c3.query("ALTER EVENT TRIGGER mr_v16_ddl_guard ENABLE");
    } finally { c3.release(); }
  });

  it("R64-P2-1: caps / audit / release wrapper belong to mr_pause_writer; DISABLE+UPDATE+ENABLE and audit wipes are refused; MainNet caps bounded; caps drift pages", async () => {
    const tbl = (await own.query("SELECT tablename AS t, tableowner AS o FROM pg_tables WHERE tablename IN ('mr_release_caps', 'mr_config_audit', 'mr_release_cosign') ORDER BY 1")).rows;
    expect(tbl).toEqual([{ t: "mr_config_audit", o: "mr_pause_writer" }, { t: "mr_release_caps", o: "mr_pause_writer" }, { t: "mr_release_cosign", o: "mr_pause_writer" }]);
    const fns = (await own.query("SELECT p.oid::regprocedure::text AS f, pg_get_userbyid(p.proowner) AS o FROM pg_proc p WHERE p.proname IN ('mr_spend_release_attested', 'mr_spend_release_attested_v12', 'mr_v16_audit') AND pronargs IN (4, 8) ORDER BY 1")).rows;
    expect(fns.map((r) => r.o)).toEqual(["mr_pause_writer", "mr_pause_writer", "mr_pause_writer"]);
    expect(pauseReasons(await pauseFacts(mon))).not.toEqual(expect.arrayContaining([expect.stringMatching(/owned by|is missing/)]));
    const before = (await own.query("SELECT count(*)::int AS n FROM mr_config_audit")).rows[0].n;
    const caps0 = (await own.query("SELECT max_release_micro::text AS r, max_day_micro::text AS d FROM mr_release_caps WHERE network = 'testnet'")).rows[0];
    const probes: Array<[string, string[]]> = [
      ["caps", ["ALTER TABLE mr_release_caps DISABLE TRIGGER mr_release_caps_guard", "UPDATE mr_release_caps SET max_day_micro = 999999999999 WHERE network = 'testnet'", "ALTER TABLE mr_release_caps ENABLE TRIGGER mr_release_caps_guard"]],
      ["audit", ["ALTER TABLE mr_config_audit DISABLE TRIGGER mr_config_audit_guard", "DELETE FROM mr_config_audit", "ALTER TABLE mr_config_audit ENABLE TRIGGER mr_config_audit_guard"]],
      ["audit-truncate", ["ALTER TABLE mr_config_audit DISABLE TRIGGER mr_config_audit_guard_t", "TRUNCATE mr_config_audit", "ALTER TABLE mr_config_audit ENABLE TRIGGER mr_config_audit_guard_t"]],
      ["drop", ["DROP TABLE mr_config_audit"]],
      ["wrapper", ["CREATE OR REPLACE FUNCTION mr_spend_release_attested(p_store text, p_id text, p_msg bytea, p_sig bytea, p_cmsg bytea, p_csig bytea, p_label text, p_reason text) RETURNS TABLE (ok boolean, from_status text) LANGUAGE sql AS $$ SELECT true, 'x' $$"]],
    ];
    // a non-superuser stand-in for the app owner (holds what t11 leaves the owner: SELECT), and a superuser without the t11 window
    await own.query("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mr_r64_owner') THEN CREATE ROLE mr_r64_owner NOLOGIN; END IF; END $$");
    await windowed("GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON mr_release_caps, mr_config_audit TO mr_r64_owner");
    for (const as of ["SET LOCAL ROLE mr_r64_owner", "RESET mr.ddl_window"]) {
      for (const [name, stmts] of probes) {
        const c = await own.connect();
        try {
          await c.query("BEGIN"); await c.query(as);
          let err = "";
          try { for (const q of stmts) await c.query(q); } catch (e) { err = (e as Error).message; }
          expect(err, `${as}: ${name}`).toMatch(/must be owner|permission denied for schema public|mr_v16_ddl_guard: .* refused|refused|owner only/);
          await c.query("ROLLBACK");
        } finally { c.release(); }
      }
    }
    await own.query("REVOKE ALL ON mr_release_caps, mr_config_audit FROM mr_r64_owner; DROP ROLE mr_r64_owner");
    expect((await own.query("SELECT count(*)::int AS n FROM mr_config_audit")).rows[0].n).toBe(before);
    expect((await own.query("SELECT max_release_micro::text AS r, max_day_micro::text AS d FROM mr_release_caps WHERE network = 'testnet'")).rows[0]).toEqual(caps0);
    // MainNet upper bound: even the legitimate writer path can't raise it
    await expect(asWriter("UPDATE mr_release_caps SET max_release_micro = 10001 WHERE network = 'mainnet'")).rejects.toThrow(/mr_release_caps_mainnet_max/);
    await expect(asWriter("UPDATE mr_release_caps SET max_day_micro = 50001 WHERE network = 'mainnet'")).rejects.toThrow(/mr_release_caps_mainnet_max/);
    // caps that differ from the manifest page (this test DB runs testnet 30000/60000 since the caps test)
    const d = await driftStatus(mon);
    const want = { network: "testnet", genesisHash: TN };
    const why = integrityReasons({ triggers: {}, marker: want, drift: d } as unknown as Parameters<typeof integrityReasons>[0], want, [],
      { providersHash: d.providersHash, functions: d.functions, aclHash: d.aclHash, releaseCaps: loadIntegrityManifest({}).releaseCaps });
    expect(why).toEqual(expect.arrayContaining([expect.stringMatching(/release caps drift for testnet \(mr_release_caps 30000\/60000, pinned 10000000\/50000000\)/)]));
    expect(why.filter((w) => /release caps drift for mainnet/.test(w))).toEqual([]);
  });

  it("R65-P2-1 / R65-P3: the owner can't reset the day cap via mr_release_nonce, a granted _v11 can't release, the 6-arg TestNet path works, the ledger is cross-checked", async () => {
    const L = "SELECT * FROM mr_spend_release_attested_v11($1, $2, $3, $4, 'auto', 'test release')";
    const REL6 = "SELECT * FROM mr_spend_release_attested($1, $2, $3, $4, 'auto', 'test release')";
    // a. GRANT EXECUTE on _v11 to mr_release (the table owner may grant what it owns): releasing through it is refused
    // run 66 optional: outside the superuser deploy window the GRANT itself is refused by the DDL guard
    await expect(own.query("GRANT EXECUTE ON FUNCTION mr_spend_release_attested_v11(text, text, bytea, bytea, text, text) TO mr_release")).rejects.toThrow(/mr_v16_ddl_guard: GRANT/);
    await expect(own.query("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO mr_release")).rejects.toThrow(/mr_v16_ddl_guard: GRANT/);
    // R67-P3-1: the ACL is the authority, not the text: a quoted name, a DO/EXECUTE concat and a REVOKE are refused too
    await expect(own.query('GRANT EXECUTE ON FUNCTION public."mr_spend_release_attested_v11"(text, text, bytea, bytea, text, text) TO mr_release')).rejects.toThrow(/mr_v16_ddl_guard: GRANT changes the ACL/);
    await expect(own.query("DO $$ BEGIN EXECUTE 'GRANT EXECUTE ON FUNCTION mr_spend_' || 'release_attested_v11(text, text, bytea, bytea, text, text) TO mr_release'; END $$")).rejects.toThrow(/mr_v16_ddl_guard: GRANT changes the ACL/);
    await expect(own.query("GRANT SELECT ON \"mr_release_ledger\" TO mr_demo_api")).rejects.toThrow(/mr_v16_ddl_guard: GRANT changes the ACL/);
    await expect(own.query("REVOKE SELECT ON mr_release_ledger FROM mr_monitor")).rejects.toThrow(/mr_v16_ddl_guard: REVOKE changes the ACL/);
    expect((await own.query("SELECT has_function_privilege('mr_release', 'mr_spend_release_attested_v11(text, text, bytea, bytea, text, text)', 'EXECUTE') AS x")).rows[0].x).toBe(false);
    expect((await own.query("SELECT (SELECT fp FROM mr_v16_acl_pin) = mr_v16_acl_fp() AS x")).rows[0].x).toBe(true);
    // a GRANT on an unprotected object still works
    await own.query("CREATE TABLE IF NOT EXISTS r67_unprotected (x int)"); await own.query("GRANT SELECT ON r67_unprotected TO mr_monitor"); await own.query("DROP TABLE r67_unprotected");
    await windowed("GRANT EXECUTE ON FUNCTION mr_spend_release_attested_v11(text, text, bytea, bytea, text, text) TO mr_release");
    const w = await spend("0.01");
    await expect(rel.query(L, w.slice(0, 4))).rejects.toThrow(/was not counted by mr_spend_release_attested \(caps ledger\)/);
    await own.query("REVOKE EXECUTE ON FUNCTION mr_spend_release_attested_v11(text, text, bytea, bytea, text, text) FROM mr_release");
    // b. a non-superuser owner of mr_release_nonce: DISABLE TRIGGER / TRUNCATE / ENABLE in one txn is refused
    await own.query("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mr_r65_owner') THEN CREATE ROLE mr_r65_owner NOLOGIN; END IF; END $$");
    const reown = async (to: string) => {
      const c = await own.connect();
      try { await c.query("SET mr.ddl_window = 'open'"); await c.query(`ALTER TABLE mr_release_nonce OWNER TO ${to}`); await c.query("RESET mr.ddl_window"); } finally { c.release(); }
    };
    const ownerWas = (await own.query("SELECT tableowner AS o FROM pg_tables WHERE tablename = 'mr_release_nonce'")).rows[0].o as string;
    await reown("mr_r65_owner");
    const nonces = (await own.query("SELECT count(*)::int AS n FROM mr_release_nonce")).rows[0].n;
    for (const as of ["SET LOCAL ROLE mr_r65_owner", "RESET mr.ddl_window"]) {
      for (const stmts of [["ALTER TABLE mr_release_nonce DISABLE TRIGGER USER", "TRUNCATE mr_release_nonce", "ALTER TABLE mr_release_nonce ENABLE TRIGGER USER"],
                           ["ALTER TABLE mr_release_nonce DISABLE TRIGGER mr_release_nonce_ledger"], ["DROP TRIGGER mr_release_nonce_ledger ON mr_release_nonce"], ["TRUNCATE mr_release_nonce"]]) {
        const c = await own.connect();
        try {
          await c.query("BEGIN"); await c.query(as);
          let err = "";
          try { for (const q of stmts) await c.query(q); } catch (e) { err = (e as Error).message; }
          expect(err, `${as}: ${stmts[0]}`).toMatch(/mr_v16_ddl_guard: .* refused|refused|must be owner/);
          await c.query("ROLLBACK");
        } finally { c.release(); }
      }
    }
    await reown(ownerWas);
    await own.query("DROP ROLE mr_r65_owner");
    expect((await own.query("SELECT count(*)::int AS n FROM mr_release_nonce")).rows[0].n).toBe(nonces);
    // c. R65-P3: the 6-arg TestNet entry runs as mr_pause_writer (non-superuser) and reaches the 8-arg wrapper's quorum
    //    check (it was owned by the app owner, which has no EXECUTE on the writer-owned wrapper: permission denied on a host)
    expect((await own.query("SELECT pg_get_userbyid(proowner) AS o FROM pg_proc WHERE oid = 'mr_spend_release_attested(text, text, bytea, bytea, text, text)'::regprocedure")).rows[0].o).toBe("mr_pause_writer");
    await expect(rel.query(REL6, w.slice(0, 4))).rejects.toThrow(/testnet requires 2 attestations .*no co-signature given/);
    expect((await rel.query(REL8, w)).rows[0].ok).toBe(true);
    expect((await own.query("SELECT amount_micro::int AS a FROM mr_release_ledger WHERE store = $1", [w[0]!.toString()])).rows[0]).toEqual({ a: 10000 });
    expect(pauseReasons(await pauseFacts(mon)).filter((r) => /caps ledger/.test(r))).toEqual([]);
    // the ledger itself: owner / mr_release can't write or wipe it
    await expect(rel.query("INSERT INTO mr_release_ledger (store, spend_id, network, amount_micro) VALUES ('x', 'y', 'testnet', 1)")).rejects.toThrow(/permission denied/);
    await expect(own.query("DELETE FROM mr_release_ledger")).rejects.toThrow(/refused/);
    // d. even a superuser wiping mr_release_nonce (replica mode skips triggers) no longer resets the day cap, and pages
    const c = await own.connect();
    try { await c.query("SET session_replication_role = replica"); await c.query("DELETE FROM mr_release_nonce"); await c.query("RESET session_replication_role"); } finally { c.release(); }
    await expect(rel.query(REL8, await spend("0.03"))).rejects.toThrow(/rolling 24 h released amount would be/); // 0.05 ledgered + 0.03 > 0.06
    expect(pauseReasons(await pauseFacts(mon))).toEqual(expect.arrayContaining([expect.stringMatching(/caps ledger: \d+ ledgered release\(s\) have no mr_release_nonce row/)]));
  });

  it("R65-P3-1: mr_v16_audit only writes from inside the guard trigger (a direct call can't append audit rows)", async () => {
    const n0 = (await own.query("SELECT count(*)::int AS n FROM mr_config_audit")).rows[0].n;
    await expect(own.query("SELECT mr_v16_audit('mr_release_caps', 'UPDATE', NULL, '{}'::jsonb)")).rejects.toThrow(/only the v16 guard trigger writes mr_config_audit/);
    await expect(own.query("SELECT mr_v16_audit('mr_spend', 'INSERT', NULL, '{}'::jsonb)")).rejects.toThrow(/only the v16 guard trigger/);
    await asWriter("UPDATE mr_release_caps SET max_release_micro = max_release_micro WHERE network = 'testnet'"); // the trigger path still audits
    expect((await own.query("SELECT count(*)::int AS n FROM mr_config_audit")).rows[0].n).toBe(n0 + 1);
  });

  it("run 66 optional: a no-op release (_v12 ok = false) leaves no ledger row (savepoint, no DELETE)", async () => {
    const w = await spend("0.01");
    { // test setup: the row moved on (settled elsewhere) between attestation and release; replica mode skips the spend guard
      const c = await own.connect();
      try { await c.query("SET session_replication_role = replica"); await c.query("UPDATE mr_spend SET status = 'settled' WHERE store = $1 AND id = 'a'", [w[0]!.toString()]); await c.query("RESET session_replication_role"); }
      finally { c.release(); }
    }
    const before = (await own.query("SELECT count(*)::int AS n FROM mr_release_ledger")).rows[0].n;
    expect((await rel.query(REL8, w)).rows[0]).toEqual({ ok: false, from_status: "settled" });
    expect((await own.query("SELECT count(*)::int AS n FROM mr_release_ledger WHERE store = $1", [w[0]!.toString()])).rows[0].n).toBe(0);
    expect((await own.query("SELECT count(*)::int AS n FROM mr_release_ledger")).rows[0].n).toBe(before);
  });

  it("R66-P3-1: the owner holds no EXECUTE on mr_v16_audit, no UPDATE on mr_pause_state, no TEMPORARY; the cooldown base changes only via the writer-owned setter (alone, unpaused, audited)", async () => {
    const o = (await own.query("SELECT pg_get_userbyid(relowner) AS o FROM pg_class WHERE relname = 'mr_spend_audit' AND relnamespace = 'public'::regnamespace")).rows[0].o as string;
    const acl = (await own.query(
      `SELECT (SELECT array_agg(DISTINCT pg_get_userbyid(a.grantee)::text) FROM pg_proc p, aclexplode(p.proacl) a WHERE p.oid = 'mr_v16_audit(text,text,jsonb,jsonb)'::regprocedure) AS audit,
              (SELECT array_agg(DISTINCT pg_get_userbyid(a.grantee)::text) FROM pg_proc p, aclexplode(p.proacl) a WHERE p.oid = 'mr_set_tamper_cooldown_base(integer)'::regprocedure) AS setter,
              (SELECT pg_get_userbyid(proowner) FROM pg_proc WHERE oid = 'mr_set_tamper_cooldown_base(integer)'::regprocedure) AS setter_owner,
              (SELECT count(*)::int FROM information_schema.column_privileges WHERE table_name = 'mr_pause_state' AND grantee = $1 AND privilege_type = 'UPDATE') AS upd,
              EXISTS (SELECT 1 FROM aclexplode((SELECT datacl FROM pg_database WHERE datname = current_database())) a WHERE a.grantee = $1::regrole AND a.privilege_type = 'TEMPORARY') AS tmp`, [o])).rows[0];
    expect(acl.audit).not.toContain(o);
    expect(acl.setter.sort()).toEqual(["mr_pause_writer", o].sort());
    expect(acl).toMatchObject({ setter_owner: "mr_pause_writer", upd: 0, tmp: false });
    const n0 = (await own.query("SELECT count(*)::int AS n FROM mr_config_audit WHERE tbl = 'mr_pause_state'")).rows[0].n;
    await own.query("SELECT mr_set_tamper_cooldown_base(4)");
    expect((await own.query("SELECT base_cooldown_s FROM mr_pause_state WHERE network = 'testnet'")).rows[0].base_cooldown_s).toBe(4);
    const last = (await own.query("SELECT op, old_row->>'base_cooldown_s' AS a, new_row->>'base_cooldown_s' AS b FROM mr_config_audit WHERE tbl = 'mr_pause_state' ORDER BY seq DESC LIMIT 1")).rows[0];
    expect(last).toEqual({ op: "UPDATE", a: "3", b: "4" });
    expect((await own.query("SELECT count(*)::int AS n FROM mr_config_audit WHERE tbl = 'mr_pause_state'")).rows[0].n).toBe(n0 + 1);
    await own.query("SELECT mr_set_tamper_cooldown_base(3)");
    // a direct UPDATE (even a superuser session) and the writer changing the base together with pause fields are refused
    await expect(own.query("UPDATE mr_pause_state SET base_cooldown_s = 5 WHERE network = 'testnet'")).rejects.toThrow(/mr_set_tamper_cooldown_base/);
    await expect(asWriter("UPDATE mr_pause_state SET base_cooldown_s = 5, reason = 'x' WHERE network = 'testnet'")).rejects.toThrow(/pause state changes only through/);
    await expect(own.query("SELECT mr_set_tamper_cooldown_base(0)")).rejects.toThrow(/>= 1/);
    // never while paused (a shorter base would shorten the running cooldown)
    await rel.query("SELECT * FROM mr_tamper_pause('r66 setter test')");
    await expect(own.query("SELECT mr_set_tamper_cooldown_base(1)")).rejects.toThrow(/can not change while paused/);
  });

  it("R69-P3-2: ALTER DEFAULT PRIVILEGES refused outside the window; pg_default_acl is drift; the ACL pin has a DML guard; a missing / differing pin pages", async () => {
    expect(pauseReasons(await pauseFacts(mon)).filter((r) => /ACL pin|ACL fingerprint|acl_pin/.test(r))).toEqual([]);
    const ownerRole = (await own.query("SELECT tableowner AS o FROM pg_tables WHERE tablename = 'mr_spend_audit'")).rows[0].o as string;
    await expect(own.query(`ALTER DEFAULT PRIVILEGES FOR ROLE ${ownerRole} GRANT EXECUTE ON FUNCTIONS TO mr_release`)).rejects.toThrow(/ALTER DEFAULT PRIVILEGES refused/);
    await expect(own.query("ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO mr_monitor")).rejects.toThrow(/ALTER DEFAULT PRIVILEGES refused/);
    expect((await own.query("SELECT count(*)::int AS n FROM pg_default_acl")).rows[0].n).toBe(0);
    // inside the window it is possible (a deploy), and then the drift hash changes
    const before = (await driftStatus(own)).aclHash;
    await windowed("ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO mr_monitor");
    const d = await driftStatus(own);
    expect(d.aclHash).not.toBe(before);
    expect(d.aclText).toMatch(/^defacl \S+ r \S+ mr_monitor=SELECT/m);
    await windowed("ALTER DEFAULT PRIVILEGES REVOKE SELECT ON TABLES FROM mr_monitor");
    expect((await driftStatus(own)).aclHash).toBe(before);
    // DML guard: the superuser outside the window can't touch the pin
    await expect(own.query("UPDATE mr_v16_acl_pin SET fp = 'x'")).rejects.toThrow(/mr_v16_acl_pin_guard: UPDATE/);
    await expect(own.query("DELETE FROM mr_v16_acl_pin")).rejects.toThrow(/mr_v16_acl_pin_guard: DELETE/);
    await expect(own.query("TRUNCATE mr_v16_acl_pin")).rejects.toThrow(/mr_v16_acl_pin_guard: TRUNCATE/);
    // a rewritten pin pages (written inside the window), and a missing pin pages
    const pin = (await own.query("SELECT fp FROM mr_v16_acl_pin")).rows[0].fp as string;
    await windowed("UPDATE mr_v16_acl_pin SET fp = md5('r69')");
    expect(pauseReasons(await pauseFacts(mon))).toEqual(expect.arrayContaining([expect.stringMatching(/protected ACL fingerprint .* differs from the pin/)]));
    await windowed("DELETE FROM mr_v16_acl_pin");
    expect(pauseReasons(await pauseFacts(mon))).toEqual(expect.arrayContaining([expect.stringMatching(/ACL pin mr_v16_acl_pin is missing/)]));
    await windowed(`INSERT INTO mr_v16_acl_pin (id, fp) VALUES (true, '${pin}')`);
    // a disabled pin guard pages
    await windowed("ALTER TABLE mr_v16_acl_pin DISABLE TRIGGER mr_v16_acl_pin_guard");
    expect(pauseReasons(await pauseFacts(mon))).toEqual(expect.arrayContaining([expect.stringMatching(/mr_v16_acl_pin_guard on mr_v16_acl_pin is not enabled/)]));
    await windowed("ALTER TABLE mr_v16_acl_pin ENABLE TRIGGER mr_v16_acl_pin_guard");
    expect(pauseReasons(await pauseFacts(mon)).filter((r) => /ACL pin|ACL fingerprint|acl_pin/.test(r))).toEqual([]);
  });

  it("R70-P3-2: a superuser GRANT + repin clears the DB pin page but not the manifest-pinned fingerprint", async () => {
    const want = { network: "testnet", genesisHash: TN };
    const manifestFp = (await driftStatus(mon)).aclFp!; // stands in for the manifest value of this DB shape
    expect(manifestFp).toMatch(/^[0-9a-f]{32}$/);
    const why = async () => {
      const d = await driftStatus(mon);
      return integrityReasons({ triggers: {}, marker: want, drift: d, pause: await pauseFacts(mon) } as unknown as Parameters<typeof integrityReasons>[0], want, [],
        { providersHash: d.providersHash, functions: d.functions, aclHash: d.aclHash, aclFp: manifestFp }).filter((r) => /ACL|acl_pin/.test(r));
    };
    expect(await why()).toEqual([]);
    // the superuser path: change a protected ACL and repin (as replica mode or the window would allow)
    const pin = (await own.query("SELECT fp FROM mr_v16_acl_pin")).rows[0].fp as string;
    await windowed("GRANT SELECT ON mr_release_ledger TO mr_demo_api");
    await windowed("UPDATE mr_v16_acl_pin SET fp = mr_v16_acl_fp()");
    expect(pauseReasons(await pauseFacts(mon)).filter((r) => /ACL pin|ACL fingerprint|acl_pin/.test(r))).toEqual([]); // the R69 page is cleared
    const r = await why();
    expect(r).toEqual(expect.arrayContaining([expect.stringMatching(/protected ACL fingerprint .* differs from the manifest pin/), expect.stringMatching(/mr_v16_acl_pin .* differs from the manifest pin/)]));
    await windowed("REVOKE SELECT ON mr_release_ledger FROM mr_demo_api");
    await windowed(`UPDATE mr_v16_acl_pin SET fp = '${pin}'`);
    expect(await why()).toEqual([]);
  });

  it("R71-P3-2: the ACL fingerprint tells a NULL (default PUBLIC EXECUTE) function ACL from an empty '{}' one", async () => {
    const fp = async () => (await own.query("SELECT mr_v16_acl_fp() AS fp")).rows[0].fp as string;
    const sig = "public.mr_jcs(jsonb)";
    const orig = (await own.query(`SELECT proacl::text AS a FROM pg_proc WHERE oid = '${sig}'::regprocedure`)).rows[0]?.a as string | null | undefined;
    if (orig === undefined) return; // shape without mr_jcs(jsonb): nothing to probe
    const set = (v: string | null) => windowed(`UPDATE pg_catalog.pg_proc SET proacl = ${v === null ? "NULL" : `'${v}'`}::aclitem[] WHERE oid = '${sig}'::regprocedure`);
    try {
      await set("{}");
      const empty = await fp();
      await set(null);
      const dflt = await fp();
      expect(empty).not.toBe(dflt); // before R71 both rendered as '-'
    } finally { await set(orig ?? null); }
  });

});
