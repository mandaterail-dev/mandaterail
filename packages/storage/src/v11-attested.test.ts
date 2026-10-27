/**
 * v11 attested release (docs/ops/attested-release-signer.md §2–§3) on real Postgres 18 with the mr_ed25519
 * extension: golden attestation vector, the happy path, negatives, replay, immutability, revoke.
 */
import { afterAll, describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import { generateKeyPairSync, randomBytes, sign, createPrivateKey } from "node:crypto";
import path from "node:path";
import { promisify } from "node:util";
import algosdk from "algosdk";
import pg from "pg";
import { TESTNET_PROFILE, toMicro } from "@mandaterail/core";
import { PgSpendStore } from "./pg.js";
import { closeShared, getPool, PG_URL, uid } from "./test-helpers.js";
import { decodeAttestation, encodeAttestation, isoSeconds, jcs, keyIdOf, verifyAttestation, type AttestBody } from "./attest.js";
import { deriveSignedTxn, SignedTxnError } from "./signed-txn.js";

afterAll(closeShared);
const run = promisify(execFile);
const SQL = path.resolve(__dirname, "../../../deploy/sql/t11-mr-reconcile-role.sql");
const pwArgs = ["-v", "pw=t-rec-pw", "-v", "mon_pw=t-mon-pw", "-v", "rel_pw=t-rel-pw"];
const applyRoles = () => run("psql", ["-X", "-q", "-v", "ON_ERROR_STOP=1", ...pwArgs, "-d", PG_URL!, "-f", SQL]);
const TN = TESTNET_PROFILE.caip2.slice(9);
const caps = { perPaymentMicro: toMicro("1"), perDayMicro: toMicro("5") };
const REL = "SELECT * FROM mr_spend_release_attested($1, $2, $3, $4, 'david', 'test release')";

// TESTNET-ONLY software key for tests (a fresh key per run; never a real signer key).
function testKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ format: "der", type: "spki" }).subarray(12);
  return { pub: new Uint8Array(pub), priv: privateKey, keyId: keyIdOf(pub) };
}
function poolAs(role: string, pw: string): pg.Pool {
  const u = new URL(PG_URL!);
  u.username = role;
  u.password = pw;
  const p = new pg.Pool({ connectionString: u.toString(), max: 2 });
  p.on("error", () => undefined);
  return p;
}
const payer = algosdk.generateAccount();
const merchant = algosdk.generateAccount();
function signedAxfer(fv: number, lv: number): Uint8Array {
  const sp = { fee: 1000n, minFee: 1000n, firstValid: BigInt(fv), lastValid: BigInt(lv), genesisHash: Buffer.from(TN, "base64"), genesisID: "testnet-v1.0", flatFee: true };
  const t = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({ sender: payer.addr, receiver: merchant.addr, amount: 10_000n, assetIndex: 10458941, suggestedParams: sp });
  return t.signTxn(payer.sk);
}

describe("v11 attestation encoding (no DB)", () => {
  it("golden vector: RFC 8032 test 1 key, fixed body -> fixed bytes and signature", () => {
    // RFC 8032 §7.1 TEST 1 secret key (public test vector, not a secret)
    const seed = Buffer.from("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "hex");
    const priv = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
    const pub = Buffer.from("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "hex");
    const body: AttestBody = {
      v: 1, network: "testnet", genesisHash: TN, keyId: keyIdOf(pub), store: "demo-api", spendId: "s1",
      txId: "A".repeat(52), sender: "B".repeat(58), groupId: "", firstValid: 100, lastValid: 1100, round: 1200,
      nonce: "A".repeat(43), expiry: "2026-10-19T23:00:00Z",
      observations: [
        { at: "2026-10-19T22:50:00Z", idxRound: 1200, method: "idx404", operator: "test-op-a", provider: "idx-a.example", round: 1200 },
        { at: "2026-10-19T22:50:01Z", idxRound: 1100, method: "blockscan", operator: "test-op-b", provider: "algod-b.example", round: 1201 },
      ],
    };
    const msg = encodeAttestation(body);
    expect(keyIdOf(pub)).toBe("21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9".slice(0, 32));
    expect(msg.toString("utf8").startsWith("MR-RELEASE-ATTEST-v1\n{\"expiry\":")).toBe(true);
    const sig = sign(null, msg, priv);
    expect(verifyAttestation(msg, sig, pub)).toBe(true);
    expect(decodeAttestation(msg)).toEqual(body);
    // Ed25519 is deterministic: the golden signature is stable
    expect(sig.toString("hex")).toMatchSnapshot();
  });
  it("jcs refuses non-canonical inputs", () => {
    expect(() => jcs("a\"b")).toThrow();
    expect(() => jcs(-1)).toThrow();
    expect(() => jcs(1.5)).toThrow();
    expect(() => jcs({ "a-b": 1 })).toThrow();
    expect(jcs({ b: 1, a: [2, "x"] })).toBe('{"a":[2,"x"],"b":1}');
    const m = Buffer.from('MR-RELEASE-ATTEST-v1\n{"v":1}');
    expect(() => decodeAttestation(m)).toThrow();
  });
  it("signed_txn derivation: canonical bytes only, payer's payment picked", () => {
    const b = signedAxfer(100, 1100);
    const d = deriveSignedTxn(b, "xpayment");
    expect(d).toMatchObject({ firstValid: 100, lastValid: 1100, groupId: "", sender: payer.addr.toString(), assetId: 10458941, closeTo: null, rekeyTo: null });
    expect(() => deriveSignedTxn(new Uint8Array([...b, 0]), "xpayment")).toThrow(SignedTxnError);
    expect(() => deriveSignedTxn(b, "group")).toThrow(SignedTxnError);
  });
});

describe.skipIf(!PG_URL)("v11 attested release [postgres]", () => {
  async function setup(opts: { submitRound?: number } = {}) {
    const pool = await getPool();
    await applyRoles();
    const k = testKey();
    await pool.query("INSERT INTO mr_signer_key (key_id, pubkey, network, margin_rounds, trust_domain, key_resource) VALUES ($1, $2, 'testnet', 10, 'gcp:mr-signer-test', 'projects/mr-signer-test/locations/us-east1/keyRings/mr/cryptoKeys/attest/cryptoKeyVersions/1')", [k.keyId, Buffer.from(k.pub)]);
    const store = uid("v11");
    const s = new PgSpendStore(pool, { store });
    await s.reserve({ id: "a", payer: payer.addr.toString(), amountMicro: 1n, caps, nowMs: Date.now() });
    const stx = signedAxfer(100, 1100);
    const d = await s.attachSignedTxn("a", { signedTxn: stx, kind: "xpayment", payer: payer.addr.toString(), submitRound: opts.submitRound ?? 1100, nowMs: Date.now() });
    expect(d).not.toBeNull();
    await s.finalize("a", "ambiguous", Date.now());
    const now = Date.now();
    const body: AttestBody = {
      v: 1, network: "testnet", genesisHash: TN, keyId: k.keyId, store, spendId: "a", txId: d!.txId, sender: d!.sender,
      groupId: "", firstValid: 100, lastValid: 1100, round: 1200, nonce: randomBytes(32).toString("base64url"),
      expiry: isoSeconds(now + 5 * 60_000),
      observations: [
        { at: isoSeconds(now + 2000), idxRound: 1200, method: "idx404", operator: "test-op-a", provider: "idx-a.example", round: 1200 },
        { at: isoSeconds(now + 3000), idxRound: 1100, method: "blockscan", operator: "test-op-b", provider: "algod-b.example", round: 1201 },
      ],
    };
    const signBody = (b: AttestBody) => { const m = encodeAttestation(b); return { m, sig: sign(null, m, k.priv) }; };
    return { pool, store, s, k, body, signBody, stx };
  }

  it("happy path releases once; replay, tampering and wrong fields are refused", async () => {
    const { pool, store, s, body, signBody } = await setup();
    const rel = poolAs("mr_release", "t-rel-pw");
    try {
      const bad = async (b: Partial<AttestBody>, re: RegExp) => {
        const { m, sig } = signBody({ ...body, ...b });
        await expect(rel.query(REL, [store, "a", m, sig])).rejects.toThrow(re);
      };
      await bad({ round: 1109 }, /round is not past/);
      await bad({ txId: "C".repeat(52) }, /differ from the stored row/);
      await bad({ lastValid: 1000 }, /differ from the stored row/);
      await bad({ network: "mainnet" }, /network must be testnet/);
      await bad({ genesisHash: "x".repeat(43) + "=" }, /genesis hash/);
      await bad({ expiry: isoSeconds(Date.now() - 1000) }, /expired/);
      await bad({ expiry: isoSeconds(Date.now() + 3600_000) }, /expiry more than 15 min/);
      await bad({ observations: [body.observations[0]!, { ...body.observations[1]!, operator: "test-op-a", provider: "algod-a.example" }] }, /2 distinct pinned operators/);
      await bad({ observations: [body.observations[0]!, { ...body.observations[1]!, provider: "evil.example" }] }, /not pinned/);
      await bad({ observations: [body.observations[0]!, { ...body.observations[1]!, idxRound: 1099 }] }, /blockscan/);
      await bad({ observations: [body.observations[0]!] }, /2 to 4 observations/);
      const { m, sig } = signBody(body);
      const flipped = Buffer.from(sig); flipped[0]! ^= 1;
      await expect(rel.query(REL, [store, "a", m, flipped])).rejects.toThrow(/does not verify/);
      // non-canonical bytes (extra space) with a valid signature over them
      const nc = Buffer.from(m.toString("utf8").replace('{"expiry"', '{ "expiry"'));
      await expect(rel.query(REL, [store, "a", nc, signBody(body).sig])).rejects.toThrow(/canonical|does not verify/);
      expect((await rel.query(REL, [store, "a", m, sig])).rows[0]).toEqual({ ok: true, from_status: "ambiguous" });
      expect((await s.get("a"))!.status).toBe("released");
      // replay: already released (not pending/ambiguous) -> ok false; nonce reuse on another spend -> refused
      expect((await rel.query(REL, [store, "a", m, sig])).rows[0]).toEqual({ ok: false, from_status: "released" });
      const a = (await pool.query("SELECT action, reason FROM mr_spend_audit WHERE store = $1 AND id = 'a'", [store])).rows;
      expect(a).toMatchObject([{ action: "attested-release" }]);
      // attestation and signed bytes are immutable now
      await expect(pool.query("UPDATE mr_spend SET attestation_msg = 'x' WHERE store = $1 AND id = 'a'", [store])).rejects.toThrow(/written once/);
      await expect(pool.query("UPDATE mr_spend SET signed_txn = 'x' WHERE store = $1 AND id = 'a'", [store])).rejects.toThrow(/immutable/);
      await expect(pool.query("DELETE FROM mr_release_nonce")).rejects.toThrow(/write-once/);
      await expect(pool.query("INSERT INTO mr_release_nonce (nonce, store, spend_id, key_id) VALUES ($1, 'x', 'y', $2)", [randomBytes(32), body.keyId])).rejects.toThrow(/only by mr_spend_release_attested/);
    } finally {
      await rel.end();
    }
  });

  it("nonce replay across spends is refused; lv_est gates early observations", async () => {
    const { store, s, body, signBody } = await setup();
    const rel = poolAs("mr_release", "t-rel-pw");
    try {
      const { m, sig } = signBody(body);
      expect((await rel.query(REL, [store, "a", m, sig])).rows[0]).toMatchObject({ ok: true });
      // second spend with the same nonce
      await s.reserve({ id: "b", payer: payer.addr.toString(), amountMicro: 1n, caps, nowMs: Date.now() });
      const stx2 = signedAxfer(101, 1100);
      const d2 = await s.attachSignedTxn("b", { signedTxn: stx2, kind: "xpayment", payer: payer.addr.toString(), submitRound: 1100, nowMs: Date.now() });
      await s.finalize("b", "ambiguous", Date.now());
      const r2 = signBody({ ...body, spendId: "b", txId: d2!.txId, firstValid: 101 });
      await expect(rel.query(REL, [store, "b", r2.m, r2.sig])).rejects.toThrow(/replay/);
    } finally {
      await rel.end();
    }
    // submit far before lastValid: lv_est is ~40 min ahead, so "now" observations are too early
    const t = await setup({ submitRound: 150 });
    const rel2 = poolAs("mr_release", "t-rel-pw");
    try {
      const { m, sig } = t.signBody(t.body);
      await expect(rel2.query(REL, [t.store, "a", m, sig])).rejects.toThrow(/outside \[lv_est/);
    } finally {
      await rel2.end();
    }
  });

  it("signed_txn is write-once, payer-bound, pending-only; revoke is one-way and admin-window only", async () => {
    const { pool, store, s, k, body, signBody, stx } = await setup();
    await expect(s.attachSignedTxn("a", { signedTxn: stx, kind: "xpayment", payer: merchant.addr.toString(), submitRound: 1, nowMs: Date.now() })).rejects.toThrow(/not the reserved payer/);
    await s.reserve({ id: "c", payer: payer.addr.toString(), amountMicro: 1n, caps, nowMs: Date.now() });
    await expect(pool.query("UPDATE mr_spend SET signed_txn = 'x', signed_txn_kind = 'xpayment', tx_id = $2, first_valid = 1, last_valid = 2, group_id = '', sender = $3, submit_round = 1, submit_at = now() - interval '1 hour' WHERE store = $1 AND id = 'c'", [store, "D".repeat(52), "E".repeat(58)])).rejects.toThrow(/database clock/);
    await expect(pool.query(`INSERT INTO mr_spend (store, id, payer, amount_micro, status, created_ms, updated_ms, signed_txn) VALUES ($1, 'z', 'P', 1, 'pending', 1, 1, 'x')`, [store])).rejects.toThrow(/new row/);
    await expect(pool.query("SELECT mr_signer_revoke($1, 'compromised key')", [k.keyId])).rejects.toThrow(/mr-admin-window/);
    const c = await pool.connect();
    try {
      await c.query("SET application_name = 'mr-admin-window'");
      await expect(c.query("SELECT mr_signer_revoke($1, 'short')", [k.keyId])).rejects.toThrow(/8\+ characters/);
      expect((await c.query("SELECT mr_signer_revoke($1, 'test: key rotated') AS r", [k.keyId])).rows[0].r).toBe(true);
      expect((await c.query("SELECT mr_signer_revoke($1, 'test: key rotated') AS r", [k.keyId])).rows[0].r).toBe(false);
    } finally {
      c.release();
    }
    await expect(pool.query("UPDATE mr_signer_key SET revoked_at = NULL, revoke_reason = NULL WHERE key_id = $1", [k.keyId])).rejects.toThrow(/UPDATE refused/);
    await expect(pool.query("INSERT INTO mr_signer_key (key_id, pubkey, network, margin_rounds, trust_domain, key_resource) VALUES ($1, $2, 'mainnet', 10, 'gcp:mr-signer-test', 'projects/mr-signer-test/locations/us-east1/keyRings/mr/cryptoKeys/attest/cryptoKeyVersions/1')", [keyIdOf(new Uint8Array(32).fill(7)), Buffer.alloc(32, 7)])).rejects.toThrow(/does not match this database/);
    const rel = poolAs("mr_release", "t-rel-pw");
    try {
      const { m, sig } = signBody(body);
      await expect(rel.query(REL, [store, "a", m, sig])).rejects.toThrow(/unknown or revoked/);
      // mr_release cannot call the unsigned path's siblings or write the tables
      await expect(rel.query("SELECT mr_signer_revoke('x', 'yyyyyyyyy')")).rejects.toThrow(/permission denied/);
      await expect(rel.query("SELECT mr_crypto.mr_ed25519_verify('a', 'b', 'c')")).rejects.toThrow(/permission denied/);
    } finally {
      await rel.end();
    }
  });

  it("R43-P2-1: at most 5 attested releases per rolling 24 h, enforced in the DB", async () => {
    const pool = await getPool();
    const rel = poolAs("mr_release", "t-rel-pw");
    try {
      for (;;) {
        const n = Number((await pool.query("SELECT count(*) FROM mr_release_nonce WHERE used_at > clock_timestamp() - interval '24 hours'")).rows[0].count);
        const { store, body, signBody } = await setup();
        const { m, sig } = signBody(body);
        if (n >= 5) {
          await expect(rel.query(REL, [store, "a", m, sig])).rejects.toThrow(/limit of 5 attested releases per 24 h/);
          break;
        }
        expect((await rel.query(REL, [store, "a", m, sig])).rows[0]).toMatchObject({ ok: true });
      }
    } finally {
      await rel.end();
    }
  });

  it("R43 launch blocker: an X-PAYMENT group (signed payer member + unsigned fee-payer wrapped) is stored, payer read from the row", async () => {
    const pool = await getPool();
    const store = uid("v11x");
    const s = new PgSpendStore(pool, { store });
    const fp = algosdk.generateAccount();
    const sp = { fee: 0n, minFee: 1000n, firstValid: 100n, lastValid: 1100n, genesisHash: Buffer.from(TN, "base64"), genesisID: "testnet-v1.0", flatFee: true };
    const pay = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({ sender: payer.addr, receiver: merchant.addr, amount: 10_000n, assetIndex: 10458941, suggestedParams: sp });
    const fee = algosdk.makePaymentTxnWithSuggestedParamsFromObject({ sender: fp.addr, receiver: fp.addr, amount: 0n, suggestedParams: { ...sp, fee: 2000n } });
    algosdk.assignGroupID([fee, pay]);
    const bytes = new Uint8Array([...algosdk.encodeMsgpack(new algosdk.SignedTransaction({ txn: fee })), ...pay.signTxn(payer.sk)]);
    await s.reserve({ id: "x", payer: payer.addr.toString(), amountMicro: 10_000n, caps, nowMs: Date.now() });
    const d = await s.attachSignedTxn("x", { signedTxn: bytes, kind: "xpayment", submitRound: 100, nowMs: Date.now() });
    expect(d).toMatchObject({ txId: pay.txID(), sender: payer.addr.toString(), groupId: Buffer.from(pay.group!).toString("base64") });
    const row = (await pool.query("SELECT tx_id, group_id, signed_txn_kind FROM mr_spend WHERE store = $1 AND id = 'x'", [store])).rows[0];
    expect(row).toMatchObject({ tx_id: pay.txID(), signed_txn_kind: "xpayment" });
    // a reservation whose payer is not the sender is refused
    await s.reserve({ id: "y", payer: merchant.addr.toString(), amountMicro: 1n, caps, nowMs: Date.now() });
    await expect(s.attachSignedTxn("y", { signedTxn: bytes, kind: "xpayment", submitRound: 100, nowMs: Date.now() })).rejects.toThrow(/payer|exactly one payment/);
  });

  it("R44: reconcile moves pending rows with signed bytes to ambiguous after the timeout (never released)", async () => {
    const pool = await getPool();
    await applyRoles();
    const store = uid("v11st");
    const s = new PgSpendStore(pool, { store });
    for (const id of ["old", "fresh", "nobytes"]) await s.reserve({ id, payer: payer.addr.toString(), amountMicro: 1n, caps, nowMs: Date.now() });
    await s.attachSignedTxn("old", { signedTxn: signedAxfer(100, 1100), kind: "xpayment", submitRound: 100, nowMs: Date.now() });
    await s.attachSignedTxn("fresh", { signedTxn: signedAxfer(101, 1100), kind: "xpayment", submitRound: 101, nowMs: Date.now() });
    await pool.query("UPDATE mr_spend SET updated_ms = updated_ms - 3600000 WHERE store = $1 AND id IN ('old', 'nobytes')", [store]);
    const rec = poolAs("mr_reconcile", "t-rec-pw");
    try {
      await expect(rec.query("SELECT mr_spend_pending_signed_to_ambiguous($1, 1000)", [store])).rejects.toThrow(/>= 60000/);
      const { reconcileSpendPg } = await import("./spend-ops.js");
      const out = await reconcileSpendPg(rec, { store, check: async () => "unknown", pendingSignedTimeoutMs: 15 * 60_000 });
      expect(out.stuckToAmbiguous).toBe(1);
      expect((await s.get("old"))!.status).toBe("ambiguous");
      expect((await s.get("fresh"))!.status).toBe("pending");
      expect((await s.get("nobytes"))!.status).toBe("pending");
      const a = (await pool.query("SELECT action, to_status FROM mr_spend_audit WHERE store = $1 AND id = 'old'", [store])).rows;
      expect(a).toEqual([{ action: "stuck-pending-ambiguous", to_status: "ambiguous" }]);
      // app roles can't call it
      const app = poolAs("mr_release", "t-rel-pw");
      await expect(app.query("SELECT mr_spend_pending_signed_to_ambiguous($1, 60000)", [store])).rejects.toThrow(/permission denied/);
      await app.end();
    } finally {
      await rec.end();
    }
  });
});
