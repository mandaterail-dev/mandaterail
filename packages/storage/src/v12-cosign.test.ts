/** v12: 2-of-2 attested releases (signer + second verifier) on real Postgres 18 + mr_ed25519. Own database. */
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
import { decodeCosign, encodeCosign, type CosignBody } from "./cosign.js";

const run = promisify(execFile);
const SQL = path.resolve(__dirname, "../../../deploy/sql/t11-mr-reconcile-role.sql");
const TN = TESTNET_PROFILE.caip2.slice(9);
const REL8 = "SELECT * FROM mr_spend_release_attested($1, $2, $3, $4, $5, $6, 'david', 'test release')";
const REL6 = "SELECT * FROM mr_spend_release_attested($1, $2, $3, $4, 'david', 'test release')";
const key = () => { const { publicKey, privateKey } = generateKeyPairSync("ed25519"); const pub = new Uint8Array(publicKey.export({ format: "der", type: "spki" }).subarray(12)); return { pub, priv: privateKey, keyId: keyIdOf(pub) }; };
const payer = algosdk.generateAccount(), merchant = algosdk.generateAccount();
let own: pg.Pool, rel: pg.Pool, admin: pg.Pool;
const prim = key(), co = key();
let n = 0;
let dbName = "";

describe.skipIf(!PG_URL)("v12 2-of-2 attested release [postgres]", () => {
  beforeAll(async () => {
    admin = new pg.Pool({ connectionString: PG_URL, max: 2 });
    const db = `mr_v12_${randomBytes(4).toString("hex")}`;
    dbName = db;
    await admin.query(`CREATE DATABASE ${db}`);
    const url = PG_URL!.replace(/\/[^/]*$/, `/${db}`);
    own = new pg.Pool({ connectionString: url, max: 4 });
    await migratePostgres(own, { network: "testnet", verifyNetwork: async (p) => ({ genesisHash: p.caip2.slice(9) }) });
    await seedTestProviders(own);
    await run("psql", ["-X", "-q", "-v", "ON_ERROR_STOP=1", "-v", "pw=t-rec-pw", "-v", "mon_pw=t-mon-pw", "-v", "rel_pw=t-rel-pw", "-d", url, "-f", SQL]);
    const u = new URL(url); u.username = "mr_release"; u.password = "t-rel-pw";
    rel = new pg.Pool({ connectionString: u.toString(), max: 2 }); rel.on("error", () => undefined);
    await own.query("INSERT INTO mr_signer_key (key_id, pubkey, network, margin_rounds, trust_domain, key_resource) VALUES ($1, $2, 'testnet', 10, 'gcp:mr-signer-test', 'projects/mr-signer-test/locations/us-east1/keyRings/mr/cryptoKeys/attest/cryptoKeyVersions/1')", [prim.keyId, Buffer.from(prim.pub)]);
    await own.query("INSERT INTO mr_cosigner_key (key_id, pubkey, network, trust_domain, key_resource) VALUES ($1, $2, 'testnet', 'aws:000000000000', 'arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000')", [co.keyId, Buffer.from(co.pub)]);
    await own.query("UPDATE mr_release_quorum SET required_m = 2 WHERE network = 'testnet'");
  });
  // drop the database so roles (mr_release) hold no privileges elsewhere (r22 drops and recreates them)
  afterAll(async () => { await rel?.end(); await own?.end(); if (dbName) await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`); await admin?.end(); });

  async function spend() {
    const store = `v12-${++n}`;
    const s = new PgSpendStore(own, { store });
    await s.reserve({ id: "a", payer: payer.addr.toString(), amountMicro: 1n, caps: { perPaymentMicro: toMicro("1"), perDayMicro: toMicro("5") }, nowMs: Date.now() });
    const t = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({ sender: payer.addr, receiver: merchant.addr, amount: 10_000n, assetIndex: 10458941,
      suggestedParams: { fee: 1000n, minFee: 1000n, firstValid: 100n, lastValid: 1100n, genesisHash: Buffer.from(TN, "base64"), genesisID: "testnet-v1.0", flatFee: true } });
    const d = await s.attachSignedTxn("a", { signedTxn: t.signTxn(payer.sk), kind: "xpayment", payer: payer.addr.toString(), submitRound: 1100, nowMs: Date.now() } as never);
    await s.finalize("a", "ambiguous", Date.now());
    await new Promise((r) => setTimeout(r, 1100));
    const now = Date.now();
    const body: AttestBody = { v: 1, network: "testnet", genesisHash: TN, keyId: prim.keyId, store, spendId: "a", txId: d!.txId, sender: payer.addr.toString(), groupId: "",
      firstValid: 100, lastValid: 1100, round: 1200, nonce: randomBytes(32).toString("base64url"), expiry: isoSeconds(now + 300_000),
      observations: [
        { at: isoSeconds(now), idxRound: 1200, method: "idx404", operator: "test-op-a", provider: "idx-a.example", round: 1200 },
        { at: isoSeconds(now), idxRound: 1100, method: "blockscan", operator: "test-op-b", provider: "algod-b.example", round: 1201 },
      ] };
    const m = encodeAttestation(body);
    const sig = sign(null, m, prim.priv);
    const cb: CosignBody = { v: 1, network: "testnet", genesisHash: TN, keyId: co.keyId, attestHash: createHash("sha256").update(m).digest("hex"), store, spendId: "a",
      txId: d!.txId, lastValid: 1100, round: 1205, nonce: randomBytes(32).toString("base64url"), expiry: isoSeconds(now + 300_000),
      observations: [{ at: isoSeconds(now), idxRound: 1205, method: "idx404", operator: "test-op-c", provider: "idx-c.example", round: 1205 }] };
    const cos = (o: Partial<CosignBody> = {}, k = co) => { const cm = encodeCosign({ ...cb, ...o }); return { cm, cs: sign(null, cm, k.priv) }; };
    return { store, s, m, sig, cb, cos };
  }

  it("format round-trips canonically", async () => {
    const w = await spend();
    const { cm } = w.cos();
    expect(decodeCosign(cm)).toEqual(w.cb);
    expect(() => decodeCosign(Buffer.from(cm.toString().replace('{"attestHash"', '{ "attestHash"')))).toThrow();
  });

  it("with quorum 2 a single attestation is refused; every co-signature defect is refused; the good pair releases once", async () => {
    const w = await spend();
    await expect(rel.query(REL6, [w.store, "a", w.m, w.sig])).rejects.toThrow(/requires 2 attestations/);
    const bad = async (o: Partial<CosignBody>, re: RegExp, k = co) => { const { cm, cs } = w.cos(o, k); await expect(rel.query(REL8, [w.store, "a", w.m, w.sig, cm, cs])).rejects.toThrow(re); };
    await bad({ attestHash: "0".repeat(64) }, /not bound to this attestation/);
    await bad({ keyId: prim.keyId }, /unknown, revoked|distinct pinned keys/, prim);
    await bad({}, /co-signature does not verify/, prim); // signed with the primary key under the co-signer's keyId
    await bad({ observations: [{ ...w.cb.observations[0]!, operator: "test-op-a", provider: "idx-a.example" }] }, /already used by the signer \(not independent\)/);
    await bad({ observations: [{ ...w.cb.observations[0]!, provider: "evil.example" }] }, /not pinned/);
    await bad({ round: 1105, observations: [{ ...w.cb.observations[0]!, round: 1105, idxRound: 1105 }] }, /past lastValid \+ margin/);
    await bad({ txId: "C".repeat(52) }, /differ from the attestation/);
    await bad({ spendId: "b" }, /differ from the attestation/);
    await bad({ expiry: isoSeconds(Date.now() - 1000) }, /expired/);
    await bad({ observations: [] }, /1 to 4 observations/);
    const { cm, cs } = w.cos();
    const flipped = Buffer.from(cs); flipped[3]! ^= 1;
    await expect(rel.query(REL8, [w.store, "a", w.m, w.sig, cm, flipped])).rejects.toThrow(/co-signature does not verify/);
    const badPrimary = Buffer.from(w.sig); badPrimary[0]! ^= 1;
    await expect(rel.query(REL8, [w.store, "a", w.m, badPrimary, cm, cs])).rejects.toThrow(/signature does not verify/);
    expect((await rel.query(REL8, [w.store, "a", w.m, w.sig, cm, cs])).rows[0]).toEqual({ ok: true, from_status: "ambiguous" });
    expect((await w.s.get("a"))!.status).toBe("released");
    const row = (await own.query("SELECT cosigner_key_id, attest_hash FROM mr_release_cosign WHERE store = $1", [w.store])).rows;
    expect(row).toEqual([{ cosigner_key_id: co.keyId, attest_hash: w.cb.attestHash }]);
    expect((await rel.query(REL8, [w.store, "a", w.m, w.sig, cm, cs])).rows[0]).toEqual({ ok: false, from_status: "released" });
  });

  it("R48-P2-1: trust domains pinned, write-once, and the co-signer's PROVIDER must differ from the signer's", async () => {
    // a co-signer key in the same provider (gcp) as the signer: refused at release, even with a valid signature
    const same = key();
    await own.query("INSERT INTO mr_cosigner_key (key_id, pubkey, network, trust_domain, key_resource) VALUES ($1, $2, 'testnet', 'gcp:other-project', 'projects/other-project/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1')", [same.keyId, Buffer.from(same.pub)]);
    const w = await spend();
    const { cm, cs } = w.cos({ keyId: same.keyId }, same);
    await expect(rel.query(REL8, [w.store, "a", w.m, w.sig, cm, cs])).rejects.toThrow(/different trust domain \(provider\).*gcp:mr-signer-test vs gcp:other-project/);
    // format, NOT NULL, write-once on both tables
    const k2 = key();
    await expect(own.query("INSERT INTO mr_cosigner_key (key_id, pubkey, network) VALUES ($1, $2, 'testnet')", [k2.keyId, Buffer.from(k2.pub)])).rejects.toThrow(/null value|not-null/);
    await expect(own.query("INSERT INTO mr_cosigner_key (key_id, pubkey, network, trust_domain, key_resource) VALUES ($1, $2, 'testnet', 'AWS no colon', 'z')", [k2.keyId, Buffer.from(k2.pub)])).rejects.toThrow(/check constraint/);
    await expect(own.query("INSERT INTO mr_signer_key (key_id, pubkey, network, margin_rounds) VALUES ($1, $2, 'testnet', 10)", [k2.keyId, Buffer.from(k2.pub)])).rejects.toThrow(/trust_domain is required/);
    await expect(own.query("UPDATE mr_signer_key SET trust_domain = 'aws:1' WHERE key_id = $1", [prim.keyId])).rejects.toThrow(/write-once|refused/);
    // R49-P3: the domain is bound to the KMS resource id
    const k3 = key();
    await expect(own.query("INSERT INTO mr_cosigner_key (key_id, pubkey, network, trust_domain, key_resource) VALUES ($1, $2, 'testnet', 'aws:111111111111', 'arn:aws:kms:us-east-1:222222222222:key/00000000-0000-0000-0000-000000000000')", [k3.keyId, Buffer.from(k3.pub)])).rejects.toThrow(/check constraint/);
    await expect(own.query("INSERT INTO mr_signer_key (key_id, pubkey, network, margin_rounds, trust_domain, key_resource) VALUES ($1, $2, 'testnet', 10, 'gcp:mr-signer-test', 'projects/evil-proj/locations/us-east1/keyRings/mr/cryptoKeys/attest/cryptoKeyVersions/1')", [k3.keyId, Buffer.from(k3.pub)])).rejects.toThrow(/check constraint/);
    await expect(own.query("INSERT INTO mr_cosigner_key (key_id, pubkey, network, trust_domain, key_resource) VALUES ($1, $2, 'testnet', 'vultr:acct1', 'vultr:acct1/key')", [k3.keyId, Buffer.from(k3.pub)])).rejects.toThrow(/check constraint/);
    await expect(own.query("INSERT INTO mr_cosigner_key (key_id, pubkey, network, trust_domain, key_resource) VALUES ($1, $2, 'testnet', 'yubikey:1.*', 'piv:1xyz:9c')", [k3.keyId, Buffer.from(k3.pub)])).rejects.toThrow(/check constraint/);
    await expect(own.query("UPDATE mr_signer_key SET key_resource = 'projects/mr-signer-test/locations/us-east1/keyRings/mr/cryptoKeys/attest/cryptoKeyVersions/2' WHERE key_id = $1", [prim.keyId])).rejects.toThrow(/write-once|refused/);
    await expect(own.query("UPDATE mr_cosigner_key SET trust_domain = 'vultr:x', revoked_at = now(), revoke_reason = 'r' WHERE key_id = $1", [co.keyId])).rejects.toThrow(/one-way revoke/);
  });

  it("guards: the v11 verifier is not callable by mr_release; keys distinct; quorum only rises; MainNet fixed at 2; tables write-once", async () => {
    const w = await spend();
    await expect(rel.query("SELECT * FROM mr_spend_release_attested_v11($1, $2, $3, $4, 'd', 'test release')", [w.store, "a", w.m, w.sig])).rejects.toThrow(/permission denied/);
    await expect(own.query("INSERT INTO mr_cosigner_key (key_id, pubkey, network, trust_domain, key_resource) VALUES ($1, $2, 'testnet', 'aws:000000000000', 'arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000')", [prim.keyId, Buffer.from(prim.pub)])).rejects.toThrow(/distinct from every primary/);
    await expect(own.query("UPDATE mr_release_quorum SET required_m = 1 WHERE network = 'testnet'")).rejects.toThrow(/only be raised/);
    await expect(own.query("UPDATE mr_release_quorum SET required_m = 1 WHERE network = 'mainnet'")).rejects.toThrow();
    await expect(own.query("DELETE FROM mr_release_quorum")).rejects.toThrow(/write-once/);
    await expect(own.query("INSERT INTO mr_release_cosign (nonce, store, spend_id, cosigner_key_id, attest_hash, cosign_msg, cosign_sig) VALUES ($1, 'x', 'y', $2, $3, 'x', $4)",
      [randomBytes(32), co.keyId, "0".repeat(64), randomBytes(64)])).rejects.toThrow(/only by mr_spend_release_attested/);
    await expect(rel.query("INSERT INTO mr_cosigner_key (key_id, pubkey, network, trust_domain, key_resource) VALUES ('x', 'x', 'testnet', 'aws:x', 'y')")).rejects.toThrow(/permission denied/);
    await expect(own.query("UPDATE mr_cosigner_key SET pubkey = $1", [randomBytes(32)])).rejects.toThrow(/one-way revoke/);
  });
});
