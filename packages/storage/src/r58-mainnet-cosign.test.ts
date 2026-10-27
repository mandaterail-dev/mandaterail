/**
 * R58-P3-3: e2e co-signed MainNet release through mr_spend_release_attested (v12, quorum 2) on a MainNet-marked DB
 * with the real allowlist rows: signer = nodely idx404 + getblock blockscan, co-signer = drpc blockscan-full.
 * Covers accept, idxRound <> lastValid reject, and operator-overlap reject. Own database.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import path from "node:path";
import { promisify } from "node:util";
import algosdk from "algosdk";
import pg from "pg";
import { MAINNET_PROFILE, toMicro } from "@mandaterail/core";
import { migratePostgres, PgSpendStore } from "./pg.js";
import { PG_URL } from "./test-helpers.js";
import { encodeAttestation, isoSeconds, keyIdOf, type AttestBody } from "./attest.js";
import { encodeCosign, type CosignBody } from "./cosign.js";

const run = promisify(execFile);
const SQL = path.resolve(__dirname, "../../../deploy/sql/t11-mr-reconcile-role.sql");
const MN = MAINNET_PROFILE.caip2.slice(9);
const REL8 = "SELECT * FROM mr_spend_release_attested($1, $2, $3, $4, $5, $6, 'david', 'r58 test release')";
const key = () => { const { publicKey, privateKey } = generateKeyPairSync("ed25519"); const pub = new Uint8Array(publicKey.export({ format: "der", type: "spki" }).subarray(12)); return { pub, priv: privateKey, keyId: keyIdOf(pub) }; };
const payer = algosdk.generateAccount(), merchant = algosdk.generateAccount();
const prim = key(), co = key();
let own: pg.Pool, rel: pg.Pool, admin: pg.Pool, dbName = "", n = 0;
const NODELY = { operator: "nodely", provider: "mainnet-idx.4160.nodely.dev" };
const GETBLOCK = { operator: "getblock", provider: "shared.eu-central-1.getblock.io" };
const DRPC = { operator: "drpc", provider: "algorand.drpc.org" };

describe.skipIf(!PG_URL)("R58-P3-3 MainNet co-signed release with a dRPC blockscan-full co-signer [postgres]", () => {
  beforeAll(async () => {
    admin = new pg.Pool({ connectionString: PG_URL, max: 2 });
    dbName = `mr_r58_${randomBytes(4).toString("hex")}`;
    await admin.query(`CREATE DATABASE ${dbName}`);
    const url = PG_URL!.replace(/\/[^/]*$/, `/${dbName}`);
    own = new pg.Pool({ connectionString: url, max: 4 });
    await migratePostgres(own, { network: "mainnet", allowMainnet: true, verifyNetwork: async (p) => ({ genesisHash: p.caip2.slice(9) }) });
    await run("psql", ["-X", "-q", "-v", "ON_ERROR_STOP=1", "-v", "pw=t-rec-pw", "-v", "mon_pw=t-mon-pw", "-v", "rel_pw=t-rel-pw", "-d", url, "-f", SQL]);
    const u = new URL(url); u.username = "mr_release"; u.password = "t-rel-pw";
    rel = new pg.Pool({ connectionString: u.toString(), max: 2 }); rel.on("error", () => undefined);
    await own.query("INSERT INTO mr_signer_key (key_id, pubkey, network, margin_rounds, trust_domain, key_resource) VALUES ($1, $2, 'mainnet', 10, 'gcp:mr-signer-test', 'projects/mr-signer-test/locations/us-east1/keyRings/mr/cryptoKeys/attest/cryptoKeyVersions/1')", [prim.keyId, Buffer.from(prim.pub)]);
    await own.query("INSERT INTO mr_cosigner_key (key_id, pubkey, network, trust_domain, key_resource) VALUES ($1, $2, 'mainnet', 'aws:000000000000', 'arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000')", [co.keyId, Buffer.from(co.pub)]);
  });
  afterAll(async () => { await rel?.end(); await own?.end(); if (dbName) await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`); await admin?.end(); });

  async function spend() {
    const store = `r58-${++n}`;
    const s = new PgSpendStore(own, { store });
    await s.reserve({ id: "a", payer: payer.addr.toString(), amountMicro: 10_000n, caps: { perPaymentMicro: toMicro("0.01"), perDayMicro: toMicro("0.05") }, nowMs: Date.now() });
    const t = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({ sender: payer.addr, receiver: merchant.addr, amount: 10_000n, assetIndex: Number(MAINNET_PROFILE.usdcAsaId),
      suggestedParams: { fee: 1000n, minFee: 1000n, firstValid: 100n, lastValid: 1100n, genesisHash: Buffer.from(MN, "base64"), genesisID: "mainnet-v1.0", flatFee: true } });
    const d = await s.attachSignedTxn("a", { signedTxn: t.signTxn(payer.sk), kind: "xpayment", payer: payer.addr.toString(), submitRound: 1100, nowMs: Date.now() } as never);
    await s.finalize("a", "ambiguous", Date.now());
    await new Promise((r) => setTimeout(r, 1100));
    const now = Date.now();
    const body: AttestBody = { v: 1, network: "mainnet", genesisHash: MN, keyId: prim.keyId, store, spendId: "a", txId: d!.txId, sender: payer.addr.toString(), groupId: "",
      firstValid: 100, lastValid: 1100, round: 1200, nonce: randomBytes(32).toString("base64url"), expiry: isoSeconds(now + 600_000),
      observations: [
        { at: isoSeconds(now), idxRound: 1100, method: "blockscan", ...GETBLOCK, round: 1201 },
        { at: isoSeconds(now), idxRound: 1200, method: "idx404", ...NODELY, round: 1200 },
      ] };
    const m = encodeAttestation(body);
    const sig = sign(null, m, prim.priv);
    const cb: CosignBody = { v: 1, network: "mainnet", genesisHash: MN, keyId: co.keyId, attestHash: createHash("sha256").update(m).digest("hex"), store, spendId: "a",
      txId: d!.txId, lastValid: 1100, round: 1205, nonce: randomBytes(32).toString("base64url"), expiry: isoSeconds(now + 600_000),
      observations: [{ at: isoSeconds(now), idxRound: 1100, method: "blockscan-full", ...DRPC, round: 1205 }] };
    const cos = (o: Partial<CosignBody> = {}) => { const cm = encodeCosign({ ...cb, ...o }); return { cm, cs: sign(null, cm, co.priv) }; };
    return { store, s, m, sig, cb, cos };
  }

  it("accepts: nodely + getblock (signer) and drpc blockscan-full (co-signer) release once", async () => {
    const w = await spend();
    const { cm, cs } = w.cos();
    expect((await rel.query(REL8, [w.store, "a", w.m, w.sig, cm, cs])).rows[0]).toEqual({ ok: true, from_status: "ambiguous" });
    expect((await w.s.get("a"))!.status).toBe("released");
  });

  it("rejects a blockscan-full observation whose idxRound <> lastValid", async () => {
    const w = await spend();
    for (const idxRound of [1099, 1101, 1205]) {
      const { cm, cs } = w.cos({ observations: [{ ...w.cb.observations[0]!, idxRound }] });
      await expect(rel.query(REL8, [w.store, "a", w.m, w.sig, cm, cs])).rejects.toThrow(/round \/ method/);
    }
    expect((await w.s.get("a"))!.status).toBe("ambiguous");
  });

  it("rejects operator overlap: the co-signer observing through an operator the signer used", async () => {
    const w = await spend();
    for (const ov of [{ ...GETBLOCK, method: "blockscan-full" as const, idxRound: 1100 }, { ...NODELY, method: "idx404" as const, idxRound: 1205 }]) {
      const { cm, cs } = w.cos({ observations: [{ ...w.cb.observations[0]!, ...ov }] });
      await expect(rel.query(REL8, [w.store, "a", w.m, w.sig, cm, cs])).rejects.toThrow(/already used by the signer \(not independent\)/);
    }
    expect((await w.s.get("a"))!.status).toBe("ambiguous");
  });
});
