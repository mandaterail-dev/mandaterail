/**
 * v12 second verifier: unit negatives + end to end on Postgres 18 with quorum 2:
 * app stored bytes -> mr-signer (two-phase, real helper) -> second verifier (own key, own nonces, own provider of
 * another operator) -> CLI checks both -> mr_spend_release_attested 8-arg.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { randomBytes } from "node:crypto";
import pg from "pg";
import { toMicro } from "@mandaterail/core";
import { keyIdOf, migratePostgres, PgSpendStore, encodeAttestation, decodeAttestation, decodeCosign } from "@mandaterail/storage";
import { attestedRelease } from "../src/cli/release.js";
import { SecondVerifier, initialVerifierState, type VerifierState } from "../src/verifier/verifier.js";
import { DurableJson } from "../src/state.js";
import { RequestAuth, initialReqState, type ReqState } from "../src/requests.js";
import { FakeProbe, payer, realHelper, setup, signedPayment, TN } from "./fixtures.js";

const PG_URL = process.env.MR_TEST_PG_URL;
const SQL = path.resolve(__dirname, "../../../deploy/sql/t11-mr-reconcile-role.sql");
let admin: pg.Pool, own: pg.Pool, rel: pg.Pool, dbName = "";

async function verifierFor(s: Awaited<ReturnType<typeof setup>>, primaryPub: Uint8Array, primaryKeyId: string) {
  process.env.MR_SIGNER_SOFTWARE_KEY = "TESTNET-ONLY";
  const { SoftwareEd25519Backend } = await import("../src/piv/backend-software.js");
  const backend = new SoftwareEd25519Backend("testnet");
  const dir = mkdtempSync(path.join(tmpdir(), "mr-ver-"));
  DurableJson.init<VerifierState>(path.join(dir, "verifier.json"), initialVerifierState());
  DurableJson.init<ReqState>(path.join(dir, "requests.json"), initialReqState());
  const auth = new RequestAuth([{ id: "cli-david", pubkey: s.requester.pub }], new DurableJson<ReqState>(path.join(dir, "requests.json")), { maxAgeS: 30, ratePerHour: 30, network: "testnet" });
  const probe = new FakeProbe({ host: "idx-v.example", operator: "test-op-v", kind: "indexer", baseUrl: "https://idx-v.example" });
  const sameOp = new FakeProbe({ host: "idx-a.example", operator: "test-op-a", kind: "indexer", baseUrl: "https://idx-a.example" });
  const st = new DurableJson<VerifierState>(path.join(dir, "verifier.json"));
  const pages: string[] = [];
  const v = new SecondVerifier({ signer: { ...s.cfg, keyId: primaryKeyId }, primaryPubkey: primaryPub, cosignerKeyId: keyIdOf(await backend.publicKey()),
    providers: [probe.provider], maxPerHour: 3, maxPer24h: 5, attestTtlS: 300 },
  { auth, probes: [sameOp, probe], backend, st, clock: async () => ({ synced: true, offsetS: 0, stratum: 2 }), page: async (x, y) => { pages.push(`${x} ${y}`); } });
  return { v, backend, probe, sameOp, st, pages, pub: await backend.publicKey() };
}

describe.skipIf(!PG_URL)("v12 second verifier, end to end with quorum 2 [postgres]", () => {
  beforeAll(async () => {
    admin = new pg.Pool({ connectionString: PG_URL, max: 2 });
    dbName = `mr_ver_${randomBytes(4).toString("hex")}`;
    await admin.query(`CREATE DATABASE ${dbName}`);
    const url = PG_URL!.replace(/\/[^/]*$/, `/${dbName}`);
    own = new pg.Pool({ connectionString: url, max: 4 });
    await migratePostgres(own, { network: "testnet", verifyNetwork: async (p) => ({ genesisHash: p.caip2.slice(9) }) });
    for (const [h, o] of [["idx-a.example", "test-op-a"], ["algod-b.example", "test-op-b"], ["idx-c.example", "test-op-c"], ["idx-own.example", "test-op-own"], ["idx-v.example", "test-op-v"]]) {
      await own.query("INSERT INTO mr_network_provider (network, host, operator_id) VALUES ('testnet', $1, $2) ON CONFLICT DO NOTHING", [h, o]);
      await own.query("INSERT INTO mr_signer_operator (network, operator) VALUES ('testnet', $1) ON CONFLICT DO NOTHING", [o]);
    }
    await promisify(execFile)("psql", ["-X", "-q", "-v", "ON_ERROR_STOP=1", "-v", "pw=t-rec-pw", "-v", "mon_pw=t-mon-pw", "-v", "rel_pw=t-rel-pw", "-d", url, "-f", SQL]);
    await own.query("UPDATE mr_release_quorum SET required_m = 2 WHERE network = 'testnet'");
    const u = new URL(url); u.username = "mr_release"; u.password = "t-rel-pw";
    rel = new pg.Pool({ connectionString: u.toString(), max: 2 }); rel.on("error", () => undefined);
  });
  afterAll(async () => { await rel?.end(); await own?.end(); if (dbName) await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`); await admin?.end(); });

  async function world() {
    const pre = await setup({}, () => ({ sign: async () => new Uint8Array() }));
    const h = await realHelper("testnet", pre.requester.pub);
    const pub = await h.backend.publicKey();
    await own.query("INSERT INTO mr_signer_key (key_id, pubkey, network, margin_rounds, trust_domain, key_resource) VALUES ($1, $2, 'testnet', 10, 'gcp:mr-signer-test', 'projects/mr-signer-test/locations/us-east1/keyRings/mr/cryptoKeys/attest/cryptoKeyVersions/1')", [h.keyId, Buffer.from(pub)]);
    const { MrSigner } = await import("../src/signer.js");
    const cfg = { ...pre.cfg, keyId: h.keyId };
    const signer = MrSigner.boot({ ...pre.deps, cfg, helper: h.helper, backend: h.backend });
    const ver = await verifierFor(pre, pub, h.keyId);
    await own.query("INSERT INTO mr_cosigner_key (key_id, pubkey, network, trust_domain, key_resource) VALUES ($1, $2, 'testnet', 'aws:000000000000', 'arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000')", [keyIdOf(ver.pub), Buffer.from(ver.pub)]);
    const store = `ver-${randomBytes(3).toString("hex")}`;
    const sp = new PgSpendStore(own, { store });
    const p = signedPayment({ fv: 100, lv: 1100 });
    await sp.reserve({ id: "a", payer: payer.addr.toString(), amountMicro: 10_000n, caps: { perPaymentMicro: toMicro("1"), perDayMicro: toMicro("5") }, nowMs: Date.now() });
    await sp.attachSignedTxn("a", { signedTxn: p.bytes, kind: "xpayment", payer: payer.addr.toString(), submitRound: 1100, nowMs: Date.now() } as never);
    await sp.finalize("a", "ambiguous", Date.now());
    await new Promise((r) => setTimeout(r, 1100));
    const deps = { db: rel, cfg, pinnedPubkey: pub, requesterId: "cli-david", requesterKey: pre.requester.priv,
      transport: { candidate: (r: never) => signer.candidate(r), confirm: (r: never) => signer.confirm(r) },
      ownProbes: [new FakeProbe({ host: "idx-own.example", operator: "test-op-own", kind: "indexer", baseUrl: "https://idx-own.example" })],
      page: async () => {}, label: "david", reason: "v12 e2e release" };
    return { pre, sp, store, deps, ver, cfg, signer };
  }

  it("without the second verifier the DB refuses (quorum 2); with it: released, co-signature stored", async () => {
    const w = await world();
    await expect(attestedRelease(w.deps as never, w.store, "a")).rejects.toThrow(/requires 2 attestations/);
    const w2 = await world();
    const r = await attestedRelease({ ...w2.deps, cosigner: { cosign: (q: never) => w2.ver.v.cosign(q), pinnedPubkey: w2.ver.pub } } as never, w2.store, "a");
    expect(r.ok).toBe(true);
    expect((await w2.sp.get("a"))!.status).toBe("released");
    const row = (await own.query("SELECT cosign_msg FROM mr_release_cosign WHERE store = $1", [w2.store])).rows[0];
    const cb = decodeCosign(row.cosign_msg);
    expect(cb.observations.map((o) => o.operator)).toEqual(["test-op-v"]); // only the independent operator
    expect(w2.ver.sameOp.calls).toBe(0); // the signer's operator is never used by the verifier
  });

  it("verifier refusals: present on its provider (anomaly pause), tampered request", async () => {
    const w = await world();
    let captured: { msg: string; sig: string } | null = null;
    const deps = { ...w.deps, cosigner: { cosign: async (q: never) => { const x = await w.ver.v.cosign(q); captured = x; return x; }, pinnedPubkey: w.ver.pub } };
    w.ver.probe.result = { kind: "present", genesis: TN };
    await expect(attestedRelease(deps as never, w.store, "a")).rejects.toThrow(/present/);
    expect(w.ver.st.get().paused?.reason).toMatch(/anomaly/);
    expect((await w.sp.get("a"))!.status).toBe("ambiguous");
    void captured;
    // a fresh verifier: tampered primary attestation (valid shape, wrong signature) is an anomaly
    const w2 = await world();
    const tamper = { ...w2.deps, cosigner: { cosign: (q: { body: Record<string, unknown>; sig: string }) => {
      const a = decodeAttestation(Buffer.from(String(q.body.attestMsg), "base64"));
      const m2 = encodeAttestation({ ...a, round: a.round + 1 });
      return w2.ver.v.cosign({ ...q, body: { ...q.body, attestMsg: m2.toString("base64") } } as never); // request sig no longer matches either
    }, pinnedPubkey: w2.ver.pub } };
    await expect(attestedRelease(tamper as never, w2.store, "a")).rejects.toThrow(/request: request signature/);
    expect(w2.ver.pages.join()).toMatch(/refused/);
  });
});
