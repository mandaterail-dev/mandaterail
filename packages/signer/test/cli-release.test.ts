/**
 * Piece 5, end to end on Postgres 18 + mr_ed25519: app stores signed_txn -> CLI echo checks -> mr-signer
 * (two-phase, TESTNET-ONLY software key via the real helper) -> CLI return verification -> DB verifier.
 * Rehearsal items 8 (return swap) and 9 (CLI independent absence check) are covered here.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import pg from "pg";
import { randomBytes } from "node:crypto";
import { toMicro } from "@mandaterail/core";
import { keyIdOf, migratePostgres, PgSpendStore, encodeAttestation, decodeAttestation } from "@mandaterail/storage";
import { attestedRelease, exportAttestedSpends, type SignerTransport } from "../src/cli/release.js";
import { FakeProbe, payer, realHelper, setup, signedPayment, TN } from "./fixtures.js";

const PG_URL = process.env.MR_TEST_PG_URL;
const run = promisify(execFile);
const SQL = path.resolve(__dirname, "../../../deploy/sql/t11-mr-reconcile-role.sql");
let admin: pg.Pool;
let own: pg.Pool;
let rel: pg.Pool;
let url: string;

describe.skipIf(!PG_URL)("CLI attested release, end to end [postgres]", () => {
  beforeAll(async () => {
    admin = new pg.Pool({ connectionString: PG_URL, max: 2 });
    const db = `mr_cli_${randomBytes(4).toString("hex")}`;
    await admin.query(`CREATE DATABASE ${db}`);
    url = PG_URL!.replace(/\/[^/]*$/, `/${db}`);
    own = new pg.Pool({ connectionString: url, max: 4 });
    await migratePostgres(own, { network: "testnet", verifyNetwork: async (p) => ({ genesisHash: p.caip2.slice(9) }) });
    for (const [h, o] of [["idx-a.example", "test-op-a"], ["algod-b.example", "test-op-b"], ["idx-c.example", "test-op-c"], ["idx-own.example", "test-op-own"]]) {
      await own.query("INSERT INTO mr_network_provider (network, host, operator_id) VALUES ('testnet', $1, $2) ON CONFLICT DO NOTHING", [h, o]);
      await own.query("INSERT INTO mr_signer_operator (network, operator) VALUES ('testnet', $1) ON CONFLICT DO NOTHING", [o]);
    }
    await run("psql", ["-X", "-q", "-v", "ON_ERROR_STOP=1", "-v", "pw=t-rec-pw", "-v", "mon_pw=t-mon-pw", "-v", "rel_pw=t-rel-pw", "-d", url, "-f", SQL]);
    const u = new URL(url);
    u.username = "mr_release";
    u.password = "t-rel-pw";
    rel = new pg.Pool({ connectionString: u.toString(), max: 2 });
    rel.on("error", () => undefined);
  });
  afterAll(async () => { await rel?.end(); await own?.end(); await admin?.end(); });

  async function world(opts: { transportHook?: (t: SignerTransport) => SignerTransport } = {}) {
    let helperW: Awaited<ReturnType<typeof realHelper>> | undefined;
    const pre = await setup({}, () => ({ sign: async () => new Uint8Array() }));
    helperW = await realHelper("testnet", pre.requester.pub);
    const keyId = helperW.keyId;
    const pub = await helperW.backend.publicKey();
    await own.query("INSERT INTO mr_signer_key (key_id, pubkey, network, margin_rounds, trust_domain, key_resource) VALUES ($1, $2, 'testnet', 10, 'gcp:mr-signer-test', 'projects/mr-signer-test/locations/us-east1/keyRings/mr/cryptoKeys/attest/cryptoKeyVersions/1')", [keyId, Buffer.from(pub)]);
    const s = { ...pre, ...(await setupWithRequester(pre, keyId, helperW)) };
    const store = `cli-${randomBytes(3).toString("hex")}`;
    const sp = new PgSpendStore(own, { store });
    const p = signedPayment({ fv: 100, lv: 1100 });
    await sp.reserve({ id: "a", payer: payer.addr.toString(), amountMicro: 10_000n, caps: { perPaymentMicro: toMicro("1"), perDayMicro: toMicro("5") }, nowMs: Date.now() });
    expect(await sp.attachSignedTxn("a", { signedTxn: p.bytes, kind: "xpayment", payer: payer.addr.toString(), submitRound: 1100, nowMs: Date.now() })).not.toBeNull();
    await sp.finalize("a", "ambiguous", Date.now());
    await new Promise((r) => setTimeout(r, 1100)); // observations are whole seconds; lv_est = submit_at here
    const ownProbe = new FakeProbe({ host: "idx-own.example", operator: "test-op-own", kind: "indexer", baseUrl: "https://idx-own.example" });
    const pages: string[] = [];
    const base: SignerTransport = { candidate: (r) => s.signer.candidate(r), confirm: (r) => s.signer.confirm(r) };
    const deps = {
      db: rel, cfg: s.cfg, pinnedPubkey: pub, requesterId: "cli-david", requesterKey: s.requester.priv, transport: opts.transportHook ? opts.transportHook(base) : base,
      ownProbes: [ownProbe], page: async (subj: string, body: string) => { pages.push(`${subj} ${body}`); }, label: "david", reason: "attested e2e",
    };
    return { s, sp, store, deps, ownProbe, pages, p };
  }

  it("happy path: released by the DB verifier, audit + nonce rows, export list for used.db", async () => {
    const w = await world();
    const r = await attestedRelease(w.deps, w.store, "a");
    expect(r).toMatchObject({ ok: true, fromStatus: "ambiguous" });
    expect((await w.sp.get("a"))!.status).toBe("released");
    expect(await exportAttestedSpends(rel)).toContain(`${w.store}/a`);
  });

  it("R41-a return swap: a different validly signed msg is refused before the DB call", async () => {
    const w = await world({
      transportHook: (t) => ({
        candidate: t.candidate,
        confirm: async (req) => {
          const real = await t.confirm(req);
          const b = decodeAttestation(Buffer.from(real.msg, "base64"));
          const m2 = encodeAttestation({ ...b, round: b.round + 1 });
          return { msg: m2.toString("base64"), sig: real.sig };
        },
      }),
    });
    await expect(attestedRelease(w.deps, w.store, "a")).rejects.toThrow(/differs from the verified echo/);
    expect((await w.sp.get("a"))!.status).toBe("ambiguous");
    expect(w.pages.join()).toMatch(/release refused/);
  });

  it("bad signature on the identical msg is refused", async () => {
    const w = await world({
      transportHook: (t) => ({ candidate: t.candidate, confirm: async (req) => { const r = await t.confirm(req); const s = Buffer.from(r.sig, "base64"); s[0]! ^= 1; return { ...r, sig: s.toString("base64") }; } }),
    });
    await expect(attestedRelease(w.deps, w.store, "a")).rejects.toThrow(/signature does not verify/);
  });

  it("R41-c independent absence: present / unreachable / low round each refuse (signer providers faked absent)", async () => {
    for (const [res, re] of [
      [{ kind: "present", genesis: TN }, /present/],
      [{ kind: "error", reason: "timeout" }, /unavailable/],
      [{ kind: "absent", method: "idx404", round: 1105, idxRound: 1105, genesis: TN }, /round below/],
    ] as const) {
      const w = await world();
      w.ownProbe.result = res as never;
      await expect(attestedRelease(w.deps, w.store, "a")).rejects.toThrow(re);
      expect((await w.sp.get("a"))!.status).toBe("ambiguous");
    }
  });

  it("CLI pins: a stored txn that does not match the CLI's own pins is refused at step A", async () => {
    const w = await world();
    const forged = { ...w.deps, cfg: { ...w.deps.cfg, merchant: payer.addr.toString() } };
    await expect(attestedRelease(forged, w.store, "a")).rejects.toThrow(/merchant/);
  });
});

// rebuild the signer with the real helper but the SAME requester key the helper pins
async function setupWithRequester(pre: Awaited<ReturnType<typeof setup>>, keyId: string, w: Awaited<ReturnType<typeof realHelper>>) {
  const { MrSigner } = await import("../src/signer.js");
  const cfg = { ...pre.cfg, keyId };
  const signer = MrSigner.boot({ ...pre.deps, cfg, helper: w.helper, backend: w.backend });
  return { cfg, signer };
}
