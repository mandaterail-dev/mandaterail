import { afterAll, describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { toMicro } from "@mandaterail/core";
import { PgSpendStore } from "./pg.js";
import { reconcileSpendPg, releaseSpendManually, spendAudit, SpendOpError } from "./spend-ops.js";
import { closeShared, getPool, PG_URL, uid, TEST_PROVIDERS } from "./test-helpers.js";
import { TESTNET_PROFILE } from "@mandaterail/core";
const quiet = () => undefined;

afterAll(closeShared);
const run = promisify(execFile);
const caps = { perPaymentMicro: toMicro("1"), perDayMicro: toMicro("5") };

async function seed(store: string) {
  const s = new PgSpendStore(await getPool(), { store });
  const now = Date.now();
  const mk = async (id: string, txId: string | null, lastValid: number | null, outcome: "ambiguous" | "pending") => {
    await s.reserve({ id, payer: "P", amountMicro: toMicro("1"), caps, nowMs: now - 3600_000 });
    if (txId) await s.attachTxId(id, txId, now, lastValid);
    if (outcome === "ambiguous") await s.finalize(id, "ambiguous", now);
  };
  await mk("onchain", "TXOK", 1000, "ambiguous");
  await mk("expired", "TXGONE", 900, "ambiguous");
  await mk("young", "TXNEW", 2000, "ambiguous");
  await mk("notx", null, null, "ambiguous");
  await mk("crashed", "TXGONE2", 900, "pending");
  return s;
}

function fakeIndexer(): Promise<{ url: string; server: Server }> {
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      if (req.url === "/health") return res.end(JSON.stringify({ round: 1500 }));
      if (req.url === "/v2/blocks/0") return res.end(JSON.stringify({ "genesis-id": "testnet-v1.0", "genesis-hash": TESTNET_PROFILE.caip2.slice(9) }));
      if (req.url?.endsWith("/TXOK")) return res.end(JSON.stringify({ transaction: { "confirmed-round": 990 } }));
      res.statusCode = 404;
      res.end("{}");
    }).listen(0, "127.0.0.1", () => {
      const a = server.address() as { port: number };
      resolve({ url: `http://127.0.0.1:${a.port}`, server });
    });
  });
}

describe.skipIf(!PG_URL)("R18-P3-2 reconcile + manual release [postgres]", () => {
  it("attachTxId stores txId + lastValid only while pending", async () => {
    const s = new PgSpendStore(await getPool(), { store: uid("tx") });
    await s.reserve({ id: "a", payer: "P", amountMicro: 1n, caps, nowMs: Date.now() });
    expect(await s.attachTxId("a", "TXA", Date.now(), 1234)).toBe(true);
    expect(await s.get("a")).toMatchObject({ txId: "TXA", lastValid: 1234, status: "pending" });
    await s.finalize("a", "settled", Date.now());
    expect(await s.attachTxId("a", "OTHER", Date.now(), 1)).toBe(false);
    expect((await s.get("a"))!.txId).toBe("TXA");
  });

  it("reconcile: confirmed -> settled, past lastValid -> needsRelease (R22-P3-1: reconcile never releases), else unknown; audited; overlapping run skipped", async () => {
    const { indexerTxCheck } = await import("@mandaterail/core");
    const store = uid("rec");
    const s = await seed(store);
    const { url, server } = await fakeIndexer();
    try {
      const pool = await getPool();
      // R27-P3-5: the check refuses loopback hosts; route an allowlisted test host to the fake (custom fetch = test flag).
      const viaFake = ((input: string | URL, init?: RequestInit) => fetch(String(input).replace("https://idx.example", url), init)) as typeof fetch;
      const check = indexerTxCheck("https://idx.example", viaFake, { profile: { ...TESTNET_PROFILE, providerAllowlist: [{ host: "idx.example", operator: "test" }] }, unsafeTestCustomFetch: true });
      expect(await reconcileSpendPg(pool, { store, check, dryRun: true })).toEqual({ checked: 5, settled: 1, released: 0, needsRelease: 2, unknown: 2 });
      expect((await s.get("onchain"))!.status).toBe("ambiguous"); // dry run changed nothing
      // overlapping run (lock held by another session) is skipped
      const holder = await pool.connect();
      await holder.query("SELECT pg_advisory_lock(hashtextextended($1, 0))", [`mr:reconcile:${store}`]);
      expect(await reconcileSpendPg(pool, { store, check })).toMatchObject({ skipped: "locked" });
      await holder.query("SELECT pg_advisory_unlock(hashtextextended($1, 0))", [`mr:reconcile:${store}`]);
      holder.release();
      expect(await reconcileSpendPg(pool, { store, check })).toEqual({ checked: 5, settled: 1, released: 0, needsRelease: 2, unknown: 2 });
      expect((await s.get("onchain"))!.status).toBe("settled");
      expect((await s.get("expired"))!.status).toBe("ambiguous"); // cap still held until mr_release frees it
      expect((await s.get("crashed"))!.status).toBe("ambiguous");
      expect((await s.get("young"))!.status).toBe("ambiguous");
      expect((await s.get("notx"))!.status).toBe("ambiguous");
      expect(await spendAudit(pool, store, "expired")).toEqual([]);
      expect(await spendAudit(pool, store, "crashed")).toMatchObject([{ actor: expect.stringMatching(/\(label, untrusted: reconcile\)$/), action: "chain-reconcile-expired", from_status: "pending", to_status: "ambiguous" }]);
      expect(await spendAudit(pool, store, "onchain")).toMatchObject([{ action: "chain-reconcile", from_status: "ambiguous", to_status: "settled" }]);
      // second run: nothing new changes; the two expired rows are still flagged
      expect(await reconcileSpendPg(pool, { store, check })).toEqual({ checked: 4, settled: 0, released: 0, needsRelease: 2, unknown: 2 });
    } finally {
      server.close();
    }
  });

  it("manual release needs operator + reason, only from pending/ambiguous, and is audited (forced)", async () => {
    const store = uid("rel");
    const s = await seed(store);
    const pool = await getPool();
    await expect(releaseSpendManually(pool, { store, id: "notx", operator: "", reason: "checked by hand", force: true, network: "testnet", warn: quiet })).rejects.toThrow(SpendOpError);
    await expect(releaseSpendManually(pool, { store, id: "notx", operator: "david", reason: "short", force: true, network: "testnet", warn: quiet })).rejects.toThrow(/reason/);
    await expect(releaseSpendManually(pool, { store, id: "missing", operator: "david", reason: "checked by hand", force: true, network: "testnet", warn: quiet })).rejects.toThrow(/not found/);
    expect(await releaseSpendManually(pool, { store, id: "notx", operator: "david", reason: "no tx on chain; facilitator confirmed failure", force: true, network: "testnet", warn: quiet })).toEqual({ id: "notx", from: "ambiguous", to: "released", forced: true });
    // R19-P3-3: idempotent
    expect(await releaseSpendManually(pool, { store, id: "notx", operator: "david", reason: "again, already released", force: true, network: "testnet", warn: quiet })).toEqual({ id: "notx", from: "released", to: "released", alreadyReleased: true });
    expect(await spendAudit(pool, store, "notx")).toMatchObject([
      { actor: expect.stringMatching(/\(label, untrusted: david\)$/), action: "manual-release-forced", from_status: "ambiguous", to_status: "released", reason: "FORCED (no chain proof): no tx on chain; facilitator confirmed failure" },
    ]);
    expect(await s.spentSinceMicro("P", 0)).toBe(toMicro("4"));
  });

  it("R19-P2-1 / R24-P2-1: release without --force needs two providers' 404 + round > lastValid + margin; both audited", async () => {
    const { twoProviderNoConfirmProof } = await import("@mandaterail/core");
    const store = uid("proof");
    const s = await seed(store);
    const pool = await getPool();
    const { url, server } = await fakeIndexer(); // round 1500
    const b = await fakeIndexer();
    try {
      // R25-P2-1: loopback hosts are refused, so allowlisted names are routed to the local fakes.
      const route: Record<string, string> = { "idx-a.example": url, "idx-b.example": b.url };
      const viaFakes = ((input: string | URL, init?: RequestInit) => {
        const u = new URL(String(input));
        return fetch(`${route[u.host]!.replace(/\/$/, "")}${u.pathname}${u.search}`, init);
      }) as typeof fetch;
      const two = (marginRounds?: number) => twoProviderNoConfirmProof([{ url: "https://idx-a.example", kind: "indexer" }, { url: "https://idx-b.example", kind: "indexer" }], viaFakes, { profile: { ...TESTNET_PROFILE, providerAllowlist: TEST_PROVIDERS }, marginRounds, unsafeTestCustomFetch: true });
      const prove = two();
      const rel = (id: string, extra: object = {}) => releaseSpendManually(pool, { store, id, operator: "david", reason: "operator check", prove, ...extra });
      await expect(releaseSpendManually(pool, { store, id: "expired", operator: "david", reason: "operator check" })).rejects.toThrow(/chain proof required/);
      await expect(rel("notx")).rejects.toThrow(/no txId/);
      await expect(rel("young")).rejects.toThrow(/not past lastValid 2000/); // could still confirm
      await expect(rel("onchain")).rejects.toThrow(/found on the indexer/);
      await expect(releaseSpendManually(pool, { store, id: "expired", operator: "d", reason: "operator check", prove: two(700) })).rejects.toThrow(/margin 700/);
      const ok = await rel("expired");
      const hA = "idx-a.example", hB = "idx-b.example";
      expect(ok).toMatchObject({ from: "ambiguous", to: "released", proof: { ok: true, txId: "TXGONE", lastValid: 900, observations: [{ provider: hA, round: 1500, status: 404 }, { provider: hB, round: 1500, status: 404 }] } });
      // R23-P2-1 / R24-P2-1: both observations live in typed columns, checked by the DB
      expect((await spendAudit(pool, store, "expired"))[0]).toMatchObject({
        action: "manual-release", reason: "operator check", proof_tx_id: "TXGONE", proof_genesis_hash: TESTNET_PROFILE.caip2.slice(9),
        proof_round_checked: "1500", proof_last_valid: "900", proof_margin: 10, proof_indexer_status: 404, proof_provider: hA, proof_kind: "indexer",
        proof2_provider: hB, proof2_kind: "indexer", proof2_genesis_hash: TESTNET_PROFILE.caip2.slice(9), proof2_round_checked: "1500", proof2_status: 404,
        proof_operator: "test-op-a", proof2_operator: "test-op-b",
      });
      for (const id of ["young", "onchain", "notx"]) expect((await s.get(id))!.status).toBe("ambiguous");
      // a settled row is never released, even forced
      await expect(rel("onchain", { force: true, network: "testnet", warn: quiet })).resolves.toMatchObject({ forced: true }); // ambiguous -> forced ok
      const s2 = new PgSpendStore(pool, { store });
      await s2.reserve({ id: "done", payer: "Q", amountMicro: 1n, caps, nowMs: Date.now() });
      await s2.finalize("done", "settled", Date.now());
      await expect(rel("done", { force: true, network: "testnet", warn: quiet })).rejects.toThrow(/settled/);
    } finally {
      server.close();
      b.server.close();
    }
  });

  it("R20-P3-1: --force refused on MainNet / without explicit network; loud warning on TestNet", async () => {
    const pool = await getPool();
    const store = uid("force");
    const s = await seed(store);
    const warns: string[] = [];
    const base = { store, id: "notx", operator: "david", reason: "force policy check", force: true } as const;
    await expect(releaseSpendManually(pool, { ...base, network: "mainnet", warn: (m) => warns.push(m) })).rejects.toThrow(/refused on MainNet/);
    await expect(releaseSpendManually(pool, { ...base, warn: (m) => warns.push(m) })).rejects.toThrow(/explicit NETWORK=testnet/);
    expect(warns).toEqual([]);
    expect((await s.get("notx"))!.status).toBe("ambiguous");
    await releaseSpendManually(pool, { ...base, network: "testnet", warn: (m) => warns.push(m) });
    expect(warns).toHaveLength(1);
    expect(warns[0]).toMatch(/^WARNING: --force .*WITHOUT chain proof/);
  });

  it("T11: staleSpendCounts counts old pending/ambiguous only; auditOwnerRisk flags the owner role", async () => {
    const pool = await getPool();
    const { staleSpendCounts, auditOwnerRisk } = await import("./spend-ops.js");
    const store = uid("stale");
    const s = new PgSpendStore(pool, { store });
    const t = Date.now();
    await s.reserve({ id: "old", payer: "P", amountMicro: 1n, caps, nowMs: t - 3_600_000 });
    await s.reserve({ id: "new", payer: "P", amountMicro: 1n, caps, nowMs: t });
    await s.reserve({ id: "oldsettled", payer: "P", amountMicro: 1n, caps, nowMs: t - 3_600_000 });
    await s.finalize("oldsettled", "settled", t);
    const c = await staleSpendCounts(pool, { store, olderThanMs: 30 * 60_000, nowMs: t });
    expect(c).toMatchObject({ pending: 1, ambiguous: 0 });
    expect(c.oldestAgeMs).toBeGreaterThanOrEqual(3_600_000);
    expect(await staleSpendCounts(pool, { store, olderThanMs: 2 * 3_600_000, nowMs: t })).toEqual({ pending: 0, ambiguous: 0, oldestAgeMs: null, needsReleaseOverdue: 0, needsReleaseOldestAgeMs: null });
    expect(await auditOwnerRisk(pool)).toMatch(/owns|superuser/); // test role owns the tables
    // A non-owner role with exactly the T11 grants: no risk, can reconcile writes, cannot touch the trigger.
    const created = await pool
      .query("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='mr_t11_rec') THEN CREATE ROLE mr_t11_rec LOGIN; END IF; END $$")
      .then(() => true, () => false);
    if (created) {
      await pool.query("GRANT SELECT ON mr_spend, mr_spend_audit TO mr_t11_rec; GRANT EXECUTE ON FUNCTION mr_spend_release(text, text, text, text, text, text, bigint, integer, text, text, text, bigint, integer, text, text, text, bigint, integer) TO mr_t11_rec"); // R22-P3-1 release grant
      const u = new URL(PG_URL!);
      u.username = "mr_t11_rec";
      u.password = "";
      const pg = (await import("pg")).default;
      const p2 = new pg.Pool({ connectionString: u.toString(), max: 1 });
      try {
        expect(await auditOwnerRisk(p2)).toBeNull();
        await expect(p2.query("ALTER TABLE mr_spend_audit DISABLE TRIGGER mr_spend_audit_no_update")).rejects.toThrow(/owner|permission/);
        await expect(p2.query("DELETE FROM mr_spend WHERE store = $1", [store])).rejects.toThrow(/permission/);
        await releaseSpendManually(p2, { store, id: "old", operator: "t11", reason: "non-owner role check", force: true, network: "testnet", warn: quiet });
      } finally {
        await p2.end();
      }
    }
  });

  it("R19-P3-1: mr_spend_audit is append-only (UPDATE/DELETE/TRUNCATE refused), v4 applied", async () => {
    const pool = await getPool();
    const { schemaVersions } = await import("./pg.js");
    expect(await schemaVersions(pool)).toContain(4);
    const store = uid("ao");
    await seed(store);
    await releaseSpendManually(pool, { store, id: "notx", operator: "david", reason: "append-only check", force: true, network: "testnet", warn: quiet });
    await expect(pool.query("UPDATE mr_spend_audit SET reason = 'x' WHERE store = $1", [store])).rejects.toThrow(/append-only/);
    await expect(pool.query("DELETE FROM mr_spend_audit WHERE store = $1", [store])).rejects.toThrow(/append-only/);
    await expect(pool.query("TRUNCATE mr_spend_audit")).rejects.toThrow(/append-only/);
    const { rows } = await pool.query<{ ok: boolean }>("SELECT has_table_privilege('public', 'mr_spend_audit', 'UPDATE') OR has_table_privilege('public', 'mr_spend_audit', 'DELETE') AS ok");
    expect(rows[0]!.ok).toBe(false);
    expect(await spendAudit(pool, store, "notx")).toHaveLength(1);
  });

  it("spend CLI: reconcile + release, JSON lines, exit codes, no URLs printed", async () => {
    const store = uid("cli");
    await seed(store);
    const { url, server } = await fakeIndexer();
    try {
      const dir = mkdtempSync(path.join(tmpdir(), "mr-rec-"));
      const envFile = path.join(dir, "state-reconcile.env");
      writeFileSync(envFile, `DATABASE_URL=${PG_URL}\nINDEXER_URL=${url}\nNETWORK=testnet\nMR_TEST_ALLOW_AUDIT_OWNER=1\n`);
      const tsx = path.resolve(__dirname, "../node_modules/.bin/tsx");
      const cli = path.resolve(__dirname, "spend-cli.ts");
      const env = { ...process.env, STATE_ENV_FILE: envFile } as NodeJS.ProcessEnv;
      delete env.DATABASE_URL;
      delete env.NETWORK;
      // R20-P3-4: as the owner role, reconcile refuses unless the test override is set
      const ownerFile = path.join(dir, "owner.env");
      writeFileSync(ownerFile, `DATABASE_URL=${PG_URL}\nINDEXER_URL=${url}\nNETWORK=testnet\n`);
      const own = await run(tsx, [cli, "reconcile", "--store", store], { env: { ...env, STATE_ENV_FILE: ownerFile } }).catch((e) => e as { code: number; stderr: string });
      expect((own as { code: number }).code).toBe(1);
      expect((own as { stderr: string }).stderr).toMatch(/refusing to run as this DB role: .*(mr_spend_audit|superuser)/);
      const ownMn = await run(tsx, [cli, "reconcile", "--store", store], { env: { ...env, NETWORK: "mainnet" } }).catch((e) => e as { code: number; stderr: string });
      expect((ownMn as { stderr: string }).stderr).toMatch(/refusing to run as this DB role/); // override ignored on MainNet
      // T11 monitor: health + stale counts
      const mon = await run(tsx, [cli, "monitor", "--store", store, "--older-than-min", "1"], { env: { ...env, MONITOR_HEALTH_URLS: `${url}/health` } }).catch((e) => e as { code: number; stdout: string; stderr: string });
      expect((mon as { stderr: string }).stderr).toMatch(/^ALERT .*"stale":\{"pending":\d+,"ambiguous":\d+/m);
      expect((mon as { code: number }).code).toBe(2); // R21-P3-1: stale rows exit non-zero
      expect((mon as { stderr: string }).stderr).toMatch(/no pager configured/);
      const monEmpty = await run(tsx, [cli, "monitor", "--store", store], { env: { ...env, MONITOR_HEALTH_URLS: "" } }).catch((e) => e as { code: number; stderr: string });
      expect((monEmpty as { code: number }).code).toBe(1);
      expect((monEmpty as { stderr: string }).stderr).toMatch(/MONITOR_HEALTH_URLS is empty/);
      // R27-P3-5: the CLI's reconcile check refuses a loopback INDEXER_URL (allowlist + host check + pinning), changing nothing ...
      const r = (await run(tsx, [cli, "reconcile", "--store", store], { env }).catch((e) => e)) as { code: number; stdout: string; stderr: string };
      expect(r.code).toBe(1);
      expect(r.stderr).toMatch(/loopback \/ localhost/);
      // ... so the same reconcile runs in-process against the fake through an allowlisted test host.
      const { indexerTxCheck } = await import("@mandaterail/core");
      const viaFake = ((input: string | URL, init?: RequestInit) => fetch(String(input).replace("https://idx.example", url), init)) as typeof fetch;
      const check = indexerTxCheck("https://idx.example", viaFake, { profile: { ...TESTNET_PROFILE, providerAllowlist: [{ host: "idx.example", operator: "test" }] }, unsafeTestCustomFetch: true });
      expect(await reconcileSpendPg(await getPool(), { store, check })).toMatchObject({ checked: 5, settled: 1, released: 0, needsRelease: 2, unknown: 2 });
      const noForce = await run(tsx, [cli, "release", "--store", store, "--id", "notx", "--operator", "david", "--reason", "verified on explorer: never broadcast"], { env }).catch((e) => e as { code: number; stderr: string });
      expect((noForce as { code: number }).code).toBe(1);
      expect((noForce as { stderr: string }).stderr).toMatch(/--force/);
      const forceArgs = [cli, "release", "--store", store, "--id", "notx", "--operator", "david", "--reason", "verified on explorer: never broadcast", "--force"];
      const mn = await run(tsx, forceArgs, { env: { ...env, NETWORK: "mainnet" } }).catch((e) => e as { code: number; stderr: string });
      expect((mn as { code: number }).code).toBe(1);
      expect((mn as { stderr: string }).stderr).toMatch(/refused on MainNet/);
      const badMargin = await run(tsx, [cli, "release", "--store", store, "--id", "notx", "--operator", "david", "--reason", "verified on explorer: never broadcast", "--margin-rounds", "-3"], { env }).catch((e) => e as { code: number; stderr: string });
      expect((badMargin as { stderr: string }).stderr).toMatch(/non-negative integer/);
      // R26-P3-5: a set PROOF2_URL (and a loopback INDEXER_URL that a proof would refuse) doesn't break --force
      const rel = await run(tsx, forceArgs, { env: { ...env, PROOF2_URL: "https://testnet-api.4160.nodely.dev", PROOF2_KIND: "algod" } });
      expect(rel.stderr).toMatch(/WARNING: --force .*WITHOUT chain proof/);
      expect(JSON.parse(rel.stdout.trim())).toMatchObject({ cmd: "release", to: "released", operator: "david", operatorTrusted: false, forced: true });
      const again = await run(tsx, [cli, "release", "--store", store, "--id", "notx", "--operator", "david", "--reason", "verified on explorer: never broadcast"], { env });
      expect(JSON.parse(again.stdout.trim())).toMatchObject({ alreadyReleased: true, note: expect.stringMatching(/already released/) });
      const bad = await run(tsx, [cli, "release", "--store", store, "--id", "notx", "--operator", "david", "--reason", "x"], { env }).catch((e) => e as { code: number; stderr: string });
      expect((bad as { code: number }).code).toBe(1);
      expect(r.stdout + rel.stdout + (bad as { stderr: string }).stderr).not.toContain(PG_URL!);
    } finally {
      server.close();
    }
  });
});
