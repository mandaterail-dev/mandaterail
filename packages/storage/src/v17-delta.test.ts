/** R66-P3-4: v16 is frozen; v17 converges an earlier v16 state and backfills the caps ledger, which is append-only. */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createHash, randomBytes } from "node:crypto";
import pg from "pg";
import { toMicro } from "@mandaterail/core";
import { migratePostgres, PgSpendStore, schemaVersions } from "./pg.js";
import { PG_URL } from "./test-helpers.js";
import { v16Sql } from "./v16-resume.js";
import { V16_SQL_SHA256 } from "./v17-delta.js";
import { keyIdOf } from "./attest.js";

describe("R66-P3-4 v16 frozen", () => {
  it("v16Sql() is byte-identical to the reviewed text (changes go in v17+)", () => {
    expect(createHash("sha256").update(v16Sql()).digest("hex")).toBe(V16_SQL_SHA256);
  });
});

describe.skipIf(!PG_URL)("R66-P3-4 v17 converge + ledger backfill [postgres]", () => {
  let admin: pg.Pool, own: pg.Pool, dbName = "";
  const migrate = () => migratePostgres(own, { network: "testnet", verifyNetwork: async (p) => ({ genesisHash: p.caip2.slice(9) }) });
  beforeAll(async () => {
    admin = new pg.Pool({ connectionString: PG_URL, max: 2 });
    dbName = `mr_v17_${randomBytes(4).toString("hex")}`;
    await admin.query(`CREATE DATABASE ${dbName}`);
    own = new pg.Pool({ connectionString: PG_URL!.replace(/\/[^/]*$/, `/${dbName}`), max: 2 });
    await migrate();
  });
  afterAll(async () => { await own?.end(); if (dbName) await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`); await admin?.end(); });

  it("a v16 applied before R64/R65 (no ledger, no caps CHECK) gets them from v17, with a ledger row per past release", async () => {
    expect(await schemaVersions(own)).toContain(17);
    const s = new PgSpendStore(own, { store: "v17-a" });
    await s.reserve({ id: "a", payer: "A".repeat(58), amountMicro: toMicro("0.02"), caps: { perPaymentMicro: toMicro("1"), perDayMicro: toMicro("5") }, nowMs: Date.now() });
    const pub = randomBytes(32), kid = keyIdOf(pub);
    await own.query("INSERT INTO mr_signer_key (key_id, pubkey, network, margin_rounds, trust_domain, key_resource) VALUES ($1, $2, 'testnet', 10, 'gcp:mr-signer-test', 'projects/mr-signer-test/locations/us-east1/keyRings/mr/cryptoKeys/attest/cryptoKeyVersions/1')", [kid, pub]);
    // the earlier-v16 state: no ledger, no nonce-ledger trigger, no MainNet caps CHECK, a release recorded without the ledger
    const c = await own.connect();
    try {
      await c.query("DROP TRIGGER mr_release_nonce_ledger ON mr_release_nonce");
      await c.query("DROP TABLE mr_release_ledger");
      await c.query("ALTER TABLE mr_release_caps DROP CONSTRAINT mr_release_caps_mainnet_max");
      await c.query("SET session_replication_role = replica"); // stands in for a release made by the earlier v16 wrapper
      await c.query("INSERT INTO mr_release_nonce (nonce, store, spend_id, key_id, used_at) VALUES ($1, 'v17-a', 'a', $2, clock_timestamp() - interval '1 hour')", [randomBytes(32), kid]);
      await c.query("SET session_replication_role = origin");
      await c.query("DELETE FROM mr_schema WHERE version = 17");
    } finally { c.release(); }
    await migrate();
    expect((await own.query("SELECT store, spend_id, network, amount_micro::text AS amt FROM mr_release_ledger")).rows).toEqual([{ store: "v17-a", spend_id: "a", network: "testnet", amt: "20000" }]);
    expect((await own.query("SELECT count(*)::int AS n FROM pg_constraint WHERE conname = 'mr_release_caps_mainnet_max'")).rows[0].n).toBe(1);
    expect((await own.query("SELECT tgname FROM pg_trigger WHERE tgname IN ('mr_release_nonce_ledger', 'mr_release_ledger_guard', 'mr_release_ledger_guard_t') AND tgenabled = 'O' ORDER BY 1")).rows.map((r) => r.tgname))
      .toEqual(["mr_release_ledger_guard", "mr_release_ledger_guard_t", "mr_release_nonce_ledger"]);
    // idempotent: a second run of the v17 text changes nothing
    await own.query("DELETE FROM mr_schema WHERE version = 17");
    await migrate();
    expect((await own.query("SELECT count(*)::int AS n FROM mr_release_ledger")).rows[0].n).toBe(1);
  });

  it("the ledger refuses UPDATE / DELETE / TRUNCATE, even from its owner or a superuser session", async () => {
    await expect(own.query("DELETE FROM mr_release_ledger")).rejects.toThrow(/mr_release_ledger: DELETE refused/);
    await expect(own.query("TRUNCATE mr_release_ledger")).rejects.toThrow(/mr_release_ledger: TRUNCATE refused/);
    await expect(own.query("UPDATE mr_release_ledger SET amount_micro = 1")).rejects.toThrow(/mr_release_ledger: written only by/);
    expect((await own.query("SELECT count(*)::int AS n FROM mr_release_ledger")).rows[0].n).toBe(1);
  });

  it("refuses to converge a pre-R62 v16 (no mr_pause_log)", async () => {
    await own.query("ALTER TABLE mr_pause_log RENAME TO mr_pause_log_x");
    await own.query("DELETE FROM mr_schema WHERE version = 17");
    await expect(migrate()).rejects.toThrow(/v17: mr_pause_log is missing/);
    await own.query("ALTER TABLE mr_pause_log_x RENAME TO mr_pause_log");
    await migrate();
  });
});
