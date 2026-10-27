/**
 * internal reviewer run 31, R31-P3-4: migrate re-checks database-wide / ALTER ROLE ALL settings
 * inside the advisory-lock transaction after DDL (a setting added concurrently aborts it),
 * and the session timeouts are bounded (never 0).
 */
import { afterAll, describe, expect, it } from "vitest";
import pg from "pg";
import { DatabaseSettingsError, migratePostgres } from "./pg.js";
import { closeShared, getPool, PG_URL, uid } from "./test-helpers.js";

afterAll(closeShared);
const verifyNetwork = async (p: { caip2: string }) => ({ genesisHash: p.caip2.slice(9) });

describe.skipIf(!PG_URL)("R31-P3-4 migrate re-check + bounded timeouts", () => {
  async function freshDb(tag: string) {
    const admin = await getPool();
    const db = `mr_r31_${uid(tag).replace(/-/g, "_")}`;
    await admin.query(`CREATE DATABASE ${db}`);
    const pool = new pg.Pool({ connectionString: PG_URL!.replace(/\/[^/]*$/, `/${db}`), max: 3 });
    pool.on("error", () => undefined);
    return { db, pool, cleanup: async () => { await pool.end(); await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); } };
  }

  it("a setting added after the first check (during DDL) aborts and rolls back", async () => {
    const h = await freshDb("race");
    try {
      const other = await h.pool.connect();
      try {
        await expect(
          migratePostgres(h.pool, {
            network: "testnet",
            verifyNetwork,
            afterDdlForTest: async () => {
              await other.query(`ALTER DATABASE ${h.db} SET search_path = evil`);
            },
          }),
        ).rejects.toBeInstanceOf(DatabaseSettingsError);
        const t = await other.query("SELECT to_regclass('public.mr_schema') AS t");
        expect(t.rows[0].t).toBeNull();
        await other.query(`ALTER DATABASE ${h.db} RESET ALL`);
      } finally {
        other.release();
      }
      await expect(migratePostgres(h.pool, { network: "testnet", verifyNetwork })).resolves.toMatchObject({ network: "testnet" });
    } finally {
      await h.cleanup();
    }
  }, 60_000);

  it("statement / lock / idle timeouts are bounded, not 0", async () => {
    const h = await freshDb("tmo");
    try {
      let seen: Record<string, string> = {};
      await migratePostgres(h.pool, {
        network: "testnet",
        verifyNetwork,
        afterDdlForTest: async (c) => {
          const r = await c.query("SELECT current_setting('statement_timeout') s, current_setting('lock_timeout') l, current_setting('idle_in_transaction_session_timeout') i");
          seen = r.rows[0];
        },
      });
      for (const v of Object.values(seen)) expect(v).not.toBe("0");
      expect(seen).toEqual({ s: "10min", l: "1min", i: "10min" });
    } finally {
      await h.cleanup();
    }
  }, 60_000);
});
