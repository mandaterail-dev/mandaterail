/**
 * internal reviewer run 30, R30-P3-1: the migrate session pins search_path and timeouts and
 * refuses while ALTER DATABASE SET / ALTER ROLE ALL IN DATABASE SET rows exist.
 * (Cluster-wide ALTER ROLE ALL SET uses the same check, setdatabase = 0; it is not
 * exercised here because it would leak into concurrently running tests.)
 */
import { afterAll, describe, expect, it } from "vitest";
import pg from "pg";
import { DatabaseSettingsError, migratePostgres } from "./pg.js";
import { closeShared, getPool, PG_URL, uid } from "./test-helpers.js";

afterAll(closeShared);
const verifyNetwork = async (p: { caip2: string }) => ({ genesisHash: p.caip2.slice(9) });

describe.skipIf(!PG_URL)("R30-P3-1 migrate session", () => {
  async function freshDb(tag: string) {
    const admin = await getPool();
    const db = `mr_r30_${uid(tag).replace(/-/g, "_")}`;
    await admin.query(`CREATE DATABASE ${db}`);
    const url = PG_URL!.replace(/\/[^/]*$/, `/${db}`);
    const pool = new pg.Pool({ connectionString: url, max: 2 });
    pool.on("error", () => undefined);
    return { db, pool, cleanup: async () => { await pool.end(); await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); } };
  }

  it("refuses with ALTER DATABASE SET or ALTER ROLE ALL IN DATABASE SET; works after RESET", async () => {
    const h = await freshDb("dbset");
    try {
      await migratePostgres(h.pool, { network: "testnet", verifyNetwork });
      for (const [set, reset] of [
        [`ALTER DATABASE ${h.db} SET search_path = evil`, `ALTER DATABASE ${h.db} RESET ALL`],
        [`ALTER ROLE ALL IN DATABASE ${h.db} SET statement_timeout = 1`, `ALTER ROLE ALL IN DATABASE ${h.db} RESET ALL`],
      ]) {
        await h.pool.query(set!);
        await expect(migratePostgres(h.pool, { network: "testnet", verifyNetwork }), set).rejects.toBeInstanceOf(DatabaseSettingsError);
        await h.pool.query(reset!);
        await expect(migratePostgres(h.pool, { network: "testnet", verifyNetwork })).resolves.toMatchObject({ network: "testnet" });
      }
    } finally {
      await h.cleanup();
    }
  }, 60_000);

  it("pins search_path and timeouts even if the session had others", async () => {
    const h = await freshDb("pin");
    try {
      await h.pool.query("CREATE SCHEMA evil");
      const pool = new pg.Pool({ connectionString: PG_URL!.replace(/\/[^/]*$/, `/${h.db}`), max: 1, options: "-c search_path=evil -c statement_timeout=50 -c lock_timeout=50" });
      pool.on("error", () => undefined);
      try {
        await migratePostgres(pool, { network: "testnet", verifyNetwork });
      } finally {
        await pool.end();
      }
      const t = await h.pool.query("SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relname = 'mr_spend'");
      expect(t.rows.map((r) => r.nspname)).toEqual(["public"]);
    } finally {
      await h.cleanup();
    }
  }, 60_000);
});
