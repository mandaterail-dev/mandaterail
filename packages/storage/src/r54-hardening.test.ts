/** R54-P3-1 (redact path tokens), R54-P3-2 (monitor refuses path-token URLs), R54-P3-3 (v14 RAISEs on a wrong operator). */
import { afterAll, describe, expect, it } from "vitest";
import pg from "pg";
import { redactSecrets } from "./backend.js";
import { parseHealthUrls } from "./monitor.js";
import { MIGRATIONS, migratePostgres, SchemaNameMismatchError } from "./pg.js";
import { closeShared, getPool, PG_URL } from "./test-helpers.js";

afterAll(closeShared);
const TOK = "0123456789abcdef0123456789abcdef"; // fake
describe("R54 hardening", () => {
  it("P3-1: redactSecrets hides a URL path token, listed or not, and credential query params", () => {
    const url = `https://shared.eu-central-1.getblock.io/${TOK}/`;
    const a = redactSecrets(`fetch ${url}v2/status failed`, [url]);
    expect(a).not.toContain(TOK);
    const b = redactSecrets(`fetch https://h.example/${TOK}/v2/status failed`);
    expect(b).not.toContain(TOK);
    expect(b).toContain("https://h.example/***/v2/status");
    expect(redactSecrets("GET https://svc.blockdaemon.com/x?apiKey=zzz123&y=1")).toBe("GET https://svc.blockdaemon.com/x?apiKey=***&y=1");
    expect(redactSecrets("https://mr-api.example/health down")).toBe("https://mr-api.example/health down");
  });
  it("P3-2: MONITOR_HEALTH_URLS refuses path tokens (query tokens stay allowed: they are stripped from keys and logs)", () => {
    expect(() => parseHealthUrls({ MONITOR_HEALTH_URLS: `https://shared.eu-central-1.getblock.io/${TOK}/health` })).toThrow(/token in the URL path/);
    expect(() => parseHealthUrls({ MONITOR_HEALTH_URLS: `https://a.example/${TOK}/health` })).toThrow(/token in the URL path/);
    expect(parseHealthUrls({ MONITOR_HEALTH_URLS: "https://a.example/health" })).toEqual(["https://a.example/health"]);
  });
  it.skipIf(!PG_URL)("P3-3: v14 RAISEs when an existing provider row has another operator; idempotent otherwise", async () => {
    const pool = await getPool();
    const v14 = MIGRATIONS.find((m) => m.version === 14)!.sql;
    const c = await pool.connect();
    try {
      await c.query("BEGIN");
      await c.query(v14); // rows already right: no-op
      const r = await c.query("SELECT host, operator_id FROM mr_network_provider WHERE network = 'mainnet' AND operator_id IN ('getblock','blockdaemon') ORDER BY 1");
      expect(r.rows).toEqual([{ host: "shared.eu-central-1.getblock.io", operator_id: "getblock" }, { host: "svc.blockdaemon.com", operator_id: "blockdaemon" }]);
      await c.query("SET LOCAL session_replication_role = replica");
      await c.query("UPDATE mr_network_provider SET operator_id = 'nodely' WHERE network = 'mainnet' AND host = 'svc.blockdaemon.com'");
      await c.query("SET LOCAL session_replication_role = origin");
      await expect(c.query(v14)).rejects.toThrow(/svc\.blockdaemon\.com is pinned to operator nodely, expected blockdaemon/);
    } finally {
      await c.query("ROLLBACK").catch(() => {});
      c.release();
    }
  });
  it.skipIf(!PG_URL)("R55-P3-1: v13 is getblock-only, v14 adds blockdaemon; a renamed applied migration is refused", async () => {
    expect(MIGRATIONS.find((m) => m.version === 13)!.name).toBe("mainnet-provider-getblock");
    expect(MIGRATIONS.find((m) => m.version === 13)!.sql).not.toContain("blockdaemon");
    expect(MIGRATIONS.find((m) => m.version === 14)!.name).toBe("mainnet-provider-blockdaemon");
    const admin = await getPool();
    const db = `mr_r55_${Date.now()}`;
    await admin.query(`CREATE DATABASE ${db}`);
    const p = new pg.Pool({ connectionString: PG_URL!.replace(/\/[^/]*$/, `/${db}`), max: 2 });
    const mig = () => migratePostgres(p, { network: "testnet", verifyNetwork: async (x) => ({ genesisHash: x.caip2.slice(9) }) });
    try {
      await mig();
      await p.query("UPDATE mr_schema SET name = 'mainnet-providers-getblock-blockdaemon' WHERE version = 13");
      await expect(mig()).rejects.toThrow(SchemaNameMismatchError);
      await expect(mig()).rejects.toThrow(/UPDATE mr_schema SET name = 'mainnet-provider-getblock' WHERE version = 13/); // R56-P3-1 hint
      await p.query("UPDATE mr_schema SET name = 'mainnet-provider-getblock' WHERE version = 13");
      await p.query("DELETE FROM mr_schema WHERE version = 14");
      await mig(); // a DB at the original v13 gets v14 (blockdaemon rows) applied
      const r = await p.query("SELECT operator_id FROM mr_network_provider WHERE network = 'mainnet' AND host = 'svc.blockdaemon.com'");
      expect(r.rows).toEqual([{ operator_id: "blockdaemon" }]);
    } finally {
      await p.end();
      await admin.query(`DROP DATABASE ${db} WITH (FORCE)`).catch(() => {});
    }
  });
  it.skipIf(!PG_URL)("v15: dRPC rows + the v11/v12 functions accept blockscan-full (same rule as blockscan)", async () => {
    const pool = await getPool();
    const r = await pool.query("SELECT operator_id FROM mr_network_provider WHERE network = 'mainnet' AND host = 'algorand.drpc.org'");
    expect(r.rows).toEqual([{ operator_id: "drpc" }]);
    const o = await pool.query("SELECT 1 FROM mr_signer_operator WHERE network = 'mainnet' AND operator = 'drpc'");
    expect(o.rowCount).toBe(1);
    const v11 = (await pool.query("SELECT pg_get_functiondef('mr_spend_release_attested_v11(text, text, bytea, bytea, text, text)'::regprocedure) AS d")).rows[0].d as string;
    expect(v11).toContain("IN ('blockscan', 'blockscan-full') THEN");
    // v16 renamed the v12 body to mr_spend_release_attested_v12 (the public 8-arg is now the pause + caps wrapper)
    const v12 = (await pool.query("SELECT pg_get_functiondef('mr_spend_release_attested_v12(text, text, bytea, bytea, bytea, bytea, text, text)'::regprocedure) AS d")).rows[0].d as string;
    expect(v12).toContain("NOT IN ('idx404', 'blockscan', 'blockscan-full')");
    expect(v12).toContain("(o->>'method' IN ('blockscan', 'blockscan-full') AND");
  });
});
