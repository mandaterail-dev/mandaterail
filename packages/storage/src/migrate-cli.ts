/**
 * Separate migrate command (apps never migrate; service roles can't DDL).
 *   STATE_ENV_FILE=/etc/mandaterail/state-migrate.env pnpm --filter @mandaterail/storage migrate
 * Uses MIGRATE_DATABASE_URL (a role allowed to create tables), else
 * DATABASE_URL. Prints versions only, never the URL.
 * R24-P3-1: MIGRATE_SET_ROLE=mr_owner makes a login admin role SET ROLE to the
 * NOLOGIN owner inside the migration. R24-P3-3: the chain is verified (algod
 * genesis + USDC ASA, ALGOD_URL optional) before the network marker is written;
 * NETWORK=mainnet also needs ALLOW_MAINNET=1.
 */
import pg from "pg";
import { loadStateEnvFile, pgPoolConfig, redactSecrets } from "./backend.js";
import { migratePostgres } from "./pg.js";

async function main() {
  loadStateEnvFile("migrate", process.env, ["MIGRATE_DATABASE_URL", "MIGRATE_SET_ROLE", "NETWORK", "ALLOW_MAINNET", "ALGOD_URL", "ALGOD_TOKEN"]);
  const url = process.env.MIGRATE_DATABASE_URL || process.env.DATABASE_URL;
  if (!url) throw new Error("MIGRATE_DATABASE_URL (or DATABASE_URL) is required");
  const pool = new pg.Pool({ ...pgPoolConfig(url, process.env), max: 1 });
  pool.on("error", () => undefined);
  try {
    const r = await migratePostgres(pool);
    console.log(`migrate: schema v${r.from} -> v${r.to}; network marker ${r.network}${r.role ? `; as role ${r.role}` : ""}`);
  } finally {
    await pool.end();
  }
}
main().catch((e) => {
  console.error("migrate failed:", redactSecrets(String(e?.message ?? e), [process.env.MIGRATE_DATABASE_URL, process.env.DATABASE_URL]));
  process.exit(1);
});
