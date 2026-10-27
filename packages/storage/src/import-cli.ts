/**
 * Usage (MIGRATE_DATABASE_URL or DATABASE_URL; STATE_ENV_FILE default
 * /etc/mandaterail/state-migrate.env):
 *   pnpm --filter @mandaterail/storage import-json -- --console apps/console/data/mandates.json \
 *        --receipts apps/demo-api/data/receipts.json
 * Migrates first; idempotent; prints counts only (never URLs).
 */
import { migratePostgres } from "./pg.js";
import pg from "pg";
import { loadStateEnvFile, pgPoolConfig, redactSecrets } from "./backend.js";
import { importConsoleJson, importInTransaction, importReceiptsJson } from "./import-json.js";

const args = process.argv.slice(2);
const arg = (n: string) => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : undefined;
};

async function main() {
  loadStateEnvFile("migrate", process.env, ["MIGRATE_DATABASE_URL", "MIGRATE_SET_ROLE", "NETWORK", "ALLOW_MAINNET", "ALGOD_URL", "ALGOD_TOKEN"]);
  const url = process.env.MIGRATE_DATABASE_URL || process.env.DATABASE_URL;
  if (!url) throw new Error("MIGRATE_DATABASE_URL (or DATABASE_URL) is required");
  const pool = new pg.Pool({ ...pgPoolConfig(url, process.env), max: 2 });
  pool.on("error", () => undefined);
  // R25-P3-2: the admin login role imports as the NOLOGIN owner via an awaited
  // SET LOCAL ROLE inside the import transaction; a failure is fatal (exit 1).
  const setRole = (process.env.MIGRATE_SET_ROLE ?? "").trim() || undefined;
  const b = { pool, close: () => pool.end() };
  try {
    await migratePostgres(b.pool);
    const c = arg("--console");
    const r = arg("--receipts");
    if (!c && !r) throw new Error("nothing to import: pass --console <file> and/or --receipts <file>");
    const res = await importInTransaction(b.pool, setRole, async (q) => ({
      console: c ? await importConsoleJson(q, c, { store: arg("--console-store") }) : undefined,
      receipts: r ? await importReceiptsJson(q, r, { store: arg("--receipts-store") }) : undefined,
    }));
    if (res.console) console.log("console:", JSON.stringify(res.console));
    if (res.receipts) console.log("receipts:", JSON.stringify(res.receipts));
  } finally {
    await b.close();
  }
}
main().catch((e) => {
  console.error("import failed:", redactSecrets(String(e?.message ?? e), [process.env.MIGRATE_DATABASE_URL, process.env.DATABASE_URL]));
  process.exit(1);
});
