/**
 * ST-P3-5: one-shot import of the Phase-1 JSON files into Postgres.
 * Idempotent (ON CONFLICT DO NOTHING), keeps file order.
 *  - console mandates.json: v2 { mandate, server } records or legacy bare
 *    mandates. `server_verified` is set only if the file says verified AND
 *    the AC2 signature re-verifies now (never trust the file alone).
 *  - demo-api receipts.json: receipts + a `settled` spend row per receipt
 *    (id "receipt:<receiptId>") so today's spend counts toward the daily cap.
 */
import { readFile } from "node:fs/promises";
import type { Pool, PoolClient } from "pg";
import { IntentMandateSchema } from "@mandaterail/schema";
import { toMicro, verifyAc2Signature } from "@mandaterail/core";
import { PgSpendStore } from "./pg.js";

export type ImportResult = { read: number; imported: number; skipped: number; invalid: number; verified?: number };

async function readArray(file: string): Promise<unknown[]> {
  const parsed = JSON.parse(await readFile(file, "utf8")) as unknown;
  if (!Array.isArray(parsed)) throw new Error(`${file}: expected a JSON array`);
  return parsed;
}

export async function importConsoleJson(pool: Pool, file: string, opts: { store?: string } = {}): Promise<ImportResult> {
  const store = opts.store ?? "console";
  const items = await readArray(file);
  const out: ImportResult = { read: items.length, imported: 0, skipped: 0, invalid: 0, verified: 0 };
  for (const item of items) {
    const isRecord = !!item && typeof item === "object" && "mandate" in item && "server" in item;
    const raw = isRecord ? (item as { mandate: unknown }).mandate : item;
    const parsed = IntentMandateSchema.safeParse(raw);
    if (!parsed.success) {
      out.invalid++;
      continue;
    }
    const m = parsed.data;
    const server = isRecord ? ((item as { server?: { signatureVerified?: boolean; verifiedAt?: string } }).server ?? {}) : {};
    let verified = false;
    if (server.signatureVerified === true && m.signature) {
      const v = await verifyAc2Signature({ mandate: m, principal: m.principal, signature: m.signature }, { allowUnsigned: false });
      verified = v.ok;
    }
    const r = await pool.query(
      `INSERT INTO mr_mandates (store, id, mandate, server_verified, verified_at)
       VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`,
      [store, m.id, JSON.stringify(m), verified, verified ? (server.verifiedAt ?? new Date().toISOString()) : null],
    );
    if (r.rowCount === 1) {
      out.imported++;
      if (verified) out.verified!++;
    } else out.skipped++;
  }
  return out;
}

type ReceiptJson = { receiptId?: unknown; payer?: unknown; amount?: unknown; createdAt?: unknown; txId?: unknown };

export async function importReceiptsJson(
  pool: Pool,
  file: string,
  opts: { store?: string; spendStore?: string } = {},
): Promise<ImportResult & { spendRows: number }> {
  const store = opts.store ?? "demo-api";
  const spend = new PgSpendStore(pool, { store: opts.spendStore ?? store });
  const items = await readArray(file);
  const out = { read: items.length, imported: 0, skipped: 0, invalid: 0, spendRows: 0 };
  for (const item of items as ReceiptJson[]) {
    const ok =
      item && typeof item.receiptId === "string" && typeof item.payer === "string" &&
      typeof item.amount === "string" && typeof item.createdAt === "string" && Number.isFinite(Date.parse(item.createdAt));
    let micro = 0n;
    try {
      micro = ok ? toMicro(item.amount as string) : 0n;
    } catch {
      micro = 0n;
    }
    if (!ok || micro <= 0n) {
      out.invalid++;
      continue;
    }
    const r = await pool.query(
      "INSERT INTO mr_receipts (store, receipt_id, receipt) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
      [store, item.receiptId, JSON.stringify(item)],
    );
    if (r.rowCount === 1) out.imported++;
    else out.skipped++;
    if (
      await spend.recordSettled({
        id: `receipt:${item.receiptId as string}`,
        payer: item.payer as string,
        amountMicro: micro,
        createdMs: Date.parse(item.createdAt as string),
        txId: typeof item.txId === "string" ? item.txId : null,
      })
    ) out.spendRows++;
  }
  return out;
}

export class ImportRoleError extends Error {}

/**
 * R25-P3-2: run an import in ONE transaction as `setRole` (the NOLOGIN owner,
 * reached through the migrate admin's SET membership). SET LOCAL ROLE is
 * awaited inside the transaction and any failure is fatal (rolls back and
 * throws): nothing is ever written as the login role by accident. The role
 * is then re-checked with current_user. The client is handed to `fn` as a
 * Pool-shaped object (only .query is used by the importers).
 */
export async function importInTransaction<T>(pool: Pool, setRole: string | undefined, fn: (q: Pool) => Promise<T>): Promise<T> {
  const role = (setRole ?? "").trim();
  if (role && !/^[a-z_][a-z0-9_]*$/.test(role)) throw new ImportRoleError("MIGRATE_SET_ROLE must be a plain role name");
  const c: PoolClient = await pool.connect();
  let began = false;
  try {
    await c.query("BEGIN");
    began = true;
    if (role) {
      try {
        await c.query(`SET LOCAL ROLE ${role}`);
      } catch (e) {
        throw new ImportRoleError(`SET LOCAL ROLE ${role} failed (${(e as { code?: string })?.code ?? "error"}); nothing imported`);
      }
      const who = await c.query<{ u: string }>("SELECT current_user::text AS u");
      if (who.rows[0]?.u !== role) throw new ImportRoleError(`import is running as ${who.rows[0]?.u}, not ${role}; nothing imported`);
    }
    const out = await fn({ query: c.query.bind(c) } as unknown as Pool);
    await c.query("COMMIT");
    began = false;
    return out;
  } finally {
    if (began) await c.query("ROLLBACK").catch(() => undefined);
    c.release();
  }
}
