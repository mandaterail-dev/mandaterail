/**
 * R75-P2-1: the MainNet key order (docs/ops/kms-key-order.md, deploy/mainnet/kms-keys.json) as behaviour, not data.
 *  - every key marked backup (inventory `role: "backup"`, or a backticked resource on a "backup" line of the doc, or
 *    the built-in mirror below) is refused by the key loaders (Cloud KMS, AWS KMS, softkey), on every network;
 *  - on MainNet the inventory must be readable and well formed (fail closed);
 *  - the active co-signer is `active.cosigner` (aliyun-softkey); the active signer key is `active.signer`, and a
 *    MainNet signer config whose key is not that entry (or with no active signer defined) is refused.
 * Overrides: MR_KEY_INVENTORY / MR_KEY_ORDER_DOC (paths) on TestNet only; R77-P3-1: refused on MainNet and with
 * NODE_ENV=production (the release's files are the only key order there). Tests inject paths through `KeyOrderFiles`
 * (code only); R79-P3-3: honoured only under vitest (VITEST set) and never with NODE_ENV=production; otherwise refused. No fallback from an active key to a backup ever happens.
 */
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export class KeyOrderError extends Error { override name = "KeyOrderError"; }

/** Built-in mirror of the backup keys (currently only AWS; test r77 asserts it matches the inventory's role-backup entries and the doc's backup lines), so a host without the repo files still refuses them. The active signer (gcp) is deliberately not in it. */
export const BUILTIN_BACKUP_KEYS: readonly { name: string; resources: readonly string[]; pubkeyB64: string }[] = [
  // the owner, 2026-10-22 19:31 ET: the GCP Cloud KMS key is the MainNet main signer (active.signer = "gcp"), no longer a backup
  { name: "aws", pubkeyB64: "+imTutKhwHJIXfKc7Y34trkVeuiuHz5tiDtKW5nAQow=", resources: ["arn:aws:kms:us-east-1:860273388508:key/7b2d2a83-0633-439e-8214-713c449fdd0c", "alias/mandaterail-verifier"] },
];
export const ACTIVE_COSIGNER = "aliyun-softkey";

export interface KeyInventory { order: string[]; active: { cosigner: string; signer: string | null }; entries: Record<string, { role: "active" | "backup"; resources: string[]; pubkeyB64?: string }> }

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../..");
export const DEFAULT_INVENTORY = path.join(ROOT, "deploy/mainnet/kms-keys.json");
export const DEFAULT_ORDER_DOC = path.join(ROOT, "docs/ops/kms-key-order.md");

export function parseKeyInventory(raw: string): KeyInventory {
  let j: Record<string, unknown>;
  try { j = JSON.parse(raw) as Record<string, unknown>; } catch { throw new KeyOrderError("key inventory is not JSON"); }
  const order = j.order;
  if (!Array.isArray(order) || order[0] !== ACTIVE_COSIGNER) throw new KeyOrderError(`key inventory: order must start with ${ACTIVE_COSIGNER}`);
  const a = j.active as { cosigner?: unknown; signer?: unknown } | undefined;
  if (!a || a.cosigner !== ACTIVE_COSIGNER || !(a.signer === null || typeof a.signer === "string")) throw new KeyOrderError(`key inventory: active.cosigner must be ${ACTIVE_COSIGNER} and active.signer a key name or null`);
  const entries: KeyInventory["entries"] = {};
  for (const [k, v] of Object.entries(j)) {
    if (k === "order" || k === "active" || k.startsWith("_")) continue;
    const e = v as Record<string, unknown>;
    if (e?.role !== "active" && e?.role !== "backup") throw new KeyOrderError(`key inventory: entry ${k} has no role active|backup`);
    const resources = [e.keyVersionName, e.keyArn, e.alias].filter((x): x is string => typeof x === "string").map((r) => r.replace(/\/cryptoKeyVersions\/\d+$/, ""));
    entries[k] = { role: e.role, resources, pubkeyB64: typeof e.pubkeyB64 === "string" ? e.pubkeyB64 : undefined };
  }
  if (a.signer !== null && entries[a.signer]?.role !== "active") throw new KeyOrderError(`key inventory: active.signer ${a.signer} is not an entry with role active`);
  return { order: order as string[], active: { cosigner: a.cosigner as string, signer: a.signer as string | null }, entries };
}

/** Backticked key resources on list items (numbered or bulleted, R77-P3-5) of the doc that mark them backup. */
export function backupResourcesFromDoc(md: string): string[] {
  const out: string[] = [];
  for (const line of md.split("\n")) {
    if (!/\bbackup\b/i.test(line) || !/^\s*(\d+[.)]|[-*+])\s/.test(line)) continue;
    for (const m of line.matchAll(/`([^`]+)`/g)) if (/^(projects\/|arn:aws:kms:|alias\/)/.test(m[1]!)) out.push(m[1]!.replace(/\/cryptoKeyVersions\/\d+$/, ""));
  }
  return out;
}

/** Code-level key order file paths (tests only; see keyOrderFilesAllowed). */
export interface KeyOrderFiles { inventoryPath?: string; docPath?: string }

export const keyOrderFilesAllowed = (env: NodeJS.ProcessEnv): boolean => env.VITEST !== undefined && env.NODE_ENV !== "production";

export function loadKeyOrder(network: string, env: NodeJS.ProcessEnv = process.env, files: KeyOrderFiles = {}): { inventory: KeyInventory | null; backups: { resources: Set<string>; pubkeys: Set<string> } } {
  // R77-P3-1: like the integrity manifest override, the env overrides are refused on MainNet / production
  if ((env.MR_KEY_INVENTORY !== undefined || env.MR_KEY_ORDER_DOC !== undefined) && (network === "mainnet" || env.NODE_ENV === "production")) {
    throw new KeyOrderError("MR_KEY_INVENTORY / MR_KEY_ORDER_DOC are refused on mainnet / NODE_ENV=production; the release's deploy/mainnet/kms-keys.json and docs/ops/kms-key-order.md are the only key order");
  }
  // R79-P3-3: the code seam is refused outside the test runner, so no caller can redirect the key order on MainNet / production
  if ((files.inventoryPath !== undefined || files.docPath !== undefined) && !keyOrderFilesAllowed(env)) {
    throw new KeyOrderError("KeyOrderFiles are a test-only seam; refused outside vitest and with NODE_ENV=production");
  }
  const ip = files.inventoryPath ?? env.MR_KEY_INVENTORY ?? DEFAULT_INVENTORY, dp = files.docPath ?? env.MR_KEY_ORDER_DOC ?? DEFAULT_ORDER_DOC;
  let inventory: KeyInventory | null = null;
  if (existsSync(ip)) inventory = parseKeyInventory(readFileSync(ip, "utf8"));
  else if (network === "mainnet") throw new KeyOrderError(`MainNet: key inventory ${ip} is missing (fail closed)`);
  const resources = new Set<string>(), pubkeys = new Set<string>();
  for (const b of BUILTIN_BACKUP_KEYS) { b.resources.forEach((r) => resources.add(r)); pubkeys.add(b.pubkeyB64); }
  for (const e of Object.values(inventory?.entries ?? {})) if (e.role === "backup") { e.resources.forEach((r) => resources.add(r)); if (e.pubkeyB64) pubkeys.add(e.pubkeyB64); }
  if (existsSync(dp)) backupResourcesFromDoc(readFileSync(dp, "utf8")).forEach((r) => resources.add(r));
  // the active signer must not also be marked backup anywhere (inconsistent key order = fail closed)
  const act = inventory?.active.signer ? inventory.entries[inventory.active.signer] : undefined;
  if (act && (act.resources.some((r) => [...resources].some((b) => r === b || r.startsWith(`${b}/`))) || (act.pubkeyB64 && pubkeys.has(act.pubkeyB64)))) {
    throw new KeyOrderError(`key order: the active signer ${inventory!.active.signer} is also marked backup (inventory, doc or built-in mirror)`);
  }
  return { inventory, backups: { resources, pubkeys } };
}

/** Refuses a key that is marked backup anywhere (resource prefix match or pinned public key). */
export function assertNotBackupKey(k: { network: string; what: string; resource?: string; pubkey?: Uint8Array }, env: NodeJS.ProcessEnv = process.env, files: KeyOrderFiles = {}): void {
  const { backups } = loadKeyOrder(k.network, env, files);
  const r = k.resource?.replace(/\/cryptoKeyVersions\/\d+$/, "");
  if (r && [...backups.resources].some((b) => r === b || r.startsWith(`${b}/`))) throw new KeyOrderError(`${k.what}: ${r} is a backup key (docs/ops/kms-key-order.md); backups never sign`);
  if (k.pubkey && backups.pubkeys.has(Buffer.from(k.pubkey).toString("base64"))) throw new KeyOrderError(`${k.what}: the pinned public key belongs to a backup key; backups never sign`);
}

/** MainNet signer: the configured key must be the inventory's active signer; none defined = refuse. */
export function assertActiveSignerKey(k: { network: string; resource: string; pubkey: Uint8Array; what?: string }, env: NodeJS.ProcessEnv = process.env, files: KeyOrderFiles = {}): void {
  assertNotBackupKey({ ...k, what: k.what ?? "signer key" }, env, files);
  if (k.network !== "mainnet") return;
  const inv = loadKeyOrder(k.network, env, files).inventory!;
  const name = inv.active.signer;
  if (name === null) throw new KeyOrderError("MainNet signer: no active signer key is defined in the key inventory (active.signer = null); refusing rather than using a backup");
  const e = inv.entries[name]!;
  const r = k.resource.replace(/\/cryptoKeyVersions\/\d+$/, "");
  if (!e.resources.includes(r) || (e.pubkeyB64 && e.pubkeyB64 !== Buffer.from(k.pubkey).toString("base64"))) throw new KeyOrderError(`MainNet signer: the configured key is not the active signer key ${name}`);
}
