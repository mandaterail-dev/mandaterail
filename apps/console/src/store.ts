import { randomBytes } from "node:crypto";
import { mkdir, open, readFile, rename, rm } from "node:fs/promises";
import path from "node:path";
import { IntentMandateSchema, type IntentMandate } from "@mandaterail/schema";
import {
  MandateExistsError,
  StoreFullError,
  type MandateServerState,
  type MandateStore,
  type StoredMandate,
} from "@mandaterail/core";

export { StoreFullError, MandateExistsError, type StoredMandate };

// Resolved per call so tests / processes can point CONSOLE_DATA_DIR elsewhere.
const dataDir = () => process.env.CONSOLE_DATA_DIR ?? path.join(process.cwd(), "data");
const storeFile = () => path.join(dataDir(), "mandates.json");


/** Historical console stub prefix — never treat as a real AC2 signature. */
export const STUB_SIGNATURE_PREFIX = "sig_console_stub";

export type MandateAuthClassification = {
  status:
    | "unsigned-draft"
    | "stub-signature"
    | "signature-present-unverified"
    | "signature-verified"
    | "signature-invalid"
    | "revoked"
    | "expired";
  authorizedForExecute: boolean;
  message: string;
};

/**
 * Server-side state kept next to (never inside) the mandate, so signed
 * bytes are untouched. `signatureVerified` is set only by the console after
 * verifying the AC2 signature at create.
 */
export type ServerState = MandateServerState;

/** R31-P3-5: YYYY-MM-DDTHH:MM:SS[.fff]Z only, round-trip checked (no 2026-02-30). */
export const STRICT_ISO_UTC = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/;
export function parseStrictIsoUtc(v: unknown): number | null {
  if (typeof v !== "string") return null;
  const m = STRICT_ISO_UTC.exec(v);
  if (!m) return null;
  const ms = Date.UTC(+m[1]!, +m[2]! - 1, +m[3]!, +m[4]!, +m[5]!, +m[6]!, m[7] ? +m[7].padEnd(3, "0") : 0);
  const d = new Date(ms);
  if (d.getUTCFullYear() !== +m[1]! || d.getUTCMonth() !== +m[2]! - 1 || d.getUTCDate() !== +m[3]! || d.getUTCHours() !== +m[4]! || d.getUTCMinutes() !== +m[5]! || d.getUTCSeconds() !== +m[6]!) return null;
  return ms;
}

export function classifyMandateAuth(
  m: IntentMandate,
  server: ServerState = { signatureVerified: false },
  nowMs: number = Date.now(),
): MandateAuthClassification {
  if (m.revoked) {
    return {
      status: "revoked",
      authorizedForExecute: false,
      message: "mandate revoked",
    };
  }
  // R30-P3-4: expiry is decided by the console's (server) clock, never the
  // browser's: an expired or unparseable expiresAt is never authorized.
  // R31-P3-5: only strict ISO 8601 UTC with a trailing Z is accepted; anything else
  // (offsets, no zone = local time, date-only, RFC 2822) is treated as expired.
  const exp = parseStrictIsoUtc(m.expiresAt);
  if (exp === null || exp <= nowMs) {
    return {
      status: "expired",
      authorizedForExecute: false,
      message: "mandate expired (console clock)",
    };
  }
  const sig = m.signature;
  if (!sig) {
    return {
      status: "unsigned-draft",
      authorizedForExecute: false,
      message: "unsigned-draft — not authorized for execute; AC2 approve required",
    };
  }
  if (sig.startsWith(STUB_SIGNATURE_PREFIX)) {
    return {
      status: "stub-signature",
      authorizedForExecute: false,
      message: "console stub signature is not a real AC2 signature",
    };
  }
  // Client-controlled metadata (e.g. draftStatus) is never trusted here.
  if (server.signatureVerified) {
    return {
      status: "signature-verified",
      authorizedForExecute: true,
      message: "signature verified by the console at create",
    };
  }
  return {
    status: "signature-present-unverified",
    authorizedForExecute: false,
    message:
      "signature present but not verified by the console — run authorize-check",
  };
}

/**
 * In-process write mutex: every read-modify-write runs serially, so a
 * concurrent create cannot resurrect a revoked mandate and the cap is
 * checked against the committed state. Single-process only.
 */
let writeChain: Promise<unknown> = Promise.resolve();
function withWriteLock<T>(fn: () => Promise<T>): Promise<T> {
  const run = writeChain.then(fn, fn);
  writeChain = run.catch(() => undefined);
  return run;
}

async function readAll(): Promise<StoredMandate[]> {
  await mkdir(dataDir(), { recursive: true });
  let raw: string;
  try {
    raw = await readFile(storeFile(), "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw e;
  }
  const parsed = JSON.parse(raw) as unknown;
  if (!Array.isArray(parsed)) return [];
  const out: StoredMandate[] = [];
  for (const item of parsed) {
    // v2 record { mandate, server }; legacy bare mandates are never verified.
    const isRecord =
      item && typeof item === "object" && "mandate" in item && "server" in item;
    const r = IntentMandateSchema.safeParse(isRecord ? item.mandate : item);
    if (!r.success) continue;
    const verified =
      isRecord && (item.server as ServerState)?.signatureVerified === true;
    out.push({
      mandate: r.data,
      server: verified
        ? {
            signatureVerified: true,
            verifiedAt: (item.server as ServerState).verifiedAt,
          }
        : { signatureVerified: false },
    });
  }
  return out;
}

/** Atomic replace: temp file in the same dir, fsync, rename, fsync dir. */
async function writeAll(items: StoredMandate[]): Promise<void> {
  const dir = dataDir();
  await mkdir(dir, { recursive: true });
  const tmp = path.join(
    dir,
    `.mandates.json.${process.pid}.${randomBytes(6).toString("hex")}.tmp`,
  );
  const fh = await open(tmp, "w", 0o600);
  try {
    await fh.writeFile(JSON.stringify(items, null, 2) + "\n", "utf8");
    await fh.sync();
  } finally {
    await fh.close();
  }
  try {
    await rename(tmp, storeFile());
  } catch (e) {
    await rm(tmp, { force: true });
    throw e;
  }
  try {
    const d = await open(dir, "r");
    try {
      await d.sync();
    } finally {
      await d.close();
    }
  } catch {
    // directory fsync is best-effort (unsupported on some platforms)
  }
}

export async function listMandates(): Promise<StoredMandate[]> {
  return readAll();
}

export async function getMandate(id: string): Promise<StoredMandate | null> {
  const all = await readAll();
  return all.find((r) => r.mandate.id === id) ?? null;
}

export async function createMandate(
  input: Omit<IntentMandate, "createdAt" | "revoked"> & {
    createdAt?: string;
    revoked?: boolean;
  },
  opts: { maxMandates?: number; signatureVerified?: boolean } = {},
): Promise<StoredMandate> {
  const now = new Date().toISOString();
  const mandate = IntentMandateSchema.parse({
    ...input,
    revoked: input.revoked ?? false,
    createdAt: input.createdAt ?? now,
  });
  const server: ServerState = opts.signatureVerified
    ? { signatureVerified: true, verifiedAt: now }
    : { signatureVerified: false };
  return withWriteLock(async () => {
    const all = await readAll();
    if (all.some((r) => r.mandate.id === mandate.id)) {
      throw new MandateExistsError(mandate.id);
    }
    if (opts.maxMandates !== undefined && all.length >= opts.maxMandates) {
      throw new StoreFullError(opts.maxMandates);
    }
    const rec = { mandate, server };
    all.push(rec);
    await writeAll(all);
    return rec;
  });
}

export async function revokeMandate(id: string): Promise<StoredMandate | null> {
  return withWriteLock(async () => {
    const all = await readAll();
    const idx = all.findIndex((r) => r.mandate.id === id);
    if (idx < 0) return null;
    all[idx] = { ...all[idx], mandate: { ...all[idx].mandate, revoked: true } };
    await writeAll(all);
    return all[idx];
  });
}

/** JSON-file mandate store (single process; the Phase 1 behaviour). */
export class FileMandateStore implements MandateStore {
  list(): Promise<StoredMandate[]> {
    return listMandates();
  }
  get(id: string): Promise<StoredMandate | null> {
    return getMandate(id);
  }
  create(
    mandate: IntentMandate,
    opts: { maxMandates?: number; signatureVerified?: boolean } = {},
  ): Promise<StoredMandate> {
    return createMandate(mandate, opts);
  }
  revoke(id: string): Promise<StoredMandate | null> {
    return revokeMandate(id);
  }
}
