/**
 * T11 / R21-P3-1 monitor: health of MONITOR_HEALTH_URLS + stale spend rows.
 *  - an empty / missing MONITOR_HEALTH_URLS is a config error (never "healthy")
 *  - health results are keyed by URL (origin + path; no userinfo or query)
 *  - any alert (a health check failing OR stale rows) exits non-zero
 *  - on an alert, MONITOR_PAGER_WEBHOOK_URL (optional) gets an HTTP POST:
 *      MONITOR_PAGER_FORMAT=json  (default) {"text": "...", "alert": {...}} — Slack incoming webhooks read "text"
 *      MONITOR_PAGER_FORMAT=slack {"text": "..."}
 *      MONITOR_PAGER_FORMAT=ntfy  text/plain body + Title/Priority/Tags headers
 *    Unset: a "no pager configured" line is logged so the gap is visible.
 *  - R22-P3-3: if the monitor itself fails (e.g. the database is unreachable
 *    for the stale-row query), that is an alert too: it pages and exits 2.
 *  - R22-P3-4: health URLs appear in logs and in the pager body, so they must
 *    hold NO secrets (no tokens in the path or query, no user:pass@). URLs with
 *    userinfo are rejected, and two URLs that map to the same key (origin +
 *    path) are a config error rather than one silently overwriting the other.
 *  - R23-P3-4: rows reconcile flagged needsRelease (expired, not on chain,
 *    still holding payer capacity) alert once flagged longer than
 *    MONITOR_NEEDS_RELEASE_MAX_MIN minutes (default 60).
 *  - R25-P3-1: every run also checks that every mr_* trigger is enabled
 *    (tgenabled = 'O', the expected ones present), that the write-once
 *    network marker is set and matches NETWORK's profile (name + genesis),
 *    and that mr_admin is not a member of the owner outside a deploy window.
 *    Any of those failing is an alert (page + exit 2).
 * The pager URL is treated as a secret and never printed.
 */
import { ANCHOR_RETAIN_DAYS_MIN, type AnchorPin, type AnchorSkip } from "./anchor.js";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { sha256hex } from "./hash.js";
import { fileURLToPath } from "node:url";
import { urlHasPathToken } from "@mandaterail/core";
import { pauseReasons, type PauseFacts } from "./spend-ops.js";
export type MonitorEnv = Record<string, string | undefined>;
export type StaleCounts = { pending: number; ambiguous: number; oldestAgeMs: number | null; needsReleaseOverdue?: number; needsReleaseOldestAgeMs?: number | null };

/** R23-P3-4: MONITOR_NEEDS_RELEASE_MAX_MIN (default 60), a positive integer. */
export function needsReleaseMaxMin(env: MonitorEnv): number {
  const raw = (env.MONITOR_NEEDS_RELEASE_MAX_MIN ?? "").trim();
  if (!raw) return 60;
  if (!/^\d+$/.test(raw) || Number(raw) <= 0) throw new MonitorConfigError("MONITOR_NEEDS_RELEASE_MAX_MIN must be a positive integer (minutes)");
  return Number(raw);
}
export class MonitorConfigError extends Error {}

/** R25-P3-1 / R26 (shape of spend-ops integrityStatus). */
export interface MonitorIntegrity {
  triggers: Record<string, string>;
  marker: { network: string; genesisHash: string } | null;
  adminOwnerMember: boolean | null;
  ownerMembers?: string[];
  windowLockHeld?: boolean;
  windowLockHolders?: Array<{ pid: number; user: string | null; app: string | null; ageS: number | null; valid: boolean }>;
  pause?: PauseFacts | null;
  drift?: { providersHash: string; providersCount: number; functions: Record<string, string>; aclHash: string; constraintsHash?: string; ownersHash?: string; triggersHash?: string; rolesHash?: string; releaseCaps?: Record<string, string>; aclFp?: string | null };
}
/**
 * R26-P3-2: what the DB must look like. functions + aclHash come from
 * deploy/integrity-manifest.json (generated from a fresh migrate + role SQL and
 * checked by the tests); providersHash from the network profiles.
 */
export interface IntegrityExpected {
  providersHash: string;
  functions: Record<string, string>;
  aclHash: string;
  /** R27-P3-3 (optional for older callers; the CLI always passes them). */
  constraintsHash?: string;
  ownersHash?: string;
  triggersHash?: string;
  rolesHash?: string;
  /** R64-P2-1: pinned mr_release_caps ("network" -> "perRelease/perDay" micro-USDC) */
  releaseCaps?: Record<string, string>;
  /** R70-P3-2: pinned mr_v16_acl_fp() of a host-shaped migrate + role SQL */
  aclFp?: string;
}
/** R26-P3-2: md5 of the sorted "network|host|operator" lines, same as INTEGRITY_SQL.providers. */
export function expectedProvidersHash(lists: Array<{ network: string; allow: ReadonlyArray<{ host: string; operator: string }> }>): string {
  const lines = lists.flatMap((l) => l.allow.map((e) => `${l.network}|${e.host}|${e.operator}`)).sort();
  return createHash("md5").update(lines.join("\n")).digest("hex");
}
/**
 * R27-P3-1 / R29: sha256 (was md5 until 94f799e) of deploy/integrity-manifest.json, pinned in code. A manifest
 * whose bytes don't hash to this is refused (page + exit 2), so a tampered
 * file can't hide drift. Regenerate both together (MR_UPDATE_INTEGRITY_MANIFEST=1
 * in r26-hardening.test.ts rewrites the file; r27-integrity.test.ts fails until
 * this constant matches it).
 */
export const INTEGRITY_MANIFEST_SHA256 = "86fec581e14068ddc1274ac6fb4078f11da19e60831f2cc2865def5f6ce123b0";
/** R27-P3-1: a manifest problem is an alert (page + exit 2), never a config error. */
export class MonitorManifestError extends Error {
  constructor(public readonly code: "MANIFEST_MISSING" | "MANIFEST_MALFORMED" | "MANIFEST_HASH_MISMATCH" | "MANIFEST_OVERRIDE_REFUSED", message: string) {
    super(message);
    this.name = "MonitorManifestError";
  }
}
export interface IntegrityManifest {
  functions: Record<string, string>;
  aclHash: string;
  constraintsHash: string;
  ownersHash: string;
  triggersHash: string;
  rolesHash: string;
  /** R64-P2-1 */
  releaseCaps: Record<string, string>;
  /** R70-P3-2 */
  aclFp: string;
  schemaVersion: number;
  /** R66-P3-3: anchor chain pins per network (prefix, minimum sequence, retention floor, public key) */
  anchor?: Record<string, AnchorPin>;
  /** rev 24 (§24.8): may the verifier run a software key file (platform aliyun-softkey) on this network? */
  verifierSoftkey?: Record<string, boolean>;
}
/**
 * rev 24 (§24.8): the softkey verifier's per-network gate, pinned in deploy/integrity-manifest.json (and so in
 * INTEGRITY_MANIFEST_SHA256). MainNet is false: turning it on is a manifest change, a new sha256 pin in code and an
 * internal reviewer run, never a config edit on the host.
 */
export const VERIFIER_SOFTKEY_PINS: Readonly<Record<string, boolean>> = Object.freeze({ mainnet: false, testnet: true });
export const DEFAULT_MANIFEST_PATH = fileURLToPath(new URL("../../../deploy/integrity-manifest.json", import.meta.url));
/**
 * R26-P3-2 / R27-P3-1: deploy/integrity-manifest.json next to this release.
 * MONITOR_INTEGRITY_MANIFEST may point elsewhere only off mainnet and outside
 * NODE_ENV=production; wherever it is read from, its md5 must equal
 * INTEGRITY_MANIFEST_SHA256 (opts.pinnedSha256 exists for tests of this function).
 */
export function loadIntegrityManifest(env: MonitorEnv, opts: { pinnedSha256?: string } = {}): IntegrityManifest {
  const override = env.MONITOR_INTEGRITY_MANIFEST?.trim();
  const prod = (env.NETWORK ?? "").trim().toLowerCase() === "mainnet" || (env.NODE_ENV ?? "").trim().toLowerCase() === "production";
  if (override && prod) throw new MonitorManifestError("MANIFEST_OVERRIDE_REFUSED", "MONITOR_INTEGRITY_MANIFEST is refused on mainnet / NODE_ENV=production; the release's deploy/integrity-manifest.json is the only manifest");
  const file = override || DEFAULT_MANIFEST_PATH;
  let raw: Buffer;
  try {
    raw = readFileSync(file);
  } catch {
    throw new MonitorManifestError("MANIFEST_MISSING", "integrity manifest (deploy/integrity-manifest.json) is missing or unreadable");
  }
  const got = sha256hex(raw);
  const want = opts.pinnedSha256 ?? INTEGRITY_MANIFEST_SHA256;
  if (got !== want) throw new MonitorManifestError("MANIFEST_HASH_MISMATCH", `integrity manifest sha256 ${got} does not match the pinned ${want} (tampered or out of date)`);
  let j: Record<string, unknown>;
  try {
    j = JSON.parse(raw.toString("utf8"));
  } catch {
    throw new MonitorManifestError("MANIFEST_MALFORMED", "integrity manifest is not JSON");
  }
  const str = (k: string) => typeof j[k] === "string";
  if (!j || typeof j.functions !== "object" || !["aclHash", "aclFp", "constraintsHash", "ownersHash", "triggersHash", "rolesHash"].every(str)
      || !j.releaseCaps || typeof j.releaseCaps !== "object" || !Object.values(j.releaseCaps as object).every((v) => typeof v === "string")) {
    throw new MonitorManifestError("MANIFEST_MALFORMED", "integrity manifest is malformed");
  }
  return {
    functions: j.functions as Record<string, string>, aclHash: j.aclHash as string, aclFp: j.aclFp as string, constraintsHash: j.constraintsHash as string,
    ownersHash: j.ownersHash as string, triggersHash: j.triggersHash as string, rolesHash: j.rolesHash as string, schemaVersion: Number(j.schemaVersion),
    releaseCaps: j.releaseCaps as Record<string, string>,
    ...(j.anchor !== undefined ? { anchor: parseAnchorPins(j.anchor) } : {}),
    ...(j.verifierSoftkey !== undefined ? { verifierSoftkey: parseSoftkeyPins(j.verifierSoftkey) } : {}),
  };
}
/** R25-P3-1 / R26-P3-1 / R26-P3-2: alert reasons for the integrity facts (empty = fine). */
export function integrityReasons(i: MonitorIntegrity, want: { network: string; genesisHash: string }, expectedTriggers: ReadonlyArray<string>, expected?: IntegrityExpected): string[] {
  const out: string[] = [];
  for (const k of expectedTriggers) if (!(k in i.triggers)) out.push(`integrity: trigger ${k} is missing`);
  for (const [k, e] of Object.entries(i.triggers)) if (e !== "O") out.push(`integrity: trigger ${k} is not enabled (tgenabled ${e})`);
  if (!i.marker) out.push("integrity: network marker (mr_network) is not set");
  else if (i.marker.network !== want.network || i.marker.genesisHash !== want.genesisHash) {
    out.push(`integrity: network marker is ${i.marker.network}/${i.marker.genesisHash}, expected ${want.network}/${want.genesisHash}`);
  }
  if (i.adminOwnerMember === true) out.push("integrity: mr_admin is a member of the table owner outside a deploy window (revoke: deploy/sql/r25-admin-window.sql -v window=close)");
  // R26-P3-2: ANY member of the owner alerts (not only mr_admin).
  const others = (i.ownerMembers ?? []).filter((m) => !(m === "mr_admin" && i.adminOwnerMember === true));
  if (others.length) out.push(`integrity: ${others.join(", ")} ${others.length === 1 ? "is a member" : "are members"} of the table owner (revoke: re-run the role SQL)`);
  // R26-P3-1: a membership with no window lock holder = a window left open by a crash / SIGKILL.
  if ((i.ownerMembers ?? []).length > 0 && i.windowLockHeld === false) out.push("integrity: deploy window left open (owner membership exists but no mr-admin-window lock holder; crashed?)");
  // R27-P3-2: lock (26026,1) may only be held by the window script (postgres, application_name mr-admin-window), at most 30 min.
  for (const h of i.windowLockHolders ?? []) {
    if (!h.valid) out.push(`integrity: deploy-window lock (26026,1) held by an unexpected session (pid ${h.pid}, user ${h.user ?? "?"}, application_name ${h.app ?? "?"}); only postgres/mr-admin-window may hold it`);
    else if (h.ageS === null) out.push(`integrity: deploy-window lock holder pid ${h.pid}: session age unreadable (re-run the role SQL: mr_window_lock_holders())`);
    else if (h.ageS > WINDOW_MAX_AGE_S) out.push(`integrity: deploy window open too long (${Math.floor(h.ageS / 60)} min > ${WINDOW_MAX_AGE_S / 60} min, pid ${h.pid})`);
  }
  out.push(...pauseReasons(i.pause));
  if (expected) {
    if (!i.drift) out.push("integrity: drift facts missing");
    else {
      if (i.drift.providersHash !== expected.providersHash) out.push(`integrity: provider allowlist drift (mr_network_provider hash ${i.drift.providersHash}, ${i.drift.providersCount} rows; expected the network profiles' list)`);
      for (const [sig, h] of Object.entries(expected.functions)) {
        if (!(sig in i.drift.functions)) out.push(`integrity: function ${sig} is missing`);
        else if (i.drift.functions[sig] !== h) out.push(`integrity: function ${sig} definition drift (prosrc md5 ${i.drift.functions[sig]}, expected ${h})`);
      }
      for (const sig of Object.keys(i.drift.functions)) if (!(sig in expected.functions)) out.push(`integrity: unexpected function ${sig}`);
      for (const [k, label] of [["constraintsHash", "constraint"], ["ownersHash", "owner"], ["triggersHash", "trigger definition"], ["rolesHash", "role flag / membership"]] as const) {
        const want = expected[k];
        if (want !== undefined && i.drift[k] !== want) out.push(`integrity: ${label} drift (hash ${i.drift[k] ?? "missing"}, expected ${want})`);
      }
      if (expected.releaseCaps) {
        const got = i.drift.releaseCaps ?? {};
        for (const n of new Set([...Object.keys(expected.releaseCaps), ...Object.keys(got)])) {
          if (got[n] !== expected.releaseCaps[n]) out.push(`integrity: release caps drift for ${n} (mr_release_caps ${got[n] ?? "missing"}, pinned ${expected.releaseCaps[n] ?? "none"})`);
        }
      }
      // R70-P3-2: the protected-ACL fingerprint and the DB pin must both equal the manifest value (a replica-mode
      // superuser repin makes pin == fp again, which clears the pin page; it can't change the manifest)
      if (expected.aclFp !== undefined) {
        if (i.drift.aclFp !== expected.aclFp) out.push(`integrity: protected ACL fingerprint ${String(i.drift.aclFp ?? "missing").slice(0, 12)} differs from the manifest pin ${expected.aclFp.slice(0, 12)}`);
        const pin = i.pause?.aclPin?.pin;
        if (pin != null && pin !== expected.aclFp) out.push(`integrity: mr_v16_acl_pin ${pin.slice(0, 12)} differs from the manifest pin ${expected.aclFp.slice(0, 12)} (repinned outside a release)`);
      }
      if (i.drift.aclHash !== expected.aclHash) out.push(`integrity: ACL drift (hash ${i.drift.aclHash}, expected ${expected.aclHash}; compare with the role SQL evidence)`);
    }
  }
  return out;
}

/** R27-P3-2: longest a deploy window may hold its lock. */
export const WINDOW_MAX_AGE_S = 30 * 60;
export const MONITOR_EXIT = { ok: 0, config: 1, alert: 2 } as const;

export function monitorUrlKey(u: string): string {
  try {
    const x = new URL(u);
    return `${x.origin}${x.pathname}`;
  } catch {
    return "invalid-url";
  }
}

export function parseHealthUrls(env: MonitorEnv): string[] {
  const urls = (env.MONITOR_HEALTH_URLS ?? "").split(",").map((u) => u.trim()).filter(Boolean);
  if (urls.length === 0) throw new MonitorConfigError("MONITOR_HEALTH_URLS is empty; set at least one health URL (an empty list is a config error, not healthy)");
  for (const u of urls) {
    let p: URL;
    try {
      p = new URL(u);
    } catch {
      throw new MonitorConfigError("MONITOR_HEALTH_URLS contains an invalid URL");
    }
    if (p.protocol !== "https:" && p.protocol !== "http:") throw new MonitorConfigError("MONITOR_HEALTH_URLS must be http(s)");
    if (p.username || p.password) throw new MonitorConfigError("MONITOR_HEALTH_URLS must not contain credentials (health URLs are logged and paged; they must hold no secrets)");
    // R54-P3-2: nor a credential in the path (e.g. a GetBlock /<token>/ URL) (the query is already stripped from keys/logs)
    if (urlHasPathToken(u)) throw new MonitorConfigError("MONITOR_HEALTH_URLS must not contain a token in the URL path (health URLs are logged and paged; they must hold no secrets)");
  }
  // R22-P3-4: results are keyed by origin + path; a collision would hide a check.
  const seen = new Set<string>();
  for (const u of urls) {
    const k = monitorUrlKey(u);
    if (seen.has(k)) throw new MonitorConfigError(`MONITOR_HEALTH_URLS has two entries with the same key ${k} (they differ only in query/fragment); make each URL unique by path`);
    seen.add(k);
  }
  return urls;
}

export type PagerFormat = "json" | "slack" | "ntfy";
export function pagerConfig(env: MonitorEnv): { url: string; format: PagerFormat } | null {
  const url = (env.MONITOR_PAGER_WEBHOOK_URL ?? "").trim();
  if (!url) return null;
  let p: URL;
  try {
    p = new URL(url);
  } catch {
    throw new MonitorConfigError("MONITOR_PAGER_WEBHOOK_URL is not a valid URL");
  }
  const loopback = ["127.0.0.1", "localhost", "[::1]"].includes(p.hostname);
  if (p.protocol !== "https:" && !(p.protocol === "http:" && loopback)) throw new MonitorConfigError("MONITOR_PAGER_WEBHOOK_URL must be https (http only for loopback)");
  const f = (env.MONITOR_PAGER_FORMAT ?? "json").trim().toLowerCase();
  if (f !== "json" && f !== "slack" && f !== "ntfy") throw new MonitorConfigError("MONITOR_PAGER_FORMAT must be json, slack or ntfy");
  return { url, format: f };
}

export interface MonitorResult {
  ok: boolean;
  health: Record<string, number | "error">;
  stale: StaleCounts;
  reasons: string[];
  pager: "not-configured" | "sent" | "failed" | "not-needed";
  exitCode: number;
}

export async function runMonitor(a: {
  env: MonitorEnv;
  store: string;
  olderThanMin: number;
  stale: () => Promise<StaleCounts>;
  /** R25-P3-1: trigger / marker / admin-membership facts; required by the CLI. */
  integrity?: { read: () => Promise<MonitorIntegrity>; want: { network: string; genesisHash: string }; expectedTriggers: ReadonlyArray<string>; expected?: IntegrityExpected };
  /** R28-P3-1: release pin check (release-pin.ts releasePinReasons); required by the CLI. */
  release?: () => { reasons: string[]; commit: string | null };
  /** R65-P3-4: anchor the append-only tables to the off-host chain and page on regression (anchor.ts anchorTick). */
  anchor?: () => Promise<{ reasons: string[]; seq: number; anchored: boolean }>;
  fetchImpl?: typeof fetch;
  log?: (line: string) => void;
  err?: (line: string) => void;
  now?: () => Date;
}): Promise<MonitorResult> {
  const f = a.fetchImpl ?? fetch;
  const log = a.log ?? ((l) => console.log(l));
  const err = a.err ?? ((l) => console.error(l));
  const urls = parseHealthUrls(a.env); // throws MonitorConfigError
  const pager = pagerConfig(a.env); // throws MonitorConfigError
  needsReleaseMaxMin(a.env); // R23-P3-4: validate before any check runs
  const health: Record<string, number | "error"> = {};
  for (const u of urls) {
    const k = monitorUrlKey(u);
    try {
      health[k] = (await f(u, { signal: AbortSignal.timeout(10_000) })).status;
    } catch {
      health[k] = "error";
    }
  }
  const reasons: string[] = [];
  let stale: StaleCounts = { pending: 0, ambiguous: 0, oldestAgeMs: null };
  try {
    stale = await a.stale();
  } catch (e) {
    // R22-P3-3: the monitor failing is itself an alert (page + exit 2), never a silent exit 1.
    reasons.push(`monitor self-failure: stale-row query failed (${errClass(e)})`);
  }
  let integrity: MonitorIntegrity | undefined;
  if (a.integrity) {
    try {
      integrity = await a.integrity.read();
      reasons.push(...integrityReasons(integrity, a.integrity.want, a.integrity.expectedTriggers, a.integrity.expected));
    } catch (e) {
      reasons.push(`monitor self-failure: integrity query failed (${errClass(e)})`);
    }
  }
  let release: { commit: string | null; pinOk: boolean } | undefined;
  if (a.release) {
    try {
      const r = a.release();
      reasons.push(...r.reasons);
      release = { commit: r.commit, pinOk: r.reasons.length === 0 };
    } catch (e) {
      reasons.push(`monitor self-failure: release pin check failed (${errClass(e)})`);
      release = { commit: null, pinOk: false };
    }
  }
  if (a.anchor) {
    try { reasons.push(...(await a.anchor()).reasons); } catch (e) { reasons.push(`monitor self-failure: anchor failed (${errClass(e)})`); }
  }
  for (const [k, s] of Object.entries(health)) if (s !== 200) reasons.push(`health ${k} -> ${s}`);
  if (stale.pending + stale.ambiguous > 0) reasons.push(`stale spend rows: ${stale.pending} pending, ${stale.ambiguous} ambiguous older than ${a.olderThanMin} min`);
  if ((stale.needsReleaseOverdue ?? 0) > 0) {
    reasons.push(`needsRelease overdue: ${stale.needsReleaseOverdue} reservation(s) flagged for release more than ${needsReleaseMaxMin(a.env)} min ago still hold payer capacity; release with proof (two-person procedure)`);
  }
  const ok = reasons.length === 0;
  const at = (a.now ?? (() => new Date()))().toISOString();
  const body = { cmd: "monitor", store: a.store, ok, health, olderThanMin: a.olderThanMin, stale, ...(integrity ? { integrity: { triggersChecked: Object.keys(integrity.triggers).length, marker: integrity.marker?.network ?? null, adminOwnerMember: integrity.adminOwnerMember, ownerMembers: integrity.ownerMembers ?? null, windowLockHeld: integrity.windowLockHeld ?? null, windowLockHolders: (integrity.windowLockHolders ?? []).length, ...(integrity.drift ? { functionsChecked: Object.keys(integrity.drift.functions).length, providers: integrity.drift.providersCount, aclHash: integrity.drift.aclHash, driftChecked: a.integrity?.expected !== undefined } : {}) } } : {}), ...(release ? { release } : {}), reasons, at };
  let pagerState: MonitorResult["pager"] = "not-needed";
  if (ok) {
    log(JSON.stringify({ ...body, pager: pager ? "configured" : "not-configured" }));
  } else {
    err(`ALERT ${JSON.stringify(body)}`);
    if (!pager) {
      pagerState = "not-configured";
      err("monitor: no pager configured (MONITOR_PAGER_WEBHOOK_URL unset); alert only in the journal");
    } else {
      pagerState = (await sendPage(pager, `MandateRail ALERT (${a.store}): ${reasons.join("; ")}`, body, f)) ? "sent" : "failed";
      if (pagerState === "failed") err("monitor: pager POST failed");
      else err("monitor: pager notified");
    }
  }
  if (ok && !pager) err("monitor: no pager configured (MONITOR_PAGER_WEBHOOK_URL unset)");
  return { ok, health, stale, reasons, pager: pagerState, exitCode: ok ? MONITOR_EXIT.ok : MONITOR_EXIT.alert };
}

/** A short, secret-free description of an error (code/class only; messages can carry URLs). */
function errClass(e: unknown): string {
  const x = e as { code?: unknown; name?: unknown } | null;
  if (x && typeof x.code === "string" && /^[A-Z0-9_]{1,32}$/i.test(x.code)) return x.code;
  if (x && typeof x.name === "string" && /^[A-Za-z]{1,40}$/.test(x.name)) return x.name;
  return "error";
}

/**
 * R22-P3-3: last-resort alert when the monitor run failed before it could
 * finish (not a config error). Pages if a valid pager is configured; exit 2.
 */
export async function monitorSelfFailure(a: { env: MonitorEnv; store: string; error: unknown; fetchImpl?: typeof fetch; err?: (line: string) => void; now?: () => Date }): Promise<MonitorResult> {
  const err = a.err ?? ((l) => console.error(l));
  // R27-P3-1: a manifest problem names itself (its messages hold no secrets).
  const reason = a.error instanceof MonitorManifestError ? `integrity manifest: ${a.error.code}: ${a.error.message}` : `monitor self-failure: ${errClass(a.error)}`;
  const body = { cmd: "monitor", store: a.store, ok: false, reasons: [reason], at: (a.now ?? (() => new Date()))().toISOString() };
  err(`ALERT ${JSON.stringify(body)}`);
  let pager: { url: string; format: PagerFormat } | null = null;
  try {
    pager = pagerConfig(a.env);
  } catch {
    err("monitor: pager config invalid; cannot page");
  }
  let state: MonitorResult["pager"] = "not-configured";
  if (pager) {
    state = (await sendPage(pager, `MandateRail ALERT (${a.store}): ${reason}`, body, a.fetchImpl ?? fetch)) ? "sent" : "failed";
    err(state === "sent" ? "monitor: pager notified" : "monitor: pager POST failed");
  } else err("monitor: no pager configured (MONITOR_PAGER_WEBHOOK_URL unset); alert only in the journal");
  return { ok: false, health: {}, stale: { pending: 0, ambiguous: 0, oldestAgeMs: null }, reasons: [reason], pager: state, exitCode: MONITOR_EXIT.alert };
}

async function sendPage(p: { url: string; format: PagerFormat }, text: string, alert: object, f: typeof fetch): Promise<boolean> {
  try {
    const init: RequestInit =
      p.format === "ntfy"
        ? { method: "POST", headers: { "Content-Type": "text/plain; charset=utf-8", Title: "MandateRail ALERT", Priority: "high", Tags: "rotating_light" }, body: text }
        : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(p.format === "slack" ? { text } : { text, alert }) };
    const res = await f(p.url, { ...init, signal: AbortSignal.timeout(10_000) });
    return res.ok;
  } catch {
    return false;
  }
}

/** R66-P3-3: the manifest's anchor pins (retention floor >= 365 d, raw 32-byte pubkey or null). */
function parseSoftkeyPins(v: unknown): Record<string, boolean> {
  if (!v || typeof v !== "object" || Array.isArray(v) || !Object.values(v as object).every((b) => typeof b === "boolean")) {
    throw new MonitorManifestError("MANIFEST_MALFORMED", "integrity manifest verifierSoftkey must map network -> boolean");
  }
  return { ...(v as Record<string, boolean>) };
}
function parseAnchorPins(v: unknown): Record<string, AnchorPin> {
  const out: Record<string, AnchorPin> = {};
  if (!v || typeof v !== "object") throw new MonitorManifestError("MANIFEST_MALFORMED", "integrity manifest anchor pins are malformed");
  for (const [n, p] of Object.entries(v as Record<string, Record<string, unknown>>)) {
    const ok = p && typeof p.prefix === "string" && /^[a-z0-9][a-z0-9/_-]*\/$/.test(p.prefix) && Number.isSafeInteger(p.minSeq) && (p.minSeq as number) >= 0
      && Number.isSafeInteger(p.retainDaysMin) && (p.retainDaysMin as number) >= ANCHOR_RETAIN_DAYS_MIN
      && (p.pubkey === null || (typeof p.pubkey === "string" && Buffer.from(p.pubkey, "base64").length === 32));
    // R69-P3-1: skip entries are exact (key under the prefix, lowercase sha256 of the stored bytes)
    const skip = p?.skip ?? [];
    const skipOk = Array.isArray(skip) && skip.every((x) => x && typeof x === "object" && typeof (x as AnchorSkip).key === "string" && typeof p.prefix === "string"
      && (x as AnchorSkip).key.startsWith((p.prefix as string).replace(/\/$/, "") + "/") && /^[0-9a-f]{64}$/.test(String((x as AnchorSkip).sha256)) && Object.keys(x).length === 2);
    // R70-P3-1: requireSigned is a boolean; MainNet must require signed anchors
    const rs = p?.requireSigned;
    const rsOk = typeof rs === "boolean" && (n !== "mainnet" || rs === true);
    if (!ok || !skipOk || !rsOk) throw new MonitorManifestError("MANIFEST_MALFORMED", `integrity manifest anchor pin for ${n} is malformed (retention floor must be >= ${ANCHOR_RETAIN_DAYS_MIN} d; skip = [{key, sha256}]; requireSigned boolean, true on mainnet)`);
    out[n] = { prefix: p.prefix as string, minSeq: p.minSeq as number, retainDaysMin: p.retainDaysMin as number, pubkey: p.pubkey as string | null, skip: (skip as AnchorSkip[]).map((x) => ({ key: x.key, sha256: x.sha256 })), requireSigned: rs as boolean };
  }
  return out;
}
