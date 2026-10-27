import { createHash } from "node:crypto";
/**
 * R18-P3-2 operator / cron operations on Postgres spend reservations.
 * Every status change is written to mr_spend_audit (actor, action, reason)
 * in the same transaction as the update.
 */
import type { Pool } from "pg";
import type { ChainCheck, SpendStatus, TwoObservationProof, TwoObservationProver } from "@mandaterail/core";
import { PgSpendStore } from "./pg.js";
import { verifyAttestation } from "./attest.js";
import { decodeResume, decodeResumeCosign } from "./resume.js";

export class SpendOpError extends Error {}

type FnResult = { ok: true; from: SpendStatus } | { ok: false; status: SpendStatus | null };
function fnResult(rows: Array<{ ok: boolean; from_status: SpendStatus | null }>): FnResult {
  const r = rows[0];
  if (r?.ok && r.from_status) return { ok: true, from: r.from_status };
  return { ok: false, status: r?.from_status ?? null };
}

/**
 * R22-P3-1: reconcile path. SECURITY DEFINER mr_spend_settle (granted to
 * mr_reconcile): pending/ambiguous -> settled, pending -> ambiguous, whitelisted
 * actions only. The DB sets the timestamp (clock_timestamp) and the actor
 * (session_user); `label` is stored as an untrusted note.
 */
async function settle(
  pool: Pool,
  a: { store: string; id: string; from: SpendStatus[]; to: "settled" | "ambiguous"; action: "chain-reconcile" | "chain-reconcile-expired"; label: string; reason: string; txId: string },
): Promise<FnResult> {
  // R23-P3-3: the DB requires a pinned, non-null txId that matches the row.
  const { rows } = await pool.query<{ ok: boolean; from_status: SpendStatus | null }>(
    "SELECT ok, from_status FROM mr_spend_settle($1, $2, $3::text[], $4, $5, $6, $7, $8)",
    [a.store, a.id, a.from, a.to, a.action, a.label, a.reason, a.txId],
  );
  return fnResult(rows);
}

/**
 * R22-P3-1 / R23-P2-1: release path. mr_spend_release is granted ONLY to
 * mr_release. The proof goes in as typed arguments; the DB checks it
 * (pinned tx_id + last_valid, margin >= 0, round > lastValid + margin,
 * indexer 404, genesis = the mr_network marker) and refuses a forced release
 * when the marker is mainnet.
 */
async function release(
  pool: Pool,
  a: { store: string; id: string; action: "manual-release" | "manual-release-forced"; label: string; reason: string; txId: string | null; proof?: Extract<TwoObservationProof, { ok: true }> },
): Promise<FnResult> {
  const p = a.proof;
  const [o1, o2] = p ? p.observations : [undefined, undefined];
  const { rows } = await pool
    .query<{ ok: boolean; from_status: SpendStatus | null }>(
      "SELECT ok, from_status FROM mr_spend_release($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)",
      [a.store, a.id, a.action, a.label, a.reason, a.txId, p?.lastValid ?? null, p?.marginRounds ?? null,
        o1?.provider ?? null, o1?.kind ?? null, o1?.genesisHash ?? null, o1?.round ?? null, o1?.status ?? null,
        o2?.provider ?? null, o2?.kind ?? null, o2?.genesisHash ?? null, o2?.round ?? null, o2?.status ?? null],
    )
    .catch((e: { code?: string; message?: string }) => {
      if (e?.code === "42501" && /permission denied/i.test(e.message ?? "")) throw new SpendOpError("this DB role cannot release reservations; releases run as mr_release with the credential supplied at runtime (docs/ops/release-custody.md)");
      if (e?.code === "42501" || e?.code === "23514") throw new SpendOpError(`database refused the release: ${e.message}`);
      throw e;
    });
  return fnResult(rows);
}

/**
 * Manual release by an operator (R19-P2-1). Freeing a cap while the txn could
 * still confirm would let a payer overspend, so a release needs either:
 *  - a chain proof (`prove`, twoProviderNoConfirmProof, R24-P2-1: two
 *    independent genesis-checked providers): the row has a txId
 *    and lastValid, the indexer returns 404 for the txId, and the current
 *    round is past lastValid + margin; or
 *  - `force: true` (CLI --force; refused on MainNet, loud stderr warning on
 *    TestNet, R20-P3-1), for rows the chain can't speak for (e.g.
 *    no txId). The reason is then the force justification.
 * The proof (or "FORCED") is written to mr_spend_audit with the reason, in the
 * same transaction as the update; the txId must not have changed in between.
 * Idempotent (R19-P3-3): an already-released row returns alreadyReleased.
 * `operator` is a free-text label, NOT an authenticated identity: whoever
 * holds the DB credentials can write any name. Access control is the
 * state-reconcile.env DATABASE_URL role.
 */
export async function releaseSpendManually(
  pool: Pool,
  a: { store: string; id: string; operator: string; reason: string; prove?: TwoObservationProver; force?: boolean; nowMs?: number; network?: "testnet" | "mainnet"; warn?: (msg: string) => void },
): Promise<{ id: string; from: SpendStatus; to: "released"; alreadyReleased?: true; proof?: TwoObservationProof; forced?: true }> {
  if (!a.operator.trim()) throw new SpendOpError("--operator is required");
  if (a.reason.trim().length < 8) throw new SpendOpError("--reason is required (at least 8 characters)");
  if (a.force) {
    // R20-P3-1: never on MainNet; elsewhere only with an explicit network and a loud warning.
    if (a.network === "mainnet") throw new SpendOpError("--force is refused on MainNet; a release there needs a chain proof");
    if (a.network !== "testnet") throw new SpendOpError("--force needs an explicit NETWORK=testnet");
    (a.warn ?? ((m: string) => console.error(m)))(
      `WARNING: --force releases reservation ${a.id} WITHOUT chain proof. If its txn can still confirm, the payer can overspend the cap. Recorded as FORCED in mr_spend_audit.`,
    );
  }
  const row = await new PgSpendStore(pool, { store: a.store }).get(a.id);
  if (!row) throw new SpendOpError("reservation not found");
  if (row.status === "released") return { id: a.id, from: "released", to: "released", alreadyReleased: true };
  if (row.status !== "pending" && row.status !== "ambiguous") throw new SpendOpError(`reservation is ${row.status}; only pending/ambiguous can be released`);
  let proof: TwoObservationProof | undefined;
  let reason: string;
  let action: "manual-release" | "manual-release-forced";
  if (a.force) {
    action = "manual-release-forced";
    reason = `FORCED (no chain proof): ${a.reason.trim()}`;
  } else {
    // R21-P3-5: never suggest --force where it is refused.
    const hint = noProofHint(a.network);
    if (!a.prove) throw new SpendOpError(`chain proof required: configure two providers (INDEXER_URL and PROOF2_URL / PROOF2_KIND)${hint}`);
    proof = await a.prove(row);
    if (!proof.ok) throw new SpendOpError(`no proof the txn can no longer confirm: ${proof.why}${hint}`);
    action = "manual-release";
    reason = a.reason.trim(); // R23-P2-1: the proof is stored in typed columns, not in the reason
  }
  // R22-P3-1: runs as mr_release (the only role with EXECUTE on mr_spend_release).
  // The DB records session_user + its own clock; the operator name is an untrusted label.
  const r = await release(pool, {
    store: a.store, id: a.id, action, label: a.operator.trim(), reason,
    txId: a.force ? null : row.txId, ...(proof && proof.ok ? { proof } : {}),
  });
  if (!r.ok) {
    if (r.status === "released") return { id: a.id, from: "released", to: "released", alreadyReleased: true };
    throw new SpendOpError(r.status ? `reservation changed to ${r.status} (or its txId changed); retry` : "reservation not found");
  }
  return { id: a.id, from: r.from, to: "released", ...(proof ? { proof } : {}), ...(a.force ? { forced: true as const } : {}) };
}

/** R21-P3-5: the override hint depends on the network; MainNet has no override. */
export function noProofHint(network: "testnet" | "mainnet" | undefined): string {
  if (network === "mainnet") return "; MainNet has no override: wait until the round is past lastValid + margin and the indexer agrees, then retry";
  if (network === "testnet") return "; on TestNet you may pass --force with a reason to override";
  return "; --force needs an explicit NETWORK=testnet and is refused on MainNet";
}

/**
 * `released` stays 0 since R22-P3-1: reconcile (mr_reconcile) can no longer
 * release. A row the chain says can no longer confirm is marked ambiguous
 * (if pending) and counted in `needsRelease`; an operator then releases it
 * with chain proof via `spend release` under the mr_release role.
 */
export type ReconcileSummary = { checked: number; settled: number; released: number; needsRelease: number; unknown: number; skipped?: "locked"; stuckToAmbiguous?: number };

/**
 * Cron-safe reconcile: one run per store at a time (pg_try_advisory_lock;
 * overlapping runs return {skipped:"locked"}), checks each ambiguous / stale
 * pending row against the chain and audits every change.
 */
export async function reconcileSpendPg(
  pool: Pool,
  a: { store: string; check: ChainCheck; pendingOlderThanMs?: number; pendingSignedTimeoutMs?: number | null; limit?: number; dryRun?: boolean; nowMs?: number },
): Promise<ReconcileSummary> {
  const lockClient = await pool.connect();
  try {
    const { rows } = await lockClient.query<{ ok: boolean }>("SELECT pg_try_advisory_lock(hashtextextended($1, 0)) AS ok", [`mr:reconcile:${a.store}`]);
    if (!rows[0]?.ok) return { checked: 0, settled: 0, released: 0, needsRelease: 0, unknown: 0, skipped: "locked" };
    try {
      const nowMs = a.nowMs ?? Date.now();
      const store = new PgSpendStore(pool, { store: a.store });
      const out: ReconcileSummary = { checked: 0, settled: 0, released: 0, needsRelease: 0, unknown: 0 };
      // R44: pending rows with stored signed bytes but no recorded settle outcome -> ambiguous after the timeout
      if (!a.dryRun && a.pendingSignedTimeoutMs !== null) {
        const has = await pool.query("SELECT to_regprocedure('mr_spend_pending_signed_to_ambiguous(text, bigint)') IS NOT NULL AS ok");
        if (has.rows[0]?.ok) {
          const r = await pool.query<{ n: number }>("SELECT mr_spend_pending_signed_to_ambiguous($1, $2) AS n", [a.store, a.pendingSignedTimeoutMs ?? 15 * 60_000]);
          if ((r.rows[0]?.n ?? 0) > 0) out.stuckToAmbiguous = r.rows[0]!.n;
        }
      }
      for (const r of await store.listUnresolved(nowMs, a.pendingOlderThanMs ?? 15 * 60_000, a.limit ?? 500)) {
        out.checked++;
        let v: "settled" | "released" | "unknown";
        try {
          v = await a.check(r);
        } catch {
          v = "unknown";
        }
        if (v === "unknown") {
          out.unknown++;
          continue;
        }
        if (!r.txId) {
          out.unknown++; // R23-P3-3: nothing is settled or flagged without a pinned txId
          continue;
        }
        if (v === "released") {
          // Expired and not on chain: only mr_release may free the cap. Flag it.
          out.needsRelease++;
          if (a.dryRun || r.status === "ambiguous") continue;
          await settle(pool, {
            store: a.store, id: r.id, from: ["pending"], to: "ambiguous", action: "chain-reconcile-expired", label: "reconcile",
            reason: `not on chain after lastValid ${r.lastValid} (tx ${r.txId}); needs release with proof`, txId: r.txId,
          });
          continue;
        }
        if (a.dryRun) {
          out.settled++;
          continue;
        }
        const t = await settle(pool, {
          store: a.store, id: r.id, from: ["pending", "ambiguous"], to: "settled", action: "chain-reconcile", label: "reconcile",
          reason: `confirmed on chain (tx ${r.txId})`, txId: r.txId,
        });
        if (t.ok) out.settled++;
      }
      return out;
    } finally {
      await lockClient.query("SELECT pg_advisory_unlock(hashtextextended($1, 0))", [`mr:reconcile:${a.store}`]).catch(() => undefined);
    }
  } finally {
    lockClient.release();
  }
}

export async function spendAudit(pool: Pool, store: string, id: string) {
  const { rows } = await pool.query(
    `SELECT at_ms::text, actor, action, from_status, to_status, reason, proof_tx_id, proof_genesis_hash,
            proof_round_checked::text, proof_last_valid::text, proof_margin, proof_indexer_status,
            proof_provider, proof_kind, proof2_provider, proof2_kind, proof2_genesis_hash, proof2_round_checked::text, proof2_status,
            proof_operator, proof2_operator
       FROM mr_spend_audit WHERE store = $1 AND id = $2 ORDER BY seq`,
    [store, id],
  );
  return rows as Array<{
    at_ms: string; actor: string; action: string; from_status: string; to_status: string; reason: string;
    proof_tx_id: string | null; proof_genesis_hash: string | null; proof_round_checked: string | null;
    proof_last_valid: string | null; proof_margin: number | null; proof_indexer_status: number | null;
    proof_provider: string | null; proof_kind: string | null; proof2_provider: string | null; proof2_kind: string | null;
    proof_operator?: string | null; proof2_operator?: string | null;
    proof2_genesis_hash: string | null; proof2_round_checked: string | null; proof2_status: number | null;
  }>;
}

/**
 * R20-P3-4: a table owner can `ALTER TABLE ... DISABLE TRIGGER` and so bypass
 * the append-only guard on mr_spend_audit. The reconcile/release role must
 * therefore never own it (or be a member of the owning role). Returns the
 * reason when the connected role could bypass the guard, else null.
 */
export async function auditOwnerRisk(pool: Pool): Promise<string | null> {
  const { rows } = await pool.query<{ owner: string; me: string; member: boolean; su: boolean }>(
    `SELECT t.tableowner AS owner, current_user AS me,
            pg_has_role(current_user, t.tableowner, 'MEMBER') AS member,
            (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS su
       FROM pg_tables t WHERE t.tablename = 'mr_spend_audit' AND t.schemaname = current_schema()`,
  );
  const r = rows[0];
  if (!r) return "mr_spend_audit not found";
  if (r.su) return "connected role is a superuser";
  if (r.member) return "connected role owns (or is a member of the owner of) mr_spend_audit";
  return null;
}

/**
 * T11 monitoring: unresolved spend rows (pending/ambiguous) older than
 * `olderThanMs`, plus (R23-P3-4) rows reconcile flagged as needing a release
 * (ambiguous, latest audit action chain-reconcile-expired) for longer than
 * `needsReleaseOlderThanMs` (MONITOR_NEEDS_RELEASE_MAX_MIN, default 60 min).
 */
export async function staleSpendCounts(
  pool: Pool,
  a: { store: string; olderThanMs: number; needsReleaseOlderThanMs?: number; nowMs?: number },
): Promise<{ pending: number; ambiguous: number; oldestAgeMs: number | null; needsReleaseOverdue: number; needsReleaseOldestAgeMs: number | null }> {
  const now = a.nowMs ?? Date.now();
  const cutoff = now - a.olderThanMs;
  const { rows } = await pool.query<{ status: string; n: string; oldest: string | null }>(
    `SELECT status, count(*)::text AS n, min(created_ms)::text AS oldest FROM mr_spend
      WHERE store = $1 AND status IN ('pending','ambiguous') AND created_ms < $2 GROUP BY status`,
    [a.store, cutoff],
  );
  const out = { pending: 0, ambiguous: 0, oldestAgeMs: null as number | null, needsReleaseOverdue: 0, needsReleaseOldestAgeMs: null as number | null };
  for (const r of rows) {
    out[r.status as "pending" | "ambiguous"] = Number(r.n);
    if (r.oldest !== null) {
      const age = now - Number(r.oldest);
      out.oldestAgeMs = Math.max(out.oldestAgeMs ?? 0, age);
    }
  }
  const nr = await pool.query<{ n: string; oldest: string | null }>(
    `SELECT count(*)::text AS n, min(flagged)::text AS oldest FROM (
       SELECT s.id, (SELECT a.at_ms FROM mr_spend_audit a WHERE a.store = s.store AND a.id = s.id ORDER BY a.seq DESC LIMIT 1) AS flagged,
              (SELECT a.action FROM mr_spend_audit a WHERE a.store = s.store AND a.id = s.id ORDER BY a.seq DESC LIMIT 1) AS action
         FROM mr_spend s WHERE s.store = $1 AND s.status = 'ambiguous') x
      WHERE x.action = 'chain-reconcile-expired' AND x.flagged < $2`,
    [a.store, now - (a.needsReleaseOlderThanMs ?? 60 * 60_000)],
  );
  out.needsReleaseOverdue = Number(nr.rows[0]?.n ?? 0);
  if (nr.rows[0]?.oldest) out.needsReleaseOldestAgeMs = now - Number(nr.rows[0].oldest);
  return out;
}

/** R25-P3-1: triggers that must exist and be enabled (tgenabled = 'O') on every run. */
export const EXPECTED_MR_TRIGGERS = [
  "mr_spend_audit.mr_spend_audit_no_update", "mr_spend_audit.mr_spend_audit_no_truncate",
  "mr_spend.mr_spend_guard_row", "mr_spend.mr_spend_guard_truncate",
  "mr_network.mr_network_no_change", "mr_network.mr_network_no_truncate",
  // v16 (R62-P2-1: a disabled guard is how an owner session would forge an unpause)
  ...["mr_pause_state", "mr_resume_nonce", "mr_pause_log", "mr_release_caps", "mr_config_audit", "mr_release_ledger"].flatMap((t) => [`${t}.${t}_guard`, `${t}.${t}_guard_t`]),
  "mr_release_nonce.mr_release_nonce_ledger", // R65-P2-1
] as const;

/** R62-P2-1: pause-state facts the monitor cross-checks against the append-only pause log and resume nonces. */
export interface PauseFacts {
  network: string; paused: boolean; pauseSeq: number; tamperCount: number;
  /** resume nonces recorded for the current pause_seq (an unpause needs exactly 2: signer + verifier) */
  noncesForSeq: number; nonceTamperCount: number | null;
  /** highest pause_seq in mr_pause_log / mr_resume_nonce, and the logged tamper_count of the current seq */
  logMaxSeq: number; nonceMaxSeq: number; logTamperCount: number | null;
  /** R63-P2-1: every stored resume pair re-verified against the pinned keys (problems; empty = all good) */
  sigProblems?: string[];
  /** R63-P2-1: the superuser event triggers (missing / not enabled = alert) and the pause objects' owner */
  ddlGuard?: Record<string, string>; pauseOwner?: string | null;
  /** R64-P2-1: "table x" / "function f(..)" -> owner, for every object in PAUSE_WRITER_TABLES / _FUNCTIONS */
  protectedOwners?: Record<string, string>;
  /** R65-P2-1: caps ledger vs mr_release_nonce / mr_spend / mr_release_caps (problems; empty = consistent) */
  ledgerProblems?: string[];
  /** R69-P3-2: the pinned protected-ACL fingerprint vs mr_v16_acl_fp() now, and the pin's DML guard triggers */
  aclPin?: { pin: string | null; fp: string | null; guards: Record<string, string> };
}
/** R63/R64-P2-1: objects deploy/sql/t11 gives to mr_pause_writer (the monitor pages any other owner or a missing one). */
export const PAUSE_WRITER_TABLES = ["mr_config_audit", "mr_pause_log", "mr_pause_state", "mr_release_caps", "mr_release_cosign", "mr_release_ledger", "mr_resume_nonce"];
export const PAUSE_WRITER_FUNCTIONS = ["mr_jcs(jsonb)", "mr_spend_release_attested(text,text,bytea,bytea,bytea,bytea,text,text)",
  "mr_spend_release_attested(text,text,bytea,bytea,text,text)", "mr_v16_nonce_ledger()",
  "mr_spend_release_attested_v12(text,text,bytea,bytea,bytea,bytea,text,text)", "mr_tamper_pause(text)", "mr_tamper_resume(bytea,bytea,bytea,bytea)",
  "mr_v16_audit(text,text,jsonb,jsonb)", "mr_v16_cooldown(integer,integer)", "mr_v16_guard()", "mr_v16_parse(bytea,text,text[])",
  "mr_set_tamper_cooldown_base(integer)"]; // R66-P3-1
export async function pauseFacts(pool: Pool): Promise<PauseFacts | null> {
  const has = await pool.query<{ ok: boolean }>("SELECT to_regclass('public.mr_pause_log') IS NOT NULL AS ok");
  if (!has.rows[0]?.ok) return null;
  const r = await pool.query(
    `SELECT s.network, s.paused, s.pause_seq::int AS seq, s.tamper_count AS cnt,
            (SELECT count(*)::int FROM mr_resume_nonce n WHERE n.network = s.network AND n.pause_seq = s.pause_seq) AS nn,
            (SELECT max(n.tamper_count) FROM mr_resume_nonce n WHERE n.network = s.network AND n.pause_seq = s.pause_seq) AS ntc,
            (SELECT coalesce(max(l.pause_seq), 0)::int FROM mr_pause_log l WHERE l.network = s.network) AS lmax,
            (SELECT coalesce(max(n.pause_seq), 0)::int FROM mr_resume_nonce n WHERE n.network = s.network) AS nmax,
            (SELECT l.tamper_count FROM mr_pause_log l WHERE l.network = s.network AND l.pause_seq = s.pause_seq) AS ltc
       FROM mr_pause_state s JOIN mr_network m ON m.network = s.network AND m.singleton`,
  );
  const x = r.rows[0];
  if (!x) return null;
  // R63-P2-1: re-verify every stored resume pair (signer attestation + verifier co-signature) against the pinned keys
  const rows = (await pool.query(
    `SELECT n.pause_seq::int AS seq, n.role, n.tamper_count AS tc, n.msg, n.sig, coalesce(sk.pubkey, ck.pubkey) AS pub
       FROM mr_resume_nonce n
       LEFT JOIN mr_signer_key sk ON n.role = 'signer' AND sk.key_id = n.key_id AND sk.network = n.network
       LEFT JOIN mr_cosigner_key ck ON n.role = 'verifier' AND ck.key_id = n.key_id AND ck.network = n.network
      WHERE n.network = $1 ORDER BY n.pause_seq, n.role`, [x.network])).rows as Array<{ seq: number; role: string; tc: number; msg: Buffer; sig: Buffer; pub: Buffer | null }>;
  const sigProblems: string[] = [];
  const bySeq = new Map<number, typeof rows>();
  for (const row of rows) bySeq.set(row.seq, [...(bySeq.get(row.seq) ?? []), row]);
  for (const [seq, pair] of bySeq) {
    const sg = pair.find((p) => p.role === "signer"), vf = pair.find((p) => p.role === "verifier");
    if (pair.length !== 2 || !sg || !vf) { sigProblems.push(`pause_seq ${seq}: ${pair.length} resume rows (expected signer + verifier)`); continue; }
    for (const p of pair) if (!p.pub || !verifyAttestation(p.msg, p.sig, p.pub)) sigProblems.push(`pause_seq ${seq}: ${p.role} resume signature does not verify against a pinned key`);
    try {
      const a = decodeResume(sg.msg), c = decodeResumeCosign(vf.msg);
      if (a.pauseSeq !== seq || c.pauseSeq !== seq || a.tamperCount !== sg.tc) sigProblems.push(`pause_seq ${seq}: signed resume names another pause`);
      if (c.attestHash !== createHash("sha256").update(sg.msg).digest("hex")) sigProblems.push(`pause_seq ${seq}: co-signature not bound to the signer message`);
      if (a.network !== x.network || c.network !== x.network) sigProblems.push(`pause_seq ${seq}: signed resume for another network`);
    } catch (e) { sigProblems.push(`pause_seq ${seq}: stored resume message does not parse (${(e as Error).message})`); }
  }
  const ev = (await pool.query<{ n: string; e: string }>("SELECT evtname AS n, evtenabled::text AS e FROM pg_event_trigger WHERE evtname LIKE 'mr\\_v16\\_ddl\\_guard%'")).rows;
  const ddlGuard: Record<string, string> = {};
  for (const e of ev) ddlGuard[e.n] = e.e;
  const own = (await pool.query<{ o: string }>("SELECT tableowner AS o FROM pg_tables WHERE schemaname = 'public' AND tablename = 'mr_pause_state'")).rows[0];
  // R64-P2-1: every object mr_pause_writer must own (the app owner could otherwise DISABLE TRIGGER / UPDATE / replace)
  const protectedOwners = Object.fromEntries((await pool.query<{ k: string; o: string }>(
    `SELECT 'table ' || c.relname AS k, pg_get_userbyid(c.relowner) AS o FROM pg_class c
      WHERE c.relnamespace = 'public'::regnamespace AND c.relname = ANY ($1)
     UNION ALL
     SELECT 'function ' || p.oid::regprocedure::text, pg_get_userbyid(p.proowner) FROM pg_proc p
      WHERE p.pronamespace = 'public'::regnamespace AND p.oid::regprocedure::text = ANY ($2)`,
    [PAUSE_WRITER_TABLES, PAUSE_WRITER_FUNCTIONS])).rows.map((x) => [x.k, x.o]));
  // R69-P3-2: pin present and equal to the live fingerprint; the pin's DML guard present and enabled ('O')
  let aclPin: PauseFacts["aclPin"];
  if ((await pool.query<{ ok: boolean }>("SELECT to_regprocedure('public.mr_v16_acl_fp()') IS NOT NULL AS ok")).rows[0]?.ok) {
    const hasPin = (await pool.query<{ ok: boolean }>("SELECT to_regclass('public.mr_v16_acl_pin') IS NOT NULL AS ok")).rows[0]?.ok;
    const q = (await pool.query<{ pin: string | null; fp: string | null }>(hasPin ? "SELECT (SELECT fp FROM public.mr_v16_acl_pin WHERE id) AS pin, public.mr_v16_acl_fp() AS fp" : "SELECT NULL::text AS pin, public.mr_v16_acl_fp() AS fp")).rows[0]!;
    const g = hasPin ? (await pool.query<{ n: string; e: string }>("SELECT tgname AS n, tgenabled::text AS e FROM pg_trigger WHERE tgrelid = 'public.mr_v16_acl_pin'::regclass AND NOT tgisinternal")).rows : [];
    aclPin = { pin: q.pin, fp: q.fp, guards: Object.fromEntries(g.map((r) => [r.n, r.e])) };
  }
  return { aclPin, network: x.network, paused: x.paused, pauseSeq: x.seq, tamperCount: x.cnt, noncesForSeq: x.nn, nonceTamperCount: x.ntc ?? null, logMaxSeq: x.lmax, nonceMaxSeq: x.nmax, logTamperCount: x.ltc ?? null,
    sigProblems, ddlGuard, pauseOwner: own?.o ?? null, protectedOwners, ledgerProblems: await ledgerProblems(pool, x.network) };
}
/**
 * R65-P2-1: the wrapper's ledger is the rolling-24 h basis; cross-check it against what actually happened.
 *  - a release nonce (any time) with no ledger row = a release outside the wrapper (or a dropped nonce trigger)
 *  - a ledger row whose spend is released but has no nonce = mr_release_nonce rows were removed
 *  - the 24 h ledger sum above the cap, or below the 24 h sum of nonce-backed releases (ledger rows missing)
 */
async function ledgerProblems(pool: Pool, network: string): Promise<string[]> {
  if (!(await pool.query<{ ok: boolean }>("SELECT to_regclass('public.mr_release_ledger') IS NOT NULL AS ok")).rows[0]?.ok) return [];
  const r = (await pool.query(
    `SELECT (SELECT count(*)::int FROM mr_release_nonce n WHERE NOT EXISTS (SELECT 1 FROM mr_release_ledger l WHERE l.store = n.store AND l.spend_id = n.spend_id)) AS unledgered,
            (SELECT count(*)::int FROM mr_release_ledger l JOIN mr_spend s ON s.store = l.store AND s.id = l.spend_id
              WHERE s.status = 'released' AND NOT EXISTS (SELECT 1 FROM mr_release_nonce n WHERE n.store = l.store AND n.spend_id = l.spend_id)) AS nonceless,
            (SELECT coalesce(sum(l.amount_micro), 0)::text FROM mr_release_ledger l WHERE l.network = $1 AND l.at > clock_timestamp() - interval '24 hours') AS lsum,
            (SELECT coalesce(sum(s.amount_micro), 0)::text FROM mr_release_nonce n JOIN mr_spend s ON s.store = n.store AND s.id = n.spend_id
              WHERE n.used_at > clock_timestamp() - interval '24 hours') AS nsum,
            (SELECT max_day_micro::text FROM mr_release_caps c WHERE c.network = $1) AS cap`, [network])).rows[0] as { unledgered: number; nonceless: number; lsum: string; nsum: string; cap: string | null };
  const out: string[] = [];
  if (r.unledgered > 0) out.push(`${r.unledgered} attested release(s) in mr_release_nonce have no caps-ledger row (released outside mr_spend_release_attested)`);
  if (r.nonceless > 0) out.push(`${r.nonceless} ledgered release(s) have no mr_release_nonce row (nonce rows removed)`);
  if (r.cap !== null && BigInt(r.lsum) > BigInt(r.cap)) out.push(`24 h ledger sum ${r.lsum} is above the day cap ${r.cap}`);
  if (BigInt(r.nsum) > BigInt(r.lsum)) out.push(`24 h released sum ${r.nsum} (mr_release_nonce) is above the ledger's ${r.lsum} (ledger rows missing)`);
  return out;
}
/** R62-P2-1: alerts for a forged unpause / rolled-back counters (the trigger state itself is in EXPECTED_MR_TRIGGERS). */
export function pauseReasons(f: PauseFacts | null | undefined): string[] {
  if (!f) return [];
  const out: string[] = [];
  if (f.pauseSeq < f.logMaxSeq || f.pauseSeq < f.nonceMaxSeq) out.push(`integrity: pause_seq went down (state ${f.pauseSeq}, log ${f.logMaxSeq}, nonces ${f.nonceMaxSeq})`);
  if (f.pauseSeq > f.logMaxSeq) out.push(`integrity: pause_seq ${f.pauseSeq} has no mr_pause_log row (pause not written by mr_tamper_pause)`);
  if (f.pauseSeq > 0 && f.logTamperCount !== null && f.tamperCount !== f.logTamperCount) out.push(`integrity: tamper_count changed outside mr_tamper_pause (state ${f.tamperCount}, logged ${f.logTamperCount})`);
  if (!f.paused && f.pauseSeq > 0 && f.noncesForSeq !== 2) out.push(`integrity: unpaused without the 2-of-2 resume (pause_seq ${f.pauseSeq} has ${f.noncesForSeq} resume nonces, expected 2)`);
  if (f.paused && f.noncesForSeq !== 0) out.push(`integrity: paused but pause_seq ${f.pauseSeq} already has resume nonces`);
  for (const p of f.sigProblems ?? []) out.push(`integrity: forged or broken resume record: ${p}`);
  for (const p of f.ledgerProblems ?? []) out.push(`integrity: caps ledger: ${p}`);
  if (f.aclPin) {
    if (f.aclPin.pin === null) out.push("integrity: ACL pin mr_v16_acl_pin is missing (every GRANT now fails closed; re-run deploy/sql/t11 as postgres)");
    else if (f.aclPin.pin !== f.aclPin.fp) out.push(`integrity: protected ACL fingerprint ${String(f.aclPin.fp).slice(0, 12)} differs from the pin ${f.aclPin.pin.slice(0, 12)} (ACL changed or pin rewritten)`);
    for (const n of ["mr_v16_acl_pin_guard", "mr_v16_acl_pin_guard_t"]) {
      if (!(n in f.aclPin.guards)) out.push(`integrity: trigger ${n} on mr_v16_acl_pin is missing (re-run deploy/sql/t11 as postgres)`);
      else if (f.aclPin.guards[n] !== "O") out.push(`integrity: trigger ${n} on mr_v16_acl_pin is not enabled (tgenabled ${f.aclPin.guards[n]})`);
    }
  }
  if (f.ddlGuard) for (const n of ["mr_v16_ddl_guard", "mr_v16_ddl_guard_drop"]) {
    if (!(n in f.ddlGuard)) out.push(`integrity: event trigger ${n} is missing (re-run deploy/sql/t11 as postgres)`);
    else if (f.ddlGuard[n] !== "O") out.push(`integrity: event trigger ${n} is not enabled (evtenabled ${f.ddlGuard[n]})`);
  }
  if (f.pauseOwner !== undefined && f.pauseOwner !== "mr_pause_writer") out.push(`integrity: mr_pause_state is owned by ${f.pauseOwner ?? "?"}, expected mr_pause_writer (re-run deploy/sql/t11)`);
  if (f.protectedOwners) {
    for (const k of [...PAUSE_WRITER_TABLES.map((t) => `table ${t}`), ...PAUSE_WRITER_FUNCTIONS.map((x) => `function ${x}`)]) {
      if (k === "table mr_pause_state") continue; // reported above
      const o = f.protectedOwners[k];
      if (o === undefined) out.push(`integrity: ${k} is missing`);
      else if (o !== "mr_pause_writer") out.push(`integrity: ${k} is owned by ${o}, expected mr_pause_writer (re-run deploy/sql/t11)`);
    }
  }
  if (f.nonceTamperCount !== null && f.nonceTamperCount !== f.tamperCount) out.push(`integrity: tamper_count differs from the one the resume was signed for (${f.tamperCount} vs ${f.nonceTamperCount})`);
  return out;
}

export interface IntegrityStatus {
  /** every non-internal trigger on an mr_* table: "table.name" -> tgenabled */
  triggers: Record<string, string>;
  marker: { network: string; genesisHash: string } | null;
  /** mr_admin can SET ROLE to the audit table's owner (must only be true during a deploy). */
  adminOwnerMember: boolean | null;
  /** R26-P3-2: every direct member of the owner (must be empty outside a deploy window). */
  ownerMembers?: string[];
  /** R26-P3-1: a deploy-window script holds the window lock right now (R27-P3-2: a VALID holder). */
  windowLockHeld?: boolean;
  /** R27-P3-2: every session holding lock (26026,1), with who it is and for how long (s; null = unreadable). */
  windowLockHolders?: Array<{ pid: number; user: string | null; app: string | null; ageS: number | null; valid: boolean }>;
  /** R26-P3-2: drift fingerprints. */
  drift?: DriftStatus;
  /** R62-P2-1 (v16) */
  pause?: PauseFacts | null;
}

/** R25-P3-1: read-only integrity facts for the monitor (works as mr_monitor). */
export async function integrityStatus(pool: Pool, o: { holderUser?: string } = {}): Promise<IntegrityStatus> {
  const holderUser = o.holderUser ?? WINDOW_HOLDER.user;
  const t = await pool.query<{ k: string; e: string }>(
    `SELECT t.tgrelid::regclass::text || '.' || t.tgname AS k, t.tgenabled::text AS e
       FROM pg_trigger t WHERE NOT t.tgisinternal AND t.tgrelid::regclass::text LIKE 'mr\\_%' ORDER BY 1`,
  );
  const triggers: Record<string, string> = {};
  for (const r of t.rows) triggers[r.k] = r.e;
  const m = await pool.query<{ network: string; genesis_hash: string }>("SELECT network, genesis_hash FROM mr_network WHERE singleton");
  const a = await pool.query<{ m: boolean | null }>(
    `SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mr_admin')
                 THEN pg_has_role('mr_admin', (SELECT tableowner FROM pg_tables WHERE schemaname = 'public' AND tablename = 'mr_spend_audit'), 'MEMBER')
            END AS m`,
  );
  const om = await pool.query<{ member: string }>(INTEGRITY_SQL.ownerMembers);
  const wl = await pool.query<{ pid: number; usr: string | null; app: string | null; age_s: number | null }>(INTEGRITY_SQL.windowLockHolders);
  const holders = wl.rows.map((r) => ({ pid: r.pid, user: r.usr, app: r.app, ageS: r.age_s, valid: r.usr === holderUser && r.app === WINDOW_HOLDER.app }));
  return {
    triggers,
    marker: m.rows[0] ? { network: m.rows[0].network, genesisHash: m.rows[0].genesis_hash } : null,
    adminOwnerMember: a.rows[0]?.m ?? null,
    ownerMembers: om.rows.map((r) => r.member),
    windowLockHeld: holders.some((h) => h.valid),
    windowLockHolders: holders,
    drift: await driftStatus(pool),
    pause: await pauseFacts(pool),
  };
}

/** R26-P3-1: the advisory lock deploy/mr-admin-window.sh holds for a whole window (two-int form). */
export const WINDOW_LOCK = { classid: 26026, objid: 1 } as const;
/** R27-P3-3: roles deploy/sql/t11-mr-reconcile-role.sql manages (their flags + memberships are in the manifest). */
export const MANAGED_ROLES = ["mr_admin", "mr_bridge", "mr_console", "mr_demo_api", "mr_monitor", "mr_pause_writer", "mr_reconcile", "mr_release"] as const;
/** R27-P3-2: the only valid holder of WINDOW_LOCK: a postgres session named mr-admin-window. */
export const WINDOW_HOLDER = { user: "postgres", app: "mr-admin-window", maxAgeS: 30 * 60 } as const;

/**
 * R26-P3-2: drift fingerprints (read-only, work as mr_monitor). ACL lines are
 * aclexplode()d and sorted, with the object's owner written OWNER and
 * PUBLIC as PUBLIC, so the same grants hash the same on any cluster.
 */
export const INTEGRITY_SQL = {
  providers: `SELECT md5(coalesce(string_agg(network || '|' || host || '|' || operator_id, E'\\n' ORDER BY network || '|' || host || '|' || operator_id COLLATE "C"), '')) AS h,
                     count(*)::int AS n FROM mr_network_provider`,
  functions: `SELECT p.oid::regprocedure::text AS sig, md5(p.prosrc) AS src
                FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
               WHERE n.nspname = 'public' AND p.proname LIKE 'mr\\_%' ORDER BY p.oid::regprocedure::text COLLATE "C"`,
  acls: `WITH objs AS (
    SELECT 'table ' || c.relname AS obj, c.relowner AS owner, c.relacl AS acl
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relname LIKE 'mr\\_%' AND c.relkind IN ('r', 'S', 'v', 'p')
    UNION ALL
    SELECT 'column ' || c.relname || '.' || a.attname, c.relowner, a.attacl
      FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relname LIKE 'mr\\_%' AND c.relkind IN ('r', 'p') AND a.attnum > 0 AND NOT a.attisdropped AND a.attacl IS NOT NULL
    UNION ALL
    SELECT 'function ' || p.oid::regprocedure::text || ' secdef=' || p.prosecdef || ' config=' || coalesce(array_to_string(p.proconfig, ','), '-')
           || ' owner=' || CASE WHEN p.proowner = (SELECT relowner FROM pg_class WHERE relname = 'mr_spend_audit' AND relnamespace = 'public'::regnamespace) THEN 'OWNER' WHEN (SELECT rolsuper FROM pg_roles WHERE oid = p.proowner) THEN 'SUPERUSER' ELSE pg_get_userbyid(p.proowner) END,
           p.proowner, p.proacl
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public' AND p.proname LIKE 'mr\\_%'
    UNION ALL
    -- R69-P3-2: default privileges (ALTER DEFAULT PRIVILEGES) of any role, any schema: none are expected
    SELECT 'defacl ' || pg_get_userbyid(d.defaclrole) || ' ' || d.defaclobjtype::text || ' ' || coalesce(d.defaclnamespace::regnamespace::text, '*'),
           d.defaclrole, d.defaclacl
      FROM pg_default_acl d
  ), lines AS (
    SELECT o.obj || ' ' || CASE WHEN o.acl IS NULL THEN '(default)'
             ELSE (CASE WHEN x.grantee = 0 THEN 'PUBLIC' WHEN x.grantee = o.owner THEN 'OWNER' ELSE pg_get_userbyid(x.grantee) END)
                  || '=' || x.privilege_type || CASE WHEN x.is_grantable THEN '*' ELSE '' END
                  || '/' || CASE WHEN x.grantor = o.owner THEN 'OWNER' ELSE pg_get_userbyid(x.grantor) END END AS l
      FROM objs o LEFT JOIN LATERAL aclexplode(o.acl) x ON true
  )
  SELECT md5(coalesce(string_agg(l, E'\\n' ORDER BY l COLLATE "C"), '')) AS h, coalesce(string_agg(l, E'\\n' ORDER BY l COLLATE "C"), '') AS text FROM lines`,
  ownerMembers: `SELECT m.rolname AS member FROM pg_auth_members am JOIN pg_roles m ON m.oid = am.member
                  WHERE am.roleid = (SELECT relowner FROM pg_class WHERE relname = 'mr_spend_audit' AND relnamespace = 'public'::regnamespace) ORDER BY 1`,
  // R27-P3-2 / R28-P3-2: holders with user / application_name / session age, read through the
  // SECURITY DEFINER mr_window_lock_holders() (role SQL; EXECUTE for mr_monitor only), which
  // returns only pid, usename, application_name and backend_start (no query text).
  windowLockHolders: `SELECT h.pid, h.usename::text AS usr, h.application_name AS app,
                 CASE WHEN h.backend_start IS NULL THEN NULL ELSE floor(extract(epoch FROM clock_timestamp() - h.backend_start))::int END AS age_s
            FROM public.mr_window_lock_holders() h ORDER BY h.pid`,
  // R27-P3-3: constraint definitions, owners, trigger definitions, role flags + memberships.
  constraints: `SELECT coalesce(string_agg(l, E'\n' ORDER BY l COLLATE "C"), '') AS text FROM (
      SELECT c.conrelid::regclass::text || '.' || c.conname || ' ' || pg_get_constraintdef(c.oid) AS l
        FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid JOIN pg_namespace n ON n.oid = t.relnamespace
       WHERE n.nspname = 'public' AND t.relname LIKE 'mr\\_%' AND c.contype <> 'n'
      UNION ALL
      -- NOT NULL from pg_attribute (PG18 also stores them as contype 'n'; this form is the same on 17 and 18)
      SELECT c.relname || '.' || a.attname || ' NOT NULL'
        FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'public' AND c.relname LIKE 'mr\\_%' AND c.relkind IN ('r', 'p') AND a.attnum > 0 AND NOT a.attisdropped AND a.attnotnull) x`,
  // owners: the audit table's owner is written OWNER (it differs per cluster); any other owner by name.
  owners: `WITH o AS (SELECT (SELECT relowner FROM pg_class WHERE relname = 'mr_spend_audit' AND relnamespace = 'public'::regnamespace) AS oid)
    SELECT coalesce(string_agg(l, E'\\n' ORDER BY l COLLATE "C"), '') AS text FROM (
      SELECT 'rel ' || c.relname || ' kind=' || c.relkind::text || ' owner=' || CASE WHEN c.relowner = (SELECT oid FROM o) THEN 'OWNER' ELSE pg_get_userbyid(c.relowner) END AS l
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'public' AND c.relname LIKE 'mr\\_%' AND c.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')
      UNION ALL
      SELECT 'function ' || p.oid::regprocedure::text || ' owner=' || CASE WHEN p.proowner = (SELECT oid FROM o) THEN 'OWNER' WHEN (SELECT rolsuper FROM pg_roles WHERE oid = p.proowner) THEN 'SUPERUSER' ELSE pg_get_userbyid(p.proowner) END
        FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public' AND p.proname LIKE 'mr\\_%') x`,
  triggerDefs: `SELECT coalesce(string_agg(l, E'\\n' ORDER BY l COLLATE "C"), '') AS text FROM (
      SELECT pg_get_triggerdef(t.oid) || ' fn=' || t.tgfoid::regprocedure::text || ' fn_md5=' || md5(p.prosrc) AS l
        FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid
       WHERE NOT t.tgisinternal AND t.tgrelid::regclass::text LIKE 'mr\\_%') x`,
  // roles: the role SQL's roles (fixed list; roles are cluster-wide) + the owner as OWNER; memberships
  // of / in them, except into the owner (deploy-window state, checked by ownerMembers).
  roles: `WITH o AS (SELECT (SELECT relowner FROM pg_class WHERE relname = 'mr_spend_audit' AND relnamespace = 'public'::regnamespace) AS oid),
    rs AS (SELECT r.oid, CASE WHEN r.oid = (SELECT oid FROM o) THEN 'OWNER' ELSE r.rolname::text END AS nm, r.rolcanlogin, r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolinherit, r.rolreplication, r.rolbypassrls, r.rolconnlimit FROM pg_roles r
            WHERE r.rolname IN (${MANAGED_ROLES.map((x) => `'${x}'`).join(", ")}) OR r.oid = (SELECT oid FROM o))
    SELECT coalesce(string_agg(l, E'\\n' ORDER BY l COLLATE "C"), '') AS text FROM (
      -- R28-P3-3: connection limit and settings are pinned for every role (app roles + owner included):
      -- the role SQL sets the limits and clears every setting (global and per-database, pg_db_role_setting).
      -- Only the app roles' LOGIN stays host-specific.
      SELECT 'role ' || nm || ' super=' || rolsuper || ' createrole=' || rolcreaterole
             || ' createdb=' || rolcreatedb || ' inherit=' || rolinherit || ' replication=' || rolreplication || ' bypassrls=' || rolbypassrls
             || CASE WHEN nm IN ('mr_demo_api', 'mr_console', 'mr_bridge') THEN '' ELSE ' login=' || rolcanlogin END
             || ' connlimit=' || rolconnlimit
             || ' config=' || coalesce((SELECT string_agg(coalesce(d.datname::text, '*') || ':' || array_to_string(s.setconfig, ','), ';' ORDER BY coalesce(d.datname::text, '*') COLLATE "C")
                                          FROM pg_db_role_setting s LEFT JOIN pg_database d ON d.oid = s.setdatabase WHERE s.setrole = rs.oid), '-') AS l
        FROM rs
      UNION ALL
      SELECT 'member ' || coalesce((SELECT nm FROM rs WHERE rs.oid = am.member), pg_get_userbyid(am.member)) || ' -> '
             || coalesce((SELECT nm FROM rs WHERE rs.oid = am.roleid), pg_get_userbyid(am.roleid))
             || ' set=' || am.set_option || ' inherit=' || am.inherit_option || ' admin=' || am.admin_option
        FROM pg_auth_members am
       WHERE (am.member IN (SELECT oid FROM rs) OR am.roleid IN (SELECT oid FROM rs)) AND am.roleid <> (SELECT oid FROM o)
      UNION ALL
      -- R29-P3-2: ALTER DATABASE <this db> SET / ALTER ROLE ALL [IN DATABASE] SET must be empty
      -- (the role SQL resets them); any row is drift.
      SELECT 'dbsetting ' || CASE WHEN s.setdatabase = 0 THEN '*' ELSE 'THISDB' END || ' ' || array_to_string(s.setconfig, ',')
        FROM pg_db_role_setting s
       WHERE s.setrole = 0 AND (s.setdatabase = 0 OR s.setdatabase = (SELECT oid FROM pg_database WHERE datname = current_database()))) x`,
  windowLock: `SELECT EXISTS (SELECT 1 FROM pg_locks l WHERE l.locktype = 'advisory' AND l.granted AND l.classid = ${WINDOW_LOCK.classid} AND l.objid = ${WINDOW_LOCK.objid} AND l.objsubid = 2
                 AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database())) AS held`,
} as const;

export interface DriftStatus {
  providersHash: string;
  providersCount: number;
  functions: Record<string, string>;
  aclHash: string;
  aclText: string;
  /** R27-P3-3 */
  constraintsHash: string; constraintsText: string;
  ownersHash: string; ownersText: string;
  triggersHash: string; triggersText: string;
  rolesHash: string; rolesText: string;
  /** R64-P2-1: mr_release_caps values ("network" -> "perRelease/perDay" micro-USDC), compared with the manifest */
  releaseCaps?: Record<string, string>;
  /** R70-P3-2: mr_v16_acl_fp() now (null when t11 is not applied), compared with the manifest-pinned value */
  aclFp?: string | null;
}

/** R26-P3-2: provider allowlist hash, prosrc md5 per mr_* function, ACL hash. */
export async function driftStatus(pool: Pool): Promise<DriftStatus> {
  const p = await pool.query<{ h: string; n: number }>(INTEGRITY_SQL.providers);
  const f = await pool.query<{ sig: string; src: string }>(INTEGRITY_SQL.functions);
  const a = await pool.query<{ h: string; text: string }>(INTEGRITY_SQL.acls);
  const t = async (q: string) => (await pool.query<{ text: string }>(q)).rows[0]!.text;
  const [constraintsText, ownersText, triggersText, rolesText] = [await t(INTEGRITY_SQL.constraints), await t(INTEGRITY_SQL.owners), await t(INTEGRITY_SQL.triggerDefs), await t(INTEGRITY_SQL.roles)];
  const md5 = (x: string) => createHash("md5").update(x).digest("hex");
  const hasCaps = (await pool.query<{ ok: boolean }>("SELECT to_regclass('public.mr_release_caps') IS NOT NULL AS ok")).rows[0]?.ok;
  const releaseCaps = hasCaps
    ? Object.fromEntries((await pool.query<{ n: string; r: string; d: string }>("SELECT network AS n, max_release_micro::text AS r, max_day_micro::text AS d FROM mr_release_caps ORDER BY network")).rows.map((x) => [x.n, `${x.r}/${x.d}`]))
    : undefined;
  // R70-P3-2: the protected-ACL fingerprint itself, so a superuser repin of mr_v16_acl_pin can't hide a change
  const hasFp = (await pool.query<{ ok: boolean }>("SELECT to_regprocedure('public.mr_v16_acl_fp()') IS NOT NULL AS ok")).rows[0]?.ok;
  const aclFp = hasFp ? (await pool.query<{ fp: string }>("SELECT public.mr_v16_acl_fp() AS fp")).rows[0]!.fp : null;
  return {
    releaseCaps, aclFp,
    constraintsHash: md5(constraintsText), constraintsText, ownersHash: md5(ownersText), ownersText,
    triggersHash: md5(triggersText), triggersText, rolesHash: md5(rolesText), rolesText,
    providersHash: p.rows[0]!.h, providersCount: p.rows[0]!.n,
    functions: Object.fromEntries(f.rows.map((r) => [r.sig, r.src])),
    aclHash: a.rows[0]!.h, aclText: a.rows[0]!.text,
  };
}
