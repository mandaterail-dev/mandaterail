/**
 * R70-P2-1 (design rev 4 §1.2): sign-side K guard, breaker/simulate preflight and the abandon(seq_to) message for the
 * escrow app. Pure functions only; the signer runtime (escrow-release.ts) calls them on one provider snapshot. Every refusal and warning comes back as a page string.
 */
export const ESCROW_K = 64; // program constant: last_seq < seq <= last_seq + K
export const ESCROW_K_WARN = 32;
export const ESCROW_K_GUARD = 48;
export const ABANDON_PREFIX = "MR-ESCROW-ABANDON-v2"; // 20 bytes (R71-P2-1: v2 adds expected_last_seq and not_after)
export const ABANDON_LEN = 108; // prefix 20 + genesis 32 + 7 x u64
export const ABANDON_TTL_MAX_S = 3600; // not_after - not_before upper bound (design rev 5 §3.3)

export interface EscrowAppState {
  bootstrapped: number; breakerState: number; keyEpoch: bigint; configEpoch: bigint; lastSeq: bigint;
  perReleaseCap: bigint; dailyHeadroom: bigint; releasesThisHour: number; maxPerHour: number;
}
/** R76-P3-2: `operators` = the escrow operator allowlist from CONFIG (escrow.operators), never the readers' own ids. */
export interface EscrowPins { keyEpoch: bigint; configEpoch: bigint; operators: readonly string[] }
export type PreflightResult =
  | { action: "sign"; pages: string[] }
  | { action: "abandon-first"; seqTo: bigint; pages: string[] }
  | { action: "refuse"; pages: string[] };

/** R71-P2-1: a co-signed abandon A both signers produced that has not landed or expired yet. */
export interface PendingAbandon { expectedLastSeq: bigint; seqTo: bigint; notBefore: number; notAfter: number }
/** R73-P3-2 / R74-P3-1: one pinned provider's read of the app (last_seq) and of chain time (LatestTimestamp). */
export interface ProviderView { provider: string; lastSeq: bigint; chainNow: number }
/** R74-P3-1: distinct pinned providers that must agree before a pending abandon counts as landed or expired. */
export const ESCROW_MIN_PROVIDERS = 2;
/**
 * R74-P3-2: a view whose chain time trails the signer's clock (chrony-checked) by more than this is stale and is not
 * used. A stalled provider therefore can't hold the min chain time back forever: it drops out (and pages); if fewer
 * than ESCROW_MIN_PROVIDERS fresh views remain, releases at or below a pending seq_to stop (fail closed, paged).
 */
export const ESCROW_VIEW_MAX_LAG_S = 60;
export function freshViews(views: readonly ProviderView[], localNow: number, maxLagS = ESCROW_VIEW_MAX_LAG_S): { fresh: ProviderView[]; pages: string[] } {
  const fresh: ProviderView[] = [], pages: string[] = [];
  for (const v of views) {
    if (!Number.isFinite(v.chainNow) || localNow - v.chainNow > maxLagS || v.chainNow - localNow > 30) pages.push(`escrow provider stale: ${v.provider} chain time ${v.chainNow} vs local ${localNow}`);
    else fresh.push(v);
  }
  return { fresh, pages };
}
/**
 * Fail closed (anything uncertain is "pending"). Views must come from >= ESCROW_MIN_PROVIDERS DISTINCT providers
 * (R74-P3-1; a repeated provider id counts once and must agree with itself). R76-P3-2: `pinned` (the config operator
 * allowlist) is REQUIRED; only views from pinned providers count, and an empty list is always pending (fail closed).
 *  - landed: EVERY provider reads last_seq >= seq_to;
 *  - expired: the MIN chain time across providers is past not_after, or EVERY provider reads last_seq > expected_last_seq
 *    (A asserts last_seq == expected, so it can never pass); last_seq < expected is a lagging read, not expiry;
 *  - otherwise, including too few providers, a non-finite chain time, or providers that disagree: pending.
 */
export function pendingAbandonStatus(p: PendingAbandon, views: readonly ProviderView[], pinned: readonly string[]): "landed" | "expired" | "pending" {
  if (!Array.isArray(pinned) || pinned.length === 0) return "pending";
  const use = views.filter((v) => pinned.includes(v.provider));
  const byId = new Map<string, ProviderView>();
  for (const v of use) {
    if (!Number.isFinite(v.chainNow)) return "pending";
    const o = byId.get(v.provider);
    if (o && (o.lastSeq !== v.lastSeq || o.chainNow !== v.chainNow)) return "pending"; // one provider, two answers
    byId.set(v.provider, v);
  }
  if (byId.size < ESCROW_MIN_PROVIDERS) return "pending";
  const vs = [...byId.values()];
  if (vs.every((v) => v.lastSeq >= p.seqTo)) return "landed";
  const minNow = Math.min(...vs.map((v) => v.chainNow));
  if (minNow > p.notAfter || vs.every((v) => v.lastSeq > p.expectedLastSeq)) return "expired";
  return "pending";
}

/**
 * Before building M for `seq` / `amount`. `lastAbandoned` = highest seq both signers hold as terminal-abandoned.
 * R71-P2-1: `pending` = an issued abandon A not yet landed / expired (judged from `views`, every provider; R73-P3-2). While it is
 * pending no release seq <= its seq_to is signed and no second abandon is issued; a seq <= lastAbandoned is refused.
 */
export function escrowPreflight(st: EscrowAppState, pins: EscrowPins, seq: bigint, amount: bigint, lastAbandoned: bigint | null, pending: PendingAbandon | null = null, views: readonly ProviderView[] = []): PreflightResult {
  const why: string[] = [];
  const pend = pending && pendingAbandonStatus(pending, views, pins.operators) === "pending" ? pending : null; // no views: stays pending (fail closed)
  if (st.bootstrapped !== 1) why.push("app not bootstrapped");
  if (st.breakerState !== 0) why.push("breaker not RUNNING");
  if (st.keyEpoch !== pins.keyEpoch) why.push(`key_epoch ${st.keyEpoch} != pinned ${pins.keyEpoch}`);
  if (st.configEpoch !== pins.configEpoch) why.push(`config_epoch ${st.configEpoch} != pinned ${pins.configEpoch}`);
  if (amount < 1n || amount > st.perReleaseCap) why.push("amount outside per_release_cap");
  if (amount > st.dailyHeadroom) why.push("24 h headroom exceeded");
  if (st.releasesThisHour >= st.maxPerHour) why.push("max_per_hour reached");
  if (seq <= st.lastSeq) why.push(`seq ${seq} <= last_seq ${st.lastSeq}`);
  if (lastAbandoned !== null && seq <= lastAbandoned) why.push(`seq ${seq} <= abandoned ${lastAbandoned} (would be a second identity for an abandoned seq)`);
  if (pend && seq <= pend.seqTo) why.push(`seq ${seq} <= pending abandon seq_to ${pend.seqTo} (wait until it lands or expires)`);
  if (why.length) return { action: "refuse", pages: why.map((w) => `escrow preflight refused: ${w}`) };
  const gap = seq - st.lastSeq;
  const pages = gap >= BigInt(ESCROW_K_WARN) ? [`escrow seq window filling (gap ${gap}/${ESCROW_K})`] : [];
  if (gap > BigInt(ESCROW_K_GUARD)) {
    pages.push("escrow seq window: release refused");
    if (pend) { pages.push(`escrow seq window: abandon to ${pend.seqTo} still pending (no re-issue before it lands or expires)`); return { action: "refuse", pages }; }
    if (lastAbandoned !== null && lastAbandoned > st.lastSeq && lastAbandoned < seq && lastAbandoned <= st.lastSeq + BigInt(ESCROW_K)) {
      return { action: "abandon-first", seqTo: lastAbandoned, pages };
    }
    pages.push("escrow seq window: no abandonable range (signer records not terminal)");
    return { action: "refuse", pages };
  }
  return { action: "sign", pages };
}

export interface SeqRecord { seq: bigint; state: "signed" | "landed" | "abandoned"; lastNotAfter: number }
/**
 * Signer rule for abandon(seq_to): every own record in (lastSeq, seqTo] is abandoned (or the seq was never signed),
 * the peer acked the same, and not_before > every not_after either side signed for those seqs. Returns not_before.
 */
export function abandonNotBefore(lastSeq: bigint, seqTo: bigint, own: SeqRecord[], peer: SeqRecord[], chainNow: number): number {
  if (!(seqTo > lastSeq && seqTo <= lastSeq + BigInt(ESCROW_K))) throw new Error("abandon: seq_to outside (last_seq, last_seq + K]");
  let maxNa = 0;
  for (const list of [own, peer]) for (const r of list) {
    if (r.seq <= lastSeq || r.seq > seqTo) continue;
    if (r.state !== "abandoned") throw new Error(`abandon: seq ${r.seq} is ${r.state}, not abandoned`);
    if (r.lastNotAfter >= chainNow) throw new Error(`abandon: seq ${r.seq} not_after has not passed by chain time`);
    maxNa = Math.max(maxNa, r.lastNotAfter);
  }
  const ownSeqs = new Set(own.filter((r) => r.seq > lastSeq && r.seq <= seqTo).map((r) => r.seq));
  const peerSeqs = new Set(peer.filter((r) => r.seq > lastSeq && r.seq <= seqTo).map((r) => r.seq));
  for (const q of ownSeqs) if (!peerSeqs.has(q)) throw new Error(`abandon: no peer terminal ack for seq ${q}`);
  return Math.max(maxNa + 1, chainNow);
}

/**
 * R71-P2-1: issue A. Refuses unless the app is bootstrapped and no earlier A is still pending (re-issue only after it
 * landed or expired). A binds expected_last_seq = the current on-chain last_seq and a short not_after, so a delayed A
 * can never land after the chain moved on and consume releases signed after it.
 */
export function abandonIssue(st: Pick<EscrowAppState, "bootstrapped" | "lastSeq">, seqTo: bigint, own: SeqRecord[], peer: SeqRecord[], views: readonly ProviderView[],
  pending: PendingAbandon | null, pinned: readonly string[], ttlS = ABANDON_TTL_MAX_S): PendingAbandon {
  if (!Array.isArray(pinned) || pinned.length === 0) throw new Error("abandon: no pinned operators (fail closed)");
  views = views.filter((v) => pinned.includes(v.provider)); // R76-P3-2
  if (new Set(views.map((v) => v.provider)).size < ESCROW_MIN_PROVIDERS || views.some((v) => !Number.isFinite(v.chainNow))) throw new Error(`abandon: needs views from >= ${ESCROW_MIN_PROVIDERS} distinct providers`);
  const chainNow = Math.min(...views.map((v) => v.chainNow)); // R73-P3-2: min chain time across providers
  if (st.bootstrapped !== 1) throw new Error("abandon: app not bootstrapped");
  if (!(ttlS > 0 && ttlS <= ABANDON_TTL_MAX_S)) throw new Error("abandon: ttl outside (0, ABANDON_TTL_MAX_S]");
  if (pending && pendingAbandonStatus(pending, views, pinned) === "pending") throw new Error(`abandon: an abandon to ${pending.seqTo} is still pending`);
  const notBefore = abandonNotBefore(st.lastSeq, seqTo, own, peer, chainNow);
  return { expectedLastSeq: st.lastSeq, seqTo, notBefore, notAfter: notBefore + ttlS };
}

const u64 = (v: bigint) => { if (v < 0n || v > 0xffff_ffff_ffff_ffffn) throw new Error("u64 out of range"); const b = Buffer.alloc(8); b.writeBigUInt64BE(v); return b; };
/** The 108-byte message both keys sign (bare Ed25519). The contract asserts last_seq == expected_last_seq and not_before <= now <= not_after. */
export function abandonMessage(a: { genesisHash: Uint8Array; appId: bigint; keyEpoch: bigint; configEpoch: bigint; expectedLastSeq: bigint; seqTo: bigint; notBefore: number; notAfter: number }): Buffer {
  if (a.genesisHash.length !== 32) throw new Error("genesis hash must be 32 bytes");
  if (!(a.seqTo > a.expectedLastSeq && a.seqTo <= a.expectedLastSeq + BigInt(ESCROW_K))) throw new Error("abandon: seq_to outside (expected_last_seq, +K]");
  if (!(a.notAfter > a.notBefore && a.notAfter - a.notBefore <= ABANDON_TTL_MAX_S)) throw new Error("abandon: not_after must be in (not_before, not_before + TTL]");
  const m = Buffer.concat([Buffer.from(ABANDON_PREFIX, "ascii"), Buffer.from(a.genesisHash), u64(a.appId), u64(a.keyEpoch), u64(a.configEpoch),
    u64(a.expectedLastSeq), u64(a.seqTo), u64(BigInt(a.notBefore)), u64(BigInt(a.notAfter))]);
  if (m.length !== ABANDON_LEN) throw new Error("abandon message length");
  return m;
}

/** Broadcaster gate: submit only after algod simulate of the complete signed group passed (R71-P3-4: and only that group). */
export function simulateGate(sim: { failed: boolean; message?: string; groupId?: string }, submitGroupId?: string): { submit: boolean; pages: string[] } {
  if (submitGroupId !== undefined && sim.groupId !== submitGroupId) return { submit: false, pages: ["escrow simulate gate: simulated group is not the group to submit"] };
  return sim.failed ? { submit: false, pages: [`escrow simulate failed: ${(sim.message ?? "unknown").slice(0, 200)}`] } : { submit: true, pages: [] };
}
