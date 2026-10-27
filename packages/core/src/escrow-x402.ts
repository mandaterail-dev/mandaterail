/**
 * Escrow x402 (scheme mandaterail-escrow-v1) timing rules from docs/ops/escrow-timelock-design.md §5.4 (rev 6, R73-P3-3).
 * Pure functions shared by the signers (not_after) and the merchant middleware (nonce resolution).
 */
/** M's validity window cap: not_after <= signed_at + 600 (checked on-chain). */
export const ESCROW_M_MAX_WINDOW_S = 600;
/** not_after <= C.expires - 30 s: block-timestamp drift margin between signer and chain. */
export const ESCROW_CHALLENGE_MARGIN_S = 30;
/** the merchant keeps an unlanded nonce `issued` for C.expires + 120 s (confirmation grace). */
export const ESCROW_CONFIRM_GRACE_S = 120;
/** shortest window worth signing; anything shorter would expire before a broadcaster can land it. */
export const ESCROW_MIN_WINDOW_S = 20;

export class EscrowTimingRefused extends Error {}

/**
 * not_after for M: min(signed_at + 600, C.expires - 30). Refuses (no seq is used) when that leaves less than
 * ESCROW_MIN_WINDOW_S, i.e. the challenge is too close to expiry to land a release in time.
 */
export function escrowNotAfter(signedAt: number, challengeExpires: number): number {
  if (!Number.isSafeInteger(signedAt) || !Number.isSafeInteger(challengeExpires)) throw new EscrowTimingRefused("signed_at / C.expires must be integer unix seconds");
  const na = Math.min(signedAt + ESCROW_M_MAX_WINDOW_S, challengeExpires - ESCROW_CHALLENGE_MARGIN_S);
  if (na - signedAt < ESCROW_MIN_WINDOW_S) throw new EscrowTimingRefused(`challenge expires too soon: not_after ${na} would leave < ${ESCROW_MIN_WINDOW_S} s after signed_at ${signedAt}`);
  return na;
}

export type NonceState = "issued" | "used" | "expired";
/**
 * What the merchant knows about the landing of the presented release:
 *  - known: confirmed on the pinned network, landing-round block timestamp `ts` (agreed by its providers);
 *  - unknown: the tx or its block can't be read yet, or the merchant's providers disagree;
 *  - absent: confirmed NOT landed (and its not_after has passed by chain time, so it never will).
 */
export type Landing = { kind: "known"; ts: number } | { kind: "unknown" } | { kind: "absent" };
export interface NonceDecision { action: "serve" | "refuse" | "hold"; state: NonceState; reason: string }

/**
 * §5.4 nonce resolution (rev 6, R73-P3-3): timestamp unknown keeps the nonce `issued` (hold: neither served nor
 * burned) until it is resolved; the confirmation grace never moves an unknown to `used` or `expired`.
 * The rest of the acceptance conjunction (C equality, session, hashes, txid uniqueness) is checked by the caller in
 * the same DB transaction; this function only decides the timing conjunct and the next nonce state.
 */
export function resolveEscrowNonce(n: { state: NonceState; expires: number }, landing: Landing, now: number): NonceDecision {
  if (n.state !== "issued") return { action: "refuse", state: n.state, reason: `nonce ${n.state}` };
  switch (landing.kind) {
    case "unknown":
      return { action: "hold", state: "issued", reason: "landing timestamp unknown: nonce stays issued until resolved" };
    case "known":
      if (!Number.isSafeInteger(landing.ts)) return { action: "hold", state: "issued", reason: "landing timestamp not an integer: treated as unknown" };
      return landing.ts <= n.expires
        ? { action: "serve", state: "used", reason: "landed in time" }
        : { action: "refuse", state: "issued", reason: `landed at ${landing.ts} after C.expires ${n.expires}` };
    case "absent":
      return now > n.expires + ESCROW_CONFIRM_GRACE_S
        ? { action: "refuse", state: "expired", reason: "not landed within C.expires + grace" }
        : { action: "hold", state: "issued", reason: "not landed yet (within confirmation grace)" };
    default: {
      // R76-P3-5: an unknown landing kind at runtime is refused (fail closed); the never-guard keeps the switch exhaustive
      const _never: never = landing;
      return { action: "refuse", state: "issued", reason: `unknown landing kind ${String((_never as { kind?: unknown })?.kind)}` };
    }
  }
}

/** A nonce sweeper may expire an issued nonce only past the grace AND with no unresolved landing pending for it. */
export function escrowNonceSweepable(n: { state: NonceState; expires: number }, unresolvedLanding: boolean, now: number): boolean {
  return n.state === "issued" && !unresolvedLanding && now > n.expires + ESCROW_CONFIRM_GRACE_S;
}
