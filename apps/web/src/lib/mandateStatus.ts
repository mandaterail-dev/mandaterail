import type { IntentMandate } from "./types";

/**
 * MR-P1R-P2-4: the panel must never call a mandate "active" unless the
 * console itself reports that it verified the AC2 signature. The client-side
 * `signature` field (or metadata) is never trusted: a missing, stub, present-
 * but-unverified, or invalid signature is shown as such, and so is an expired
 * mandate. Only `authorization.status === "signature-verified"` with
 * `authorizedForExecute === true` counts as active.
 * R30-P3-4: expiry comes from the console (server clock): it reports
 * status "expired" / authorizedForExecute false once expiresAt has passed.
 * The browser clock can only make a mandate look expired sooner, never keep
 * an expired one active.
 */
export type MandateDisplayStatus =
  | "active"
  | "revoked"
  | "expired"
  | "unsigned"
  | "unverified"
  | "invalid";

export function mandateDisplayStatus(
  m: IntentMandate,
  nowMs: number = Date.now(),
): MandateDisplayStatus {
  if (m.revoked) return "revoked";
  const a = m.authorization;
  if (a?.status === "revoked") return "revoked";
  if (a?.status === "signature-invalid") return "invalid";
  if (a?.status === "expired") return "expired";
  if (!m.signature || a?.status === "unsigned-draft") return "unsigned";
  if (
    !a ||
    a.status !== "signature-verified" ||
    a.authorizedForExecute !== true
  ) {
    return "unverified";
  }
  const exp = Date.parse(m.expiresAt);
  if (!Number.isFinite(exp) || exp <= nowMs) return "expired";
  return "active";
}

export const MANDATE_STATUS_STYLE: Record<MandateDisplayStatus, string> = {
  active: "bg-emerald-50 text-emerald-700",
  revoked: "bg-rose-50 text-rose-700",
  expired: "bg-slate-100 text-slate-600",
  unsigned: "bg-amber-50 text-amber-700",
  unverified: "bg-amber-50 text-amber-700",
  invalid: "bg-rose-50 text-rose-700",
};
