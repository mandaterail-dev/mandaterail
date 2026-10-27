import { AC2_BRIDGE_URL, USE_MOCKS } from "./config";
import type { HealthResponse, PairStatus, PendingApproval } from "../lib/types";
import { mockPending, mutatePending } from "../mocks/data";

/**
 * OperatorAuth for bridge operator routes (GET /pending, Approve/Deny).
 *
 * signed-challenge (bridge /health operatorAttestationMode): fetch
 * GET /operator/challenge, sign with the connected wallet (use-wallet
 * signData / ARC-60, e.g. Lute) or — when the wallet cannot sign arbitrary
 * data (Pera, Defly, Exodus, Kibisis in use-wallet 4.6.0) — paste a base64
 * algosdk.signBytes(message) signature produced offline. Sends
 * X-MandateRail-Operator-Attestation. No shared secret in the SPA.
 *
 * token-lab (TestNet local only): optional VITE_AC2_OPERATOR_TOKEN →
 * X-MandateRail-Operator-Token. Never set it on public Pages.
 * Do NOT store mnemonics here.
 */
import {
  attestationHeaderFor,
  OPERATOR_ATTESTATION_HEADER,
  type BridgeOperatorAction,
  type OperatorSigner,
} from "./operatorAuth";

export type { OperatorSigner, SignDataResult, OperatorChallenge } from "./operatorAuth";
export type OperatorAction = BridgeOperatorAction;

let cachedMode: string | null = null;
async function attestationMode(): Promise<string> {
  if (cachedMode) return cachedMode;
  const h = await getJson<{ operatorAttestationMode?: string }>("/health");
  cachedMode = h.operatorAttestationMode ?? "token-lab";
  return cachedMode;
}

async function operatorAuthHeaders(
  action: OperatorAction,
  id: string,
  signer?: OperatorSigner | null,
): Promise<Record<string, string>> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if ((await attestationMode()) === "signed-challenge") {
    if (!signer) throw new Error("Connect an allowlisted operator wallet to continue.");
    headers[OPERATOR_ATTESTATION_HEADER] = await attestationHeaderFor(AC2_BRIDGE_URL, signer, action, id);
    return headers;
  }
  const token = import.meta.env.VITE_AC2_OPERATOR_TOKEN;
  if (typeof token === "string" && token.length > 0) {
    headers["X-MandateRail-Operator-Token"] = token;
  }
  return headers;
}

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(`${AC2_BRIDGE_URL}${path}`);
  if (!res.ok) throw new Error(`ac2-bridge ${path}: ${res.status}`);
  return res.json() as Promise<T>;
}

/** POST for operator-gated routes (approve/reject). */
async function postOperatorJson<T>(
  path: string,
  action: OperatorAction,
  id: string,
  signer: OperatorSigner | null | undefined,
  body?: unknown,
): Promise<T> {
  const res = await fetch(`${AC2_BRIDGE_URL}${path}`, {
    method: "POST",
    headers: await operatorAuthHeaders(action, id, signer),
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`ac2-bridge ${path}: ${res.status}`);
  return res.json() as Promise<T>;
}

export async function getBridgeHealth(): Promise<HealthResponse> {
  if (USE_MOCKS) {
    return {
      ok: true,
      service: "mandaterail-ac2-bridge",
      paired: true,
      mock: true,
    };
  }
  return getJson<HealthResponse>("/health");
}

export async function getPairStatus(): Promise<PairStatus> {
  if (USE_MOCKS) {
    return {
      paired: true,
      mode: "manual",
      pendingCount: mockPending.filter((p) => p.status === "pending").length,
    };
  }
  return getJson<PairStatus>("/pair/status");
}

/** True when the bridge requires a wallet-signed challenge per operator call. */
export async function bridgeRequiresSignedChallenge(): Promise<boolean> {
  if (USE_MOCKS) return false;
  return (await attestationMode()) === "signed-challenge";
}

export async function listPending(
  signer?: OperatorSigner | null,
): Promise<PendingApproval[]> {
  if (USE_MOCKS) return mockPending.filter((p) => p.status === "pending");
  const res = await fetch(`${AC2_BRIDGE_URL}/pending`, {
    headers: await operatorAuthHeaders("list", "pending", signer),
  });
  if (!res.ok) throw new Error(`ac2-bridge /pending: ${res.status}`);
  const data = (await res.json()) as { pending: PendingApproval[] };
  return data.pending.filter((p) => p.status === "pending");
}

export async function approvePending(
  id: string,
  signer?: OperatorSigner | null,
): Promise<PendingApproval> {
  if (USE_MOCKS) {
    const item = mutatePending(id, "approved");
    if (!item) throw new Error("not_found");
    return item;
  }
  return postOperatorJson<PendingApproval>(`/approve/${id}`, "approve", id, signer, {
    useLocal: false,
  });
}

export async function rejectPending(
  id: string,
  signer?: OperatorSigner | null,
): Promise<PendingApproval> {
  if (USE_MOCKS) {
    const item = mutatePending(id, "rejected");
    if (!item) throw new Error("not_found");
    return item;
  }
  return postOperatorJson<PendingApproval>(`/reject/${id}`, "reject", id, signer);
}
