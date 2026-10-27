import { CONSOLE_API_URL, USE_MOCKS } from "./config";
import type { HealthResponse, IntentMandate } from "../lib/types";
import { mockMandates, mutateRevoke } from "../mocks/data";
import { DEMO_PRINCIPAL } from "../lib/fixtures";
import {
  attestationHeaderFor,
  OPERATOR_ATTESTATION_HEADER,
  type ConsoleOperatorAction,
  type OperatorSigner,
} from "./operatorAuth";

/**
 * Console mandate store. Hosted (signed-challenge) consoles need a
 * wallet-signed challenge per call, same flow as the AC2 bridge (audience
 * mandaterail-console). Local-only consoles accept direct loopback only.
 */
async function getJson<T>(path: string, headers: Record<string, string> = {}): Promise<T> {
  const res = await fetch(`${CONSOLE_API_URL}${path}`, { headers });
  if (!res.ok) throw new Error(`console ${path}: ${res.status}`);
  return res.json() as Promise<T>;
}

async function postJson<T>(
  path: string,
  body?: unknown,
  headers: Record<string, string> = {},
): Promise<T> {
  const res = await fetch(`${CONSOLE_API_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: body === undefined ? "{}" : JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`console ${path}: ${res.status}`);
  return res.json() as Promise<T>;
}

let cachedConsoleMode: string | null = null;
async function consoleMode(): Promise<string> {
  if (cachedConsoleMode) return cachedConsoleMode;
  const h = await getJson<{ operatorAttestationMode?: string }>("/health");
  cachedConsoleMode = h.operatorAttestationMode ?? "local-only";
  return cachedConsoleMode;
}

/** True when the console requires a wallet-signed challenge per call. */
export async function consoleRequiresSignedChallenge(): Promise<boolean> {
  if (USE_MOCKS) return false;
  return (await consoleMode()) === "signed-challenge";
}

async function consoleAuthHeaders(
  action: ConsoleOperatorAction,
  id: string,
  signer?: OperatorSigner | null,
): Promise<Record<string, string>> {
  if ((await consoleMode()) !== "signed-challenge") return {};
  if (!signer) throw new Error("Connect an allowlisted operator wallet to continue.");
  return {
    [OPERATOR_ATTESTATION_HEADER]: await attestationHeaderFor(CONSOLE_API_URL, signer, action, id),
  };
}

export async function getConsoleHealth(): Promise<HealthResponse> {
  if (USE_MOCKS) {
    return { ok: true, service: "mandaterail-console", mock: true };
  }
  return getJson<HealthResponse>("/health");
}

export async function listMandates(
  signer?: OperatorSigner | null,
): Promise<IntentMandate[]> {
  if (USE_MOCKS) return [...mockMandates];
  const data = await getJson<{ items: IntentMandate[] }>(
    "/mandates",
    await consoleAuthHeaders("mandate.list", "mandates", signer),
  );
  return data.items;
}

export async function getMandate(
  id: string,
  signer?: OperatorSigner | null,
): Promise<IntentMandate | null> {
  if (USE_MOCKS) return mockMandates.find((m) => m.id === id) ?? null;
  const res = await fetch(`${CONSOLE_API_URL}/mandates/${encodeURIComponent(id)}`, {
    headers: await consoleAuthHeaders("mandate.read", id, signer),
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`console /mandates/${id}: ${res.status}`);
  return res.json() as Promise<IntentMandate>;
}

export async function createMandate(
  body: Partial<IntentMandate> = {},
  signer?: OperatorSigner | null,
): Promise<IntentMandate> {
  if (USE_MOCKS) {
    const created: IntentMandate = {
      id: body.id ?? `mandate-mock-${Date.now()}`,
      principal: body.principal ?? DEMO_PRINCIPAL,
      agent: body.agent ?? "did:example:agent-1",
      maxAmount: body.maxAmount ?? "10.00",
      asset: body.asset ?? "USDC",
      allowlist: body.allowlist ?? ["demo-merchant"],
      expiresAt:
        body.expiresAt ??
        new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      revoked: false,
      nonce: body.nonce ?? crypto.randomUUID(),
      signature: body.signature ?? null,
      createdAt: new Date().toISOString(),
      metadata: body.metadata,
    };
    mockMandates.unshift(created);
    return created;
  }
  // The create challenge is bound to the mandate id, so choose it client-side.
  const withId = { ...body, id: body.id ?? crypto.randomUUID() };
  return postJson<IntentMandate>(
    "/mandates",
    withId,
    await consoleAuthHeaders("mandate.create", withId.id, signer),
  );
}

export async function revokeMandate(
  id: string,
  signer?: OperatorSigner | null,
): Promise<IntentMandate> {
  if (USE_MOCKS) {
    const m = mutateRevoke(id);
    if (!m) throw new Error("not_found");
    return m;
  }
  return postJson<IntentMandate>(
    `/mandates/${encodeURIComponent(id)}/revoke`,
    undefined,
    await consoleAuthHeaders("mandate.revoke", id, signer),
  );
}
