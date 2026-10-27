import { DEMO_API_URL, USE_MOCKS } from "./config";
import type { HealthResponse, Receipt } from "../lib/types";
import { mockReceipts } from "../mocks/data";

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(`${DEMO_API_URL}${path}`);
  if (!res.ok) throw new Error(`demo-api ${path}: ${res.status}`);
  return res.json() as Promise<T>;
}

export async function getDemoHealth(): Promise<HealthResponse> {
  if (USE_MOCKS) {
    return { ok: true, service: "mandaterail-demo-api", mock: true };
  }
  return getJson<HealthResponse>("/health");
}

export async function listReceipts(limit = 50): Promise<Receipt[]> {
  if (USE_MOCKS) return mockReceipts.slice(0, limit);
  const data = await getJson<{ receipts: Receipt[] }>(
    `/receipts?limit=${limit}`,
  );
  return data.receipts;
}

export async function getReceipt(id: string): Promise<Receipt | null> {
  if (USE_MOCKS) return mockReceipts.find((r) => r.receiptId === id) ?? null;
  const res = await fetch(`${DEMO_API_URL}/receipts/${id}`);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`demo-api /receipts/${id}: ${res.status}`);
  return res.json() as Promise<Receipt>;
}
