/**
 * JSON-file receipt store for successful settles.
 * Default path: apps/demo-api/data/receipts.json (override with RECEIPTS_PATH).
 */
import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  MAINNET_PROFILE,
  TESTNET_PROFILE,
  type ReceiptStore,
} from "@mandaterail/core";

/** TestNet explorer (Phase-1 default); see explorerUrlForTx for MainNet. */
export const EXPLORER_TX_BASE = TESTNET_PROFILE.explorerTxBase;

export interface Receipt {
  receiptId: string;
  mandateId: string;
  txId: string;
  network: string;
  payer: string;
  merchant: string;
  amount: string;
  asset: string;
  createdAt: string;
  explorerUrl: string;
}

export function explorerUrlForTx(txId: string, network?: string): string {
  const base = network === MAINNET_PROFILE.caip2 ? MAINNET_PROFILE.explorerTxBase : EXPLORER_TX_BASE;
  return `${base}/${txId}`;
}

function defaultReceiptsPath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  return resolve(here, "../data/receipts.json");
}

export function receiptsPath(): string {
  return process.env.RECEIPTS_PATH
    ? resolve(process.env.RECEIPTS_PATH)
    : defaultReceiptsPath();
}

function loadAll(path: string): Receipt[] {
  if (!existsSync(path)) return [];
  try {
    const raw = readFileSync(path, "utf8");
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed as Receipt[];
  } catch {
    return [];
  }
}

function saveAll(path: string, receipts: Receipt[]): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(receipts, null, 2) + "\n", "utf8");
  renameSync(tmp, path);
}

/** Extract Algorand tx id from facilitator settle payload. */
export function extractTxId(settle: unknown): string | null {
  if (!settle || typeof settle !== "object") return null;
  const o = settle as Record<string, unknown>;
  for (const key of ["transaction", "txId", "txid", "txID"]) {
    const v = o[key];
    if (typeof v === "string" && v.length > 0) return v;
  }
  return null;
}

export interface PersistReceiptInput {
  mandateId: string;
  txId: string;
  network: string;
  payer: string;
  merchant: string;
  amount: string;
  asset: string;
  createdAt?: string;
}

/** JSON-file receipts (single process; the Phase 1 behaviour). */
export class FileReceiptStore implements ReceiptStore<Receipt> {
  constructor(private readonly path: () => string = receiptsPath) {}
  add(receipt: Receipt): void {
    const p = this.path();
    const all = loadAll(p);
    all.push(receipt);
    saveAll(p, all);
  }
  get(receiptId: string): Receipt | null {
    return loadAll(this.path()).find((r) => r.receiptId === receiptId) ?? null;
  }
  /** Latest first. */
  list(limit: number): Receipt[] {
    return loadAll(this.path()).slice().reverse().slice(0, Math.max(0, limit));
  }
}

let store: ReceiptStore<Receipt> = new FileReceiptStore();

/** Swap the receipts backend (e.g. Postgres via @mandaterail/storage). */
export function setReceiptStore(s: ReceiptStore<Receipt>): void {
  store = s;
}

export function buildReceipt(input: PersistReceiptInput): Receipt {
  return {
    receiptId: crypto.randomUUID(),
    mandateId: input.mandateId,
    txId: input.txId,
    network: input.network,
    payer: input.payer,
    merchant: input.merchant,
    amount: input.amount,
    asset: input.asset,
    createdAt: input.createdAt ?? new Date().toISOString(),
    explorerUrl: explorerUrlForTx(input.txId, input.network),
  };
}

export async function persistReceipt(input: PersistReceiptInput): Promise<Receipt> {
  const receipt = buildReceipt(input);
  await store.add(receipt);
  return receipt;
}

export async function getReceipt(receiptId: string): Promise<Receipt | null> {
  return store.get(receiptId);
}

/** Latest first. */
export async function listReceipts(limit = 50): Promise<Receipt[]> {
  return store.list(limit);
}

export function getReceiptStore(): ReceiptStore<Receipt> {
  return store;
}
