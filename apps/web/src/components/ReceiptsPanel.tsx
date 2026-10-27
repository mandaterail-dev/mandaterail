import type { Receipt } from "../lib/types";
import { formatTime, shortAddress } from "../lib/format";
import { MERCHANT_SUFFIX } from "../lib/fixtures";

interface ReceiptsPanelProps {
  receipts: Receipt[];
  loading: boolean;
}

export function ReceiptsPanel({ receipts, loading }: ReceiptsPanelProps) {
  return (
    <section className="rounded-lg border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-100 px-4 py-3">
        <h2 className="text-sm font-semibold tracking-wide text-ink">
          Receipts
        </h2>
        <p className="mt-0.5 text-xs text-slate-500">
          demo-api · merchant …{MERCHANT_SUFFIX}
        </p>
      </div>
      <div className="divide-y divide-slate-100">
        {loading && (
          <p className="px-4 py-6 text-sm text-slate-500">Loading…</p>
        )}
        {!loading && receipts.length === 0 && (
          <p className="px-4 py-6 text-sm text-slate-500">No receipts yet.</p>
        )}
        {receipts.map((r) => (
          <div key={r.receiptId} className="px-4 py-3">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <p className="text-sm font-medium text-ink">
                {r.amount} ASA {r.asset}
              </p>
              <time className="text-xs text-slate-500">
                {formatTime(r.createdAt)}
              </time>
            </div>
            <p className="mt-0.5 text-xs text-slate-500">
              tx {shortAddress(r.txId, 6)} · mandate {r.mandateId}
            </p>
            <a
              href={r.explorerUrl}
              target="_blank"
              rel="noreferrer"
              className="mt-1 inline-block text-xs font-medium text-accent hover:underline"
            >
              Explorer
            </a>
          </div>
        ))}
      </div>
    </section>
  );
}
