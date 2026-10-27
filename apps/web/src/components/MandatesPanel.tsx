import type { IntentMandate } from "../lib/types";
import { formatTime, shortAddress } from "../lib/format";
import { MANDATE_STATUS_STYLE, mandateDisplayStatus } from "../lib/mandateStatus";

interface MandatesPanelProps {
  mandates: IntentMandate[];
  loading: boolean;
  onRevoke: (id: string) => void;
  busyId: string | null;
  /** signed-challenge consoles: sign a list challenge to load mandates. */
  onLoad?: () => void;
}

export function MandatesPanel({
  mandates,
  loading,
  onRevoke,
  busyId,
  onLoad,
}: MandatesPanelProps) {
  return (
    <section className="rounded-lg border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-100 px-4 py-3">
        <h2 className="text-sm font-semibold tracking-wide text-ink">
          Mandates
        </h2>
        {onLoad && (
          <div className="mt-0.5 flex items-center justify-between">
            <p className="text-xs text-slate-500">Console</p>
            <button
              type="button"
              onClick={onLoad}
              className="text-xs font-semibold text-accent hover:underline"
            >
              Sign in as operator to load
            </button>
          </div>
        )}
      </div>
      <div className="divide-y divide-slate-100">
        {loading && (
          <p className="px-4 py-6 text-sm text-slate-500">Loading…</p>
        )}
        {!loading && mandates.length === 0 && (
          <p className="px-4 py-6 text-sm text-slate-500">No mandates.</p>
        )}
        {mandates.map((m) => {
          const status = mandateDisplayStatus(m);
          return (
          <div
            key={m.id}
            className="flex flex-col gap-2 px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
          >
            <div className="min-w-0 space-y-0.5">
              <div className="flex flex-wrap items-center gap-2">
                <code className="truncate text-sm font-medium text-ink">
                  {m.id}
                </code>
                <span
                  className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${MANDATE_STATUS_STYLE[status]}`}
                  title={m.authorization?.message}
                >
                  {status}
                </span>
              </div>
              <p className="text-xs text-slate-500">
                {m.maxAmount} {m.asset} · principal{" "}
                {shortAddress(m.principal, 4)} · exp {formatTime(m.expiresAt)}
              </p>
            </div>
            {!m.revoked && (
              <button
                type="button"
                disabled={busyId === m.id}
                onClick={() => onRevoke(m.id)}
                className="shrink-0 rounded-md border border-slate-300 px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50"
              >
                Revoke
              </button>
            )}
          </div>
          );
        })}
      </div>
    </section>
  );
}
