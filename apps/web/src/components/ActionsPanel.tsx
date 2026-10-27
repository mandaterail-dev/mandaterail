import type { PendingApproval } from "../lib/types";
import { formatTime } from "../lib/format";

interface ActionsPanelProps {
  pending: PendingApproval[];
  loading: boolean;
  busyId: string | null;
  onApprove: (id: string) => void;
  onDeny: (id: string) => void;
  /** signed-challenge bridges: sign a list challenge to load pending items. */
  onLoadPending?: () => void;
}

export function ActionsPanel({
  pending,
  loading,
  busyId,
  onApprove,
  onDeny,
  onLoadPending,
}: ActionsPanelProps) {
  return (
    <section className="rounded-lg border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-100 px-4 py-3">
        <h2 className="text-sm font-semibold tracking-wide text-ink">
          Pending approvals
        </h2>
        <div className="mt-0.5 flex items-center justify-between">
          <p className="text-xs text-slate-500">AC2 bridge</p>
          {onLoadPending && (
            <button
              type="button"
              onClick={onLoadPending}
              className="text-xs font-semibold text-accent hover:underline"
            >
              Sign in as operator to load
            </button>
          )}
        </div>
      </div>
      <div className="divide-y divide-slate-100">
        {loading && (
          <p className="px-4 py-6 text-sm text-slate-500">Loading…</p>
        )}
        {!loading && pending.length === 0 && (
          <p className="px-4 py-6 text-sm text-slate-500">
            No pending approvals.
          </p>
        )}
        {pending.map((p) => (
          <div
            key={p.id}
            className="flex flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
          >
            <div className="min-w-0 space-y-0.5">
              <p className="text-sm font-medium text-ink">
                {p.display_hint ?? p.sig_hint ?? p.id}
              </p>
              <p className="text-xs text-slate-500">
                {p.mandateId ? `mandate ${p.mandateId} · ` : ""}
                {formatTime(p.createdAt)}
              </p>
            </div>
            <div className="flex shrink-0 gap-2">
              <button
                type="button"
                disabled={busyId === p.id}
                onClick={() => onApprove(p.id)}
                className="rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-white hover:bg-[#244f8f] disabled:opacity-50"
              >
                Approve
              </button>
              <button
                type="button"
                disabled={busyId === p.id}
                onClick={() => onDeny(p.id)}
                className="rounded-md border border-slate-300 px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-50"
              >
                Deny
              </button>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
