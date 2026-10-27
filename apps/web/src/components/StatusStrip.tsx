import { shortAddress } from "../lib/format";
import type { PairStatus } from "../lib/types";

interface StatusStripProps {
  address: string | null;
  pair: PairStatus | null;
  bridgeOk: boolean | null;
  mocks: boolean;
}

function Dot({ ok }: { ok: boolean | null }) {
  const color =
    ok === null ? "bg-slate-300" : ok ? "bg-emerald-500" : "bg-rose-500";
  return <span className={`inline-block h-2 w-2 rounded-full ${color}`} />;
}

export function StatusStrip({
  address,
  pair,
  bridgeOk,
  mocks,
}: StatusStripProps) {
  const pairLabel = pair
    ? pair.paired
      ? `paired (${pair.mode})`
      : "unpaired"
    : "—";

  return (
    <div className="border-b border-slate-200 bg-slate-50">
      <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-6 gap-y-2 px-4 py-2 text-xs text-slate-600">
        <span>
          Address{" "}
          <strong className="font-mono text-ink">{shortAddress(address, 6)}</strong>
        </span>
        <span className="flex items-center gap-1.5">
          <Dot ok={pair?.paired ?? null} />
          AC2 {pairLabel}
        </span>
        <span className="flex items-center gap-1.5">
          <Dot ok={bridgeOk} />
          Bridge {bridgeOk === null ? "—" : bridgeOk ? "healthy" : "down"}
        </span>
        {mocks && (
          <span className="rounded bg-slate-200 px-1.5 py-0.5 font-medium text-slate-700">
            mocks
          </span>
        )}
      </div>
    </div>
  );
}
