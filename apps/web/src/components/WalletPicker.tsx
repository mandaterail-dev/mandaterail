import { useEffect, useId, useRef } from "react";
import type { Wallet } from "@txnlab/use-wallet-react";

export type WalletPickerProps = {
  open: boolean;
  wallets: Wallet[];
  busy?: boolean;
  error?: string | null;
  onSelect: (wallet: Wallet) => void | Promise<void>;
  onClose: () => void;
};

/**
 * Accessible multi-wallet Connect modal.
 * Lists providers from useWallet().wallets; Esc / backdrop / close dismiss.
 * Accent #2B5EA7 (Tailwind `accent`).
 */
export function WalletPicker({
  open,
  wallets,
  busy = false,
  error = null,
  onSelect,
  onClose,
}: WalletPickerProps) {
  const titleId = useId();
  const descId = useId();
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      role="presentation"
    >
      <button
        type="button"
        className="absolute inset-0 bg-slate-900/40"
        aria-label="Close wallet picker"
        onClick={onClose}
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descId}
        className="relative z-10 w-full max-w-sm rounded-lg border border-slate-200 bg-white shadow-xl"
      >
        <div className="flex items-start justify-between gap-3 border-b border-slate-100 px-4 py-3">
          <div>
            <h2 id={titleId} className="text-base font-semibold text-slate-900">
              Connect wallet
            </h2>
            <p id={descId} className="mt-0.5 text-xs text-slate-500">
              Display identity on TestNet. Mandates still sign via AC2 / OperatorAuth.
            </p>
          </div>
          <button
            ref={closeRef}
            type="button"
            onClick={onClose}
            className="rounded-md px-2 py-1 text-sm text-slate-500 hover:bg-slate-50 hover:text-slate-800"
            aria-label="Close"
          >
            ✕
          </button>
        </div>

        <ul className="max-h-80 space-y-1 overflow-y-auto p-3" aria-label="Available wallets">
          {wallets.map((wallet) => {
            const name = wallet.metadata?.name ?? wallet.id;
            const icon = wallet.metadata?.icon;
            return (
              <li key={wallet.id}>
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => {
                    void onSelect(wallet);
                  }}
                  className="flex w-full items-center gap-3 rounded-md border border-transparent px-3 py-2.5 text-left text-sm font-medium text-slate-800 hover:border-slate-200 hover:bg-slate-50 disabled:cursor-wait disabled:opacity-60"
                >
                  {icon ? (
                    <img src={icon} alt="" className="h-7 w-7 rounded" width={28} height={28} />
                  ) : (
                    <span
                      className="flex h-7 w-7 items-center justify-center rounded bg-[#2B5EA7]/10 text-xs font-semibold text-[#2B5EA7]"
                      aria-hidden
                    >
                      {name.slice(0, 1).toUpperCase()}
                    </span>
                  )}
                  <span className="flex-1">{name}</span>
                </button>
              </li>
            );
          })}
        </ul>

        {error && (
          <div
            role="alert"
            className="border-t border-rose-100 bg-rose-50 px-4 py-2 text-xs text-rose-800"
          >
            {error}
          </div>
        )}
      </div>
    </div>
  );
}
