import { useCallback, useEffect, useState } from "react";
import { TopBar } from "./components/TopBar";
import { WalletPicker } from "./components/WalletPicker";
import { StatusStrip } from "./components/StatusStrip";
import { MandatesPanel } from "./components/MandatesPanel";
import { ReceiptsPanel } from "./components/ReceiptsPanel";
import { ActionsPanel } from "./components/ActionsPanel";
import { useWalletConnect } from "./hooks/useWalletConnect";
import { useOperatorSigner } from "./hooks/useOperatorSigner";
import {
  USE_API_MOCKS,
  approvePending,
  bridgeRequiresSignedChallenge,
  getBridgeHealth,
  getPairStatus,
  listMandates,
  consoleRequiresSignedChallenge,
  listPending,
  listReceipts,
  rejectPending,
  revokeMandate,
} from "./api";
import type { IntentMandate, PairStatus, PendingApproval, Receipt } from "./lib/types";
import { mockMandates, mockPending, mockReceipts } from "./mocks/data";
import { X_PROFILE_URL } from "./lib/social";

export default function App() {
  const wallet = useWalletConnect();
  const operatorSigner = useOperatorSigner();
  const [mandates, setMandates] = useState<IntentMandate[]>([]);
  const [receipts, setReceipts] = useState<Receipt[]>([]);
  const [pending, setPending] = useState<PendingApproval[]>([]);
  const [pair, setPair] = useState<PairStatus | null>(null);
  const [bridgeOk, setBridgeOk] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [usingFallback, setUsingFallback] = useState(false);

  const refresh = useCallback(async () => {
    setError(null);
    try {
      // signed-challenge: listing pending is operator-gated; only sign when the
      // operator explicitly asks (onLoadPending), never on background refresh.
      const signed = await bridgeRequiresSignedChallenge().catch(() => false);
      // Same for the console: listing mandates needs a signed challenge.
      const consoleSigned = await consoleRequiresSignedChallenge().catch(() => false);
      const [m, r, p, ps, health] = await Promise.all([
        consoleSigned ? Promise.resolve<IntentMandate[]>([]) : listMandates(),
        listReceipts(),
        signed ? Promise.resolve<PendingApproval[]>([]) : listPending(),
        getPairStatus(),
        getBridgeHealth(),
      ]);
      setMandates(m);
      setReceipts(r);
      setPending(p);
      setPair(ps);
      setBridgeOk(Boolean(health.ok));
      setUsingFallback(false);
    } catch (e) {
      // A Pages browser cannot reach a developer's localhost backends. Keep
      // the console useful even if a live/local endpoint is unavailable.
      setMandates([...mockMandates]);
      setReceipts([...mockReceipts]);
      setPending(mockPending.filter((item) => item.status === "pending"));
      setPair({
        paired: true,
        mode: "manual",
        pendingCount: mockPending.filter((item) => item.status === "pending").length,
      });
      setBridgeOk(true);
      setUsingFallback(true);
      setError(
        USE_API_MOCKS
          ? "Demo data is temporarily unavailable. Showing calm empty states."
          : "Local backends unreachable (demo-api / console / AC2 bridge). Showing demo data. Run the backends locally or set VITE_USE_MOCKS=true.",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const onRevoke = async (id: string) => {
    setBusyId(id);
    try {
      await revokeMandate(id, operatorSigner);
      await refresh();
    } catch (e) {
      setError(
        /failed to fetch|networkerror|load failed/i.test(
          e instanceof Error ? e.message : String(e),
        )
          ? "That local backend is unreachable. Showing demo data is still available."
          : e instanceof Error
            ? e.message
            : String(e),
      );
    } finally {
      setBusyId(null);
    }
  };

  const onLoadMandates = async () => {
    setError(null);
    try {
      setMandates(await listMandates(operatorSigner));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const onLoadPending = async () => {
    setError(null);
    try {
      setPending(await listPending(operatorSigner));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const onApprove = async (id: string) => {
    setBusyId(id);
    try {
      await approvePending(id, operatorSigner);
      await refresh();
    } catch (e) {
      setError(
        /failed to fetch|networkerror|load failed/i.test(
          e instanceof Error ? e.message : String(e),
        )
          ? "That local backend is unreachable. Showing demo data is still available."
          : e instanceof Error
            ? e.message
            : String(e),
      );
    } finally {
      setBusyId(null);
    }
  };

  const onDeny = async (id: string) => {
    setBusyId(id);
    try {
      await rejectPending(id, operatorSigner);
      await refresh();
    } catch (e) {
      setError(
        /failed to fetch|networkerror|load failed/i.test(
          e instanceof Error ? e.message : String(e),
        )
          ? "That local backend is unreachable. Showing demo data is still available."
          : e instanceof Error
            ? e.message
            : String(e),
      );
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="min-h-screen">
      <TopBar
        connected={wallet.connected}
        address={wallet.address}
        providerName={wallet.providerName}
        onConnect={() => {
          void Promise.resolve(wallet.connect()).catch((e) => {
            setError(e instanceof Error ? e.message : String(e));
          });
        }}
        onDisconnect={() => {
          void Promise.resolve(wallet.disconnect()).catch((e) => {
            setError(e instanceof Error ? e.message : String(e));
          });
        }}
      />
      <WalletPicker
        open={wallet.pickerOpen}
        wallets={wallet.pickerWallets}
        busy={wallet.connecting || !wallet.isReady}
        error={wallet.connectError}
        onSelect={async (w) => {
          try {
            await wallet.selectWallet(w);
          } catch (e) {
            setError(e instanceof Error ? e.message : String(e));
          }
        }}
        onClose={wallet.closePicker}
      />
      <StatusStrip
        address={wallet.address}
        pair={pair}
        bridgeOk={bridgeOk}
        mocks={USE_API_MOCKS || usingFallback}
      />
      <main className="mx-auto max-w-6xl space-y-4 px-4 py-6">
        {error && (
          <div className="rounded-md border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-800">
            {error}
          </div>
        )}
        <div className="grid gap-4 lg:grid-cols-2">
          <MandatesPanel
            mandates={mandates}
            loading={loading}
            onRevoke={onRevoke}
            busyId={busyId}
            onLoad={() => void onLoadMandates()}
          />
          <ReceiptsPanel receipts={receipts} loading={loading} />
        </div>
        <ActionsPanel
          pending={pending}
          loading={loading}
          busyId={busyId}
          onApprove={onApprove}
          onDeny={onDeny}
          onLoadPending={() => void onLoadPending()}
        />
        <p className="text-center text-xs text-slate-400">
          MandateRail console · USDC ASA 10458941 · Apache-2.0
          {" · "}
          <a className="hover:text-accent" href="/docs/">Docs</a>
          {" · "}
          <a className="hover:text-accent" href="/docs/openapi.yaml" target="_blank" rel="noopener noreferrer">API</a>
          {" · "}
          <a className="hover:text-accent" href="/brand/manual.html">Brand</a>
          {" · "}
          <a
            className="inline-flex align-middle text-slate-500 transition-colors hover:text-accent"
            href={X_PROFILE_URL}
            target="_blank"
            rel="noopener noreferrer"
            aria-label="MandateRail on X"
            title="MandateRail on X"
          >
            <svg aria-hidden="true" focusable="false" width="17" height="17" viewBox="0 0 24 24" fill="currentColor">
              <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817-5.966 6.817H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z" />
            </svg>
          </a>
        </p>
      </main>
    </div>
  );
}
