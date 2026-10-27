interface TopBarProps {
  connected: boolean;
  address: string | null;
  onConnect: () => void;
  onDisconnect: () => void;
  /** Optional wallet provider label (Pera, Defly, Lute, Exodus, Kibisis, Mock, …). */
  providerName?: string | null;
}

const navLink =
  "text-sm font-medium text-slate-600 hover:text-accent transition-colors";

export function TopBar({
  connected,
  address,
  onConnect,
  onDisconnect,
  providerName,
}: TopBarProps) {
  return (
    <header className="border-b border-slate-200 bg-white">
      <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-4 py-3">
        <div className="flex min-w-0 items-center gap-3">
          <a href="/" className="flex items-center gap-2" aria-label="MandateRail home">
            <img
              src="/brand/wordmark-rail-check-light.svg"
              alt="MandateRail"
              className="h-8 w-auto"
            />
          </a>
          <span className="rounded-full bg-amber-50 px-2.5 py-0.5 text-xs font-medium text-amber-800 ring-1 ring-amber-200">
            TestNet · not audited
          </span>
        </div>

        <nav className="flex flex-wrap items-center gap-4" aria-label="Site">
          <a className={navLink} href="/docs/">
            Docs
          </a>
          <a
            className={navLink}
            href="/docs/openapi.yaml"
            target="_blank"
            rel="noopener noreferrer"
          >
            API
          </a>
          <a className={navLink} href="/docs/05-developer-integration.html">
            Developers
          </a>
          <a className={navLink} href="/brand/manual.html">
            Brand
          </a>
        </nav>

        <div className="flex items-center gap-2">
          {connected && address ? (
            <>
              <span className="hidden text-xs text-slate-500 sm:inline">
                {providerName ? `${providerName} · ` : ""}
                {address.slice(0, 6)}…{address.slice(-4)}
              </span>
              <button
                type="button"
                onClick={onDisconnect}
                className="rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-50"
              >
                Disconnect
              </button>
            </>
          ) : (
            <button
              type="button"
              onClick={onConnect}
              className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-white hover:bg-[#244f8f]"
            >
              Connect wallet
            </button>
          )}
        </div>
      </div>
    </header>
  );
}
