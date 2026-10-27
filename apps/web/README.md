# @mandaterail/web

MandateRail web console (Vite + React + TypeScript + Tailwind).

Default brand direction: **rail-check** (`public/brand/`).

## Run

From the monorepo root:

```bash
pnpm install
pnpm --filter @mandaterail/web dev
# or: pnpm web
```

Open http://127.0.0.1:5173

### Env

Copy `.env.example` → `.env` for an offline local development profile:

```
VITE_DEMO_API_URL=http://127.0.0.1:8787
VITE_AC2_BRIDGE_URL=http://127.0.0.1:8790
VITE_CONSOLE_API_URL=http://127.0.0.1:8788
VITE_USE_MOCKS=true
VITE_USE_API_MOCKS=true
VITE_WALLET_MOCKS=false
# VITE_WALLETCONNECT_PROJECT_ID=
```

With `VITE_USE_MOCKS=true`, the UI runs offline against fixtures (USDC ASA `10458941`, merchant suffix `JEHWBIRI`). No mnemonics.

Set `VITE_USE_MOCKS=false` and start the local backends (`demo-api`, `ac2-bridge`, `console`) to hit live JSON APIs.

### CORS

Browsers will block cross-origin calls to `127.0.0.1:8787/8788/8790` unless those services send CORS headers (or you proxy via Vite). Mocks avoid this for local UI work.

## Build

```bash
pnpm --filter @mandaterail/web build
```

## Wallet

Connect opens a multi-wallet picker backed by `@txnlab/use-wallet-react` on Algorand TestNet (`NetworkId.TESTNET`).

Registered providers: **Pera, Defly, Defly Web, Lute** (`siteName: MandateRail`), **Exodus, Kibisis**. Optional **WalletConnect** when `VITE_WALLETCONNECT_PROJECT_ID` is non-empty. Never MAGIC / MNEMONIC / KMD / WEB3AUTH.

- **Display identity only.** The connected address is shown in the TopBar; IntentMandate signing still goes through the AC2 bridge / OperatorAuth. The SPA never receives or handles mnemonics.
- API demo mode is controlled by `VITE_USE_API_MOCKS` (with `VITE_USE_MOCKS` retained as a compatibility alias); localhost URLs remain available as `.env` / `.env.local` overrides.
- Wallet mode is separate: Connect opens the picker unless `VITE_WALLET_MOCKS=true` (picker of six still shown; any choice yields `DEMO_PRINCIPAL` with providerName `Mock`).
- Cloudflare Pages builds set API mocks on and wallet mocks off, so the public demo has data without making localhost requests while real wallet providers remain available.
- Peer deps: `lute-connect` and `@agoralabs-sh/avm-web-provider` (Defly Web + Kibisis).


## Brand

See `public/brand/README.md` for mark directions and accent hexes.


## Cloudflare Pages (static deploy)

Build output is `apps/web/dist/` (`vite` `base: '/'`). Do **not** deploy until live backends expose CORS (or you proxy APIs).

```bash
pnpm --filter @mandaterail/web build
# from apps/web:
npx wrangler pages deploy dist --project-name=mandaterail
```

Set Pages env vars (`VITE_*` are bake-time — rebuild after changing). Prefer mocks or a same-origin API gateway until CORS is ready.
