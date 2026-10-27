# Eng hygiene review — multi-wallet Connect picker (2026-09-21)

**NOT a public audited claim.** Internal engineering hygiene only. Do not cite this note as “security audited,” “formally verified,” or MainNet-hardened.

## Scope

- Feature: multi-wallet Connect picker on `apps/web` (display identity only).
- Branch intent: push `<public-repo>` only.
- Wallets registered: Pera, Defly, Defly Web, Lute (`siteName: MandateRail`), Exodus, Kibisis; optional WalletConnect iff `VITE_WALLETCONNECT_PROJECT_ID` non-empty.
- Explicitly **excluded**: MAGIC, MNEMONIC, KMD, WEB3AUTH.
- Signing: IntentMandate / OperatorAuth remain on AC2 bridge — SPA connect is display identity only.

## Tests run

- `pnpm --filter @mandaterail/web typecheck`
- `pnpm --filter @mandaterail/web build`
- Confirm `lute-connect` and `@agoralabs-sh/avm-web-provider` present in `apps/web/package.json` **and** `pnpm-lock.yaml` (lazy wallet imports mean a green build alone is insufficient).

## Code review

- Pera→Defly auto-chain removed; user selects an explicit wallet via `WalletPicker`.
- Connect errors surfaced in UI (no bare `void wallet.connect()` unhandled rejection).
- Esc / backdrop / close dismiss; `role="dialog"` + labelled title/description.
- TopBar prop type members unchanged (docstring may list additional providers).
- `useWalletStub.ts` retained.
- Mock path: picker of six still shown; connect yields `DEMO_PRINCIPAL` with `providerName === "Mock"`.

## Security punchlist

| ID | Finding | Severity | Status |
|----|---------|----------|--------|
| W1 | SPA never receives mnemonics / never signs IntentMandate via wallet SDK | — | PASS (by design) |
| W2 | No MAGIC/MNEMONIC/KMD/WEB3AUTH registered | P0 footgun | PASS |
| W3 | WalletConnect only when project id configured (no empty WC client) | P1 | PASS |
| W4 | TestNet default (`NetworkId.TESTNET`) | — | PASS |
| W5 | Connect errors must not leak secrets into UI | P2 | PASS (wallet SDK messages only) |

## Residual risks

- Browser-extension / WalletConnect UX failures are user-environment dependent.
- Defly Web / Kibisis require `@agoralabs-sh/avm-web-provider`; Lute requires `lute-connect` — both must stay direct deps.
- Public Pages demo still relies on API mocks; that is not production auth.

## Verdict

**PASS (eng hygiene)** — fit to merge for TestNet display-identity Connect. **Not** an external security audit.
