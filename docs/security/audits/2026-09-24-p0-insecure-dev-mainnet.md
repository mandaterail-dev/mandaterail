# Eng hygiene review — P0 insecure-dev MainNet gates (2026-09-24)

**Internal AI review (eng hygiene); not a third-party audit.** Internal engineering hygiene only. Do not cite this note as a third-party audit, “formally verified,” or MainNet-hardened. internal reviewer Qwen recheck punchlist items — internal AI review.

## Scope

- **P0-1:** Close MainNet footgun in `authorizeOperator` loopback tokenless bypass; startup hard-fail for MainNet / `ALLOW_MAINNET` without `AC2_OPERATOR_TOKEN`; treat `ALLOW_INSECURE_DEV` itself as requiring TestNet lab profile.
- **P1-2:** SPA Approve/Deny attaches `X-MandateRail-Operator-Token` when `VITE_AC2_OPERATOR_TOKEN` is set (OperatorAuth header contract). No mnemonics.
- **P1-4:** `demo-api` default bind `127.0.0.1` (was `0.0.0.0`) + non-loopback warning.
- Branch intent: Mac checkout → push `<public-repo>` `main` only (never `<personal>`).

## Code changes

### P0-1 (`@mandaterail/core` `insecure-dev.ts`)

| Control | Behavior |
|---------|----------|
| `authorizeOperator` tokenless bypass | Requires loopback **and** `ALLOW_INSECURE_DEV=1` **and** TestNet `NETWORK` **and** not `ALLOW_MAINNET` / MainNet NETWORK |
| `listEnabledInsecureFlags` | Includes `ALLOW_INSECURE_DEV` — setting it without TestNet fails startup |
| `checkInsecureDev` / `assertInsecureDevOrExit` | Structured check + exit; same call sites |
| `checkOperatorGate` / `assertOperatorGateOrExit` | MainNet-ish **or** `ALLOW_MAINNET=1` → require non-empty `AC2_OPERATOR_TOKEN` or refuse start |
| Call sites | `ac2-bridge` + `demo-api` call both asserts at startup |
| ac2-bridge header comment | Updated to match new rules |

### P1-2 (`apps/web`)

- `approvePending` / `rejectPending` send `X-MandateRail-Operator-Token` when `import.meta.env.VITE_AC2_OPERATOR_TOKEN` is set.
- If unset, still call (bridge may allow TestNet loopback lab).
- Documented in `apps/web/.env.example`. Wallet connect remains identity-only.

### P1-4 (`apps/demo-api`)

- `DEMO_API_HOST` default `127.0.0.1`.
- Warns when bind is non-loopback.
- Root `.env.example` comment updated.

## Tests run

- `pnpm --filter @mandaterail/core test` (vitest) — includes new MainNet / ALLOW_MAINNET / operator-gate cases
- `pnpm --filter @mandaterail/core typecheck` (if run in this drop)

## Residual risks

| Residual | Notes |
|----------|--------|
| **SPA operator token (P1-2)** | A public SPA **cannot** hold a real operator secret. Baking `VITE_AC2_OPERATOR_TOKEN` into Cloudflare Pages ships the token to every browser. Acceptable only for **local console** matching `AC2_OPERATOR_TOKEN`. For Pages live, OperatorAuth **must** move to **server-side attestation** (device / HSM / vault) — see `docs/security/05-operator-attestation-bindings.md`. |
| Loopback lab bypass | Still intentional under explicit TestNet + `ALLOW_INSECURE_DEV`; not production auth. |
| MainNet readiness | These gates reduce accidental MainNet exposure of lab footguns; they do **not** equal MainNet hardening or an audit. |

## Verdict

**PASS (eng hygiene)** — P0-1 MainNet gates, P1-2 OperatorAuth header attach, and P1-4 localhost bind are recorded and wired for TestNet/lab demos. **Not** an external security audit.
