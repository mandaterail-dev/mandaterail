# Eng hygiene review — P1 security residuals (2026-09-21)

**NOT a public audited claim.** Internal engineering hygiene only. Do not cite this note as “security audited,” “formally verified,” or MainNet-hardened.

## Scope

- Runtime merchant API key prefix validation (`mr_test_` / `mr_live_`) in `@mandaterail/core`, enforced by `demo-api` when `X-MandateRail-Key` is present.
- Deny-by-default CORS allowlist via `CORS_ORIGINS` (comma-separated exact origins; empty = no CORS headers) on `demo-api` and `ac2-bridge`.
- `OperatorAttestation` verifier stub (`device` | `hsm` | `vault`) via `UnimplementedOperatorAttestationVerifier` (501); production device/HSM/vault bindings remain TODO. Lab token shim stays `InsecureDevOperatorAuth`.
- Wiring into `apps/demo-api` and `apps/ac2-bridge`.
- Branch intent: Mac checkout → push `<public-repo>` `main` only (never `<personal>`).

## Tests run

- `pnpm install`
- `pnpm --filter @mandaterail/core test`
- `pnpm --filter @mandaterail/core typecheck`
- `pnpm --filter @mandaterail/demo-api typecheck` (ensure demo-api still typechecks)

## Code review

- Prefix helper rejects cross-network keys (`mr_live_` on TestNet; `mr_test_` on MainNet) and requires explicit MainNet enablement before accepting `mr_live_`.
- CORS middleware applies only allowlisted `Origin` values; missing/empty `CORS_ORIGINS` yields no ACAO headers (localhost SPA should proxy).
- Attestation stub is explicit and non-spoofing: unimplemented path returns 501 rather than silently succeeding.
- AC2 bridge comments record that real device/HSM/vault verifiers are still TODO.

## Security punchlist

| ID | Finding | Severity | Status |
|----|---------|----------|--------|
| P1-KEY | Runtime `mr_test_` / `mr_live_` prefix validation | P1 residual (from P0 recheck) | PASS (code + tests) |
| P1-CORS | Deny-by-default `CORS_ORIGINS` allowlist on demo-api + ac2-bridge | P1 | PASS (code + tests); Pages origin must be added to env when browser-calling APIs |
| P1-ATTEST | OperatorAttestation stub (device/HSM/vault) wired, unimplemented | P1 residual | PASS (stub only — not production attestation) |
| P1-WIRE | demo-api + ac2-bridge consume core helpers | P1 | PASS |

## Residual risks

- **Pages / Webdesigner:** production Cloudflare Pages origin is **not** automatically allowlisted. If the SPA calls demo-api/ac2-bridge cross-origin, operators must set `CORS_ORIGINS` to include that Pages origin. Do not change Pages config from this residual drop.
- Attestation stub is intentionally unimplemented — do not treat presence of the interface as production OperatorAttestation.
- Broader P1 items (replay/nonce ledger, receipt IDOR, gateway CORS policy) remain open per `02-remediation-status.md`.

## Verdict

**PASS (eng hygiene)** — P1 residuals for API key prefix, CORS allowlist, and attestation stub are recorded and wired for TestNet/lab demos. **Not** an external security audit.
