# Remediation status

Tracks P0 / P1 / P2 items from the Qwen threat-model punchlist and related OpenAPI contract notes.  
**Internal AI review only (eng hygiene); no third-party audit. NOT formally verified. Not a claim of production hardening.**

**Scorecard (Qwen P0 recheck):** P0 items **closed** (code and/or contract). P1 items remain **open** or **partial** — see `04-qwen-p0-recheck.md`.

Last updated: 2026-09-21 (America/New_York) — P1 residuals eng-hygiene note recorded (see `audits/2026-09-21-p1-security-residuals.md`); code from Qwen P0 recheck residuals (`04-qwen-p0-recheck.md`).

| ID | Priority | Item | Status | Notes |
|----|----------|------|--------|-------|
| S2 | P0 | Unauthenticated AC2 approve/reject — OperatorAuth + loopback default | **Remediated (code)** | `ac2-bridge`: default bind `127.0.0.1`; `X-MandateRail-Operator-Token` / `AC2_OPERATOR_TOKEN`; loopback+`ALLOW_INSECURE_DEV=1` fallback; manual `/sign` gated. Docs + OpenAPI `OperatorAuth`. |
| S-console | P0 | Console must not bypass AC2 human gate | **Remediated (code)** | No stub signatures; `unsigned-draft` labeling; `POST .../authorize-check` refuses unsigned/stub; verify via `@mandaterail/core`. README warning. |
| S-drift | P0 | `AC2_BRIDGE_AUTO_LOCAL` / `DEV_ALLOW_UNSIGNED` hard-fail outside lab | **Remediated (code)** | `assertInsecureDevOrExit` in `@mandaterail/core`; called from `ac2-bridge` + `demo-api`. Requires `ALLOW_INSECURE_DEV=1` + TestNet `NETWORK`. |
| OA-P0-1 | P0 | OpenAPI: OperatorAuth on approve/reject (not ApiKeyAuth) | **Remediated (contract)** | `openapi/openapi.yaml` + `docs/api/auth.md` |
| OA-P0-2 | P0 | Document `mr_test_` / `mr_live_` key prefixes + validation required | **Remediated (code + contract)** | Auth doc + ApiKeyAuth; runtime `validateMerchantApiKeyPrefix` in `@mandaterail/core`, wired in `demo-api` when key present |
| OA-P0-3 | P0 | Mark console/dev-only surfaces (`x-mandaterail-surface`) | **Remediated (contract)** | Extension on console/dev paths + server descriptions |
| OA-P0-attest | P0 residual | OperatorAttestation verifier (device\|hsm\|vault) | **Stub only** | Interface + `UnimplementedOperatorAttestationVerifier` (501). Token shim = `InsecureDevOperatorAuth` only. Production bindings TODO. |
| OA-P0-apikey-runtime | P0 residual | Runtime `mr_test_` / `mr_live_` prefix validation | **Remediated (code)** | `@mandaterail/core` + `demo-api` middleware when `X-MandateRail-Key` present; MainNet requires `ALLOW_MAINNET=1` |
| OA-P1-CORS | P1 | CORS note in OpenAPI description | **Remediated (code + contract)** | OpenAPI note + runtime `CORS_ORIGINS` allowlist (empty = no CORS headers) on `demo-api` / `ac2-bridge` |
| OA-P1-errors | P1 | Error schema consistency on bridge routes | **Partial** | 401 responses added on operator routes; further alignment TBD |
| OA-P1-loopback | P1 | Document which routes must never leave loopback | **Partial** | Auth + security docs; runtime bind warnings |
| T-RP-* | P1 | Replay / nonce ledger + revoke propagation | **Open** | |
| T-RC-* | P1 | Receipt integrity / IDOR | **Open** | |
| T-CO-* | P1 | Production CORS / browser origin controls | **Partial** | Deny-by-default allowlist shipped; broader prod gateway policy still open |
| OA-P2-create | P2 | Tighten MandateCreate schema | **Open** | Do not block P0 |
| T-RC-04 | P2 | Mock facilitator hard-refuse outside demo | **Open** | |
| T-PM-01 | P2 | Runtime payTo ≠ payer assert | **Open** | |

## How to read status

- **Remediated (code)** — implemented in this repo’s demo apps / libraries; still TestNet / localhost oriented.
- **Remediated (contract)** — OpenAPI / docs updated; runtime may still be demo-only.
- **Partial / Open** — not closed; do not claim fixed in public materials.
