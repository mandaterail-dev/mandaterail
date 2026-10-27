# Qwen P0 recheck — internal reviewer scorecard

**Status:** Engineering recheck summary. **Internal AI review only (eng hygiene); no third-party audit. NOT formally verified.**  
**Anchor tip (requested):** `423daf3` (Mac checkout).  
**Box implementation base:** `d112e25` (P0 OperatorAuth / console gate / insecure-dev hard-fail). Local-computer tooling was set to **Never** for this agent session, so the Mac tip was not readable directly; PASS items below are reconstructed from the remediation tracker and P0 commit at `d112e25`, then residual work applied on the box clone.

Institutional voice — no personal bylines.

---

## PASS (P0 closed)

| ID | Item | Evidence |
|----|------|----------|
| S2 | Unauthenticated AC2 approve/reject | OperatorAuth (`X-MandateRail-Operator-Token` / `AC2_OPERATOR_TOKEN`); loopback + `ALLOW_INSECURE_DEV=1` fallback; default bind `127.0.0.1` |
| S-console | Console must not bypass AC2 human gate | Unsigned drafts labeled; authorize-check refuses unsigned/stub; verify via `@mandaterail/core` |
| S-drift | Insecure flags outside lab | `assertInsecureDevOrExit` requires `ALLOW_INSECURE_DEV=1` + TestNet `NETWORK` or process exit |
| OA-P0-1 | OpenAPI OperatorAuth on approve/reject | Contract updated; not merchant ApiKeyAuth |
| OA-P0-2 | Document `mr_test_` / `mr_live_` prefixes | Auth doc + OpenAPI (runtime validation added in this recheck) |
| OA-P0-3 | Console/dev surface markers | `x-mandaterail-surface` on console/dev paths |

---

## Residuals addressed in this recheck

| Residual | Disposition |
|----------|-------------|
| Runtime merchant API key prefix validation | **Implemented** in `@mandaterail/core` (`validateMerchantApiKeyPrefix`); wired in `demo-api` when `X-MandateRail-Key` present. `mr_test_` on TestNet; `mr_live_` only when MainNet explicitly enabled (`ALLOW_MAINNET=1` + MainNet `NETWORK`). |
| Operator attestation (device \| hsm \| vault) | **Stub only** — `OperatorAttestationVerifier` + `UnimplementedOperatorAttestationVerifier` (501). Live token shim remains `InsecureDevOperatorAuth`. Production bindings TODO. |
| CORS deny-by-default | **Implemented** — `CORS_ORIGINS` allowlist helper; empty = no CORS headers (localhost SPA must proxy). Wired in `demo-api` + `ac2-bridge`. |

---

## Still open (P1 / P2 — not claimed closed)

| ID | Item | Status |
|----|------|--------|
| T-RP-* | Replay / nonce ledger + revoke propagation | Open |
| T-RC-* | Receipt integrity / IDOR | Open |
| OA-P1-errors | Error schema consistency on bridge routes | Partial |
| OA-P1-loopback | Document which routes must never leave loopback | Partial |
| OA-P2-create | Tighten MandateCreate schema | Open |
| T-RC-04 | Mock facilitator hard-refuse outside demo | Open |
| T-PM-01 | Runtime payTo ≠ payer assert | Open |

---

## Explicit non-claims

- Closing P0 and the residuals above reduces demo footguns; it does **not** make MandateRail production-hardened or MainNet-ready.
- Independent Qwen review ≠ formal verification.
- `InsecureDevOperatorAuth` is a lab token shim, not device/HSM/vault attestation.
