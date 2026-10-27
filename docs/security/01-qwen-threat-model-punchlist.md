# Qwen independent review — threat model punchlist

**Source:** Independent Qwen review of MandateRail threat model / AC2 surface.  
**Ingest path (Mac, if present):**  
`<local-path>`  
**Status of this document:** Engineering punchlist summary. **Internal AI review only (eng hygiene); no third-party audit. NOT formally verified.** Findings below were **not** independently re-audited by MandateRail engineering before remediation tracking began.

Institutional voice — no personal bylines.

---

## Summary

Qwen’s review treated the draft STRIDE register (`00-threat-model.md`) as a useful skeleton and highlighted **config-drift and localhost-trust gaps** that can elevate demo assumptions into accidental exposure. Highest severity centered on **unauthenticated AC2 approve/reject**, **console/file-store bypass of the human gate**, and **insecure env flags** (`AC2_BRIDGE_AUTO_LOCAL`, `DEV_ALLOW_UNSIGNED`) surviving outside explicit CI/dev.

---

## P0 findings (implement first)

| ID | Finding | Sketch | Punchlist remediation |
|----|---------|--------|------------------------|
| **S2** | Unauthenticated AC2 `/approve` / `/reject` | Any process that can reach the bridge can inject or reject signatures | Keep default bind `127.0.0.1`. Require `X-MandateRail-Operator-Token` matching `AC2_OPERATOR_TOKEN` for `/approve` and `/reject` (and manual-mode `/sign`). If token unset: allow **only** loopback **and** `ALLOW_INSECURE_DEV=1`; else 401. Document in `docs/api/auth.md` + OpenAPI `OperatorAuth`. Block non-localhost exposure without bind+auth before demos beyond loopback. |
| **S-console** | Console / file-store can bypass AC2 human gate | Placeholder or missing signatures treated as usable mandates | Refuse unsigned mandates on any execute/authorize path; label `unsigned-draft`; verify via `@mandaterail/core` when signature present; README warning. |
| **S-drift** | `AC2_BRIDGE_AUTO_LOCAL` / `DEV_ALLOW_UNSIGNED` config-drift | Flags left on outside CI → auto-sign or accept unsigned | On `demo-api` and `ac2-bridge` startup: if either flag enabled, require `ALLOW_INSECURE_DEV=1` **and** `NETWORK` indicating TestNet; else `process.exit(1)`. Log one warning at start when flags on. |

---

## P1 / P2 (tracked, not all remediated here)

| Priority | Theme | Notes |
|----------|-------|-------|
| P1 | Replay / nonce ledger; revoke propagation | Threat register T-RP-* |
| P1 | CORS deny-by-default; bridge pending authz | OpenAPI + runtime |
| P1 | Receipt integrity / IDOR on demo list | Merchant-scoped receipts |
| P2 | Mock facilitator hard-refuse outside demo builds | T-RC-04 |
| P2 | Payer ≠ payTo runtime assert | T-PM-01 |
| P2 | Tighten MandateCreate in OpenAPI | Contract only |

See also OpenAPI review ingest: `03-qwen-openapi-punchlist.md` (if present) and remediation tracker `02-remediation-status.md`.

---

## Explicit non-claims

- This punchlist is **not** an audit report.
- Closing P0 items reduces demo footguns; it does **not** make MandateRail production-hardened or MainNet-ready.
- Independent Qwen review ≠ formal verification.
