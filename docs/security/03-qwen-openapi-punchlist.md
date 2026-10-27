# Qwen independent review — OpenAPI punchlist

**Source:** Independent Qwen OpenAPI pass.  
**Ingest path (Mac, if present):**  
`<local-path>`  
**Status:** Engineering punchlist summary. **Internal AI review only (eng hygiene); no third-party audit. NOT formally verified.** Original Mac file was not readable from the build agent at ingest time; this document reconstructs the internal reviewer / steering punchlist.

---

## P0 contract

1. **`/approve/{id}` and `/reject/{id}`** must use a separate **`OperatorAuth`** security scheme (`X-MandateRail-Operator-Token`), **not** general `ApiKeyAuth` (`X-MandateRail-Key`).
2. Document merchant key prefixes **`mr_test_`** (TestNet) and **`mr_live_`** (MainNet) in `openapi.yaml` + `docs/api/auth.md`; note that **prefix validation is required** at issuance/verification time (planned runtime).
3. Mark console / dev-only paths clearly via extension **`x-mandaterail-surface: console-dev`** (and/or server descriptions) so SDKs do not treat the file-store as a public product API.

## P1 (if time)

- CORS note in OpenAPI `info.description`
- Error schemas on operator routes (401/404 consistency)
- List wrapper consistency (`items` / `pending` / `receipts`)
- Call out which routes must **never leave loopback** (AC2 approve/reject/sign-manual, console store)

## P2

- Tighten `MandateCreate` (require signature in production profile) — **do not block P0**

## Remediation mapping

See `02-remediation-status.md` rows `OA-P0-*` / `OA-P1-*` / `OA-P2-*`.
