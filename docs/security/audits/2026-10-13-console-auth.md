# Review: console signed-challenge auth (2026-10-13, runs 12–15)

> **Internal AI review (eng hygiene).** internal reviewer (internal reviewer run 12), the internal dual-model reviewer. Not a third-party audit. Public copy may only say \"AI security reviewed. Use at your own risk.\" TestNet only. Not MainNet-hardened.

## Scope
- Repo: `<public-repo>`, branch `main`
- Base: `f02527a` (console signed-challenge auth, CORS, limits, startup gate). The run-12 fixes land on top of it (`2f30f3a`, `01b9fde`, `6bf64bc`). Run 13 reviewed `6bf64bc`; its fixes are in the commit that follows it.
- Files: `apps/console/src/{store,app,gate,index}.ts`, `apps/console/src/app.test.ts`, `.gitignore`, `.env.example`, `apps/console/README.md`, `docs/security/README.md`

## Findings
| ID | Sev | Finding | Status |
|---|---|---|---|
| CON-P2-1 | P2 | `store.ts` read-modify-write was not atomic or serialized, so a concurrent create could resurrect a revoked mandate and concurrent creates could exceed `CONSOLE_MAX_MANDATES`. A crash mid-write could truncate the file. | **Fixed**: in-process write mutex around read-modify-write, cap enforced inside the lock, temp file + fsync + rename (+ best-effort dir fsync). Tests: concurrent create+revoke keeps the mandate revoked; 25 concurrent creates at cap 10 yield exactly 10 and leave no temp files. |
| CON-P2-2 | P2 | The limiter counts requests before auth: unauthenticated `/mandates/*` requests (`apps/console/src/app.ts:295`, where the rate-limit middleware runs before `authorize`) and `GET /operator/challenge` requests (`app.ts:277`). It's keyed per client, so unauthenticated callers only use up their own quota, plus the global cap. | **Accepted**: Caddy rate limiting at the edge. |
| CON-P2-3 | P2 | `.ceo-export/` (patches, bundle, tarball) was committed. | **Fixed**: `git rm -r`, added to `.gitignore`. History was not rewritten, so the files remain in earlier commits. |
| CON-P3-4 | P3 | Test gaps: positive authorize-check, real bridge nonce replay, X-Forwarded-For keying with hops=1. | **Fixed**: positive authorize-check (verified signature → 200) and refused unsigned draft (403); a real bridge-issued, allowlisted-signed nonce gets 401 at the console; hops=1 buckets per X-Forwarded-For client. |
| CON-P3-5 | P3 | Docs omitted authorize-check from the authenticated routes, overstated "proxy headers denied", and the `CONSOLE_*` vars were missing from `.env.example`. | **Fixed** (this report included). |
| CON-P2-7 | P2 | Signed create could never verify: the console added `createdAt`, `metadata` and defaults to the signed bytes. | **Fixed (follow-up)**: signed creates are stored exactly as signed, and are rejected if the bytes would change or the signature fails. E2E test: signed POST /mandates, then authorize-check returns 200. `POST /mandates/{id}/authorize-check` is now an OpenAPI path. |
| CON-P2-8 | P2 | `resolvePrincipalAddress` trusted the client-sent `principalPubkey`, so an allowlisted operator could sign with their own key while naming any principal. | **Fixed (run 13)**: the verify key is bound to `principal`. For an Algorand address it's derived from the address, and a mismatched `principalPubkey` is rejected. For an Ed25519 `did:key`, `principalPubkey` is required and must equal the DID key. Any other principal is rejected. Tests in core and console: a forged principal is rejected at create (400) and at authorize-check (403); the right principal passes. |
| CON-P3-9 | P3 | Signed `createdAt` wasn't validated. A create could arrive already revoked. "Verified" status came from client-writable `metadata.draftStatus`. | **Fixed (run 13)**: signed `createdAt` must be ISO 8601, at most 15 min in the past and 2 min in the future (400 `invalid_createdAt`). `revoked: true` creates get 400 `already_revoked`. The store keeps a server-side `server.signatureVerified` flag beside each mandate, outside the signed bytes, and `classifyMandateAuth` uses only that flag. Legacy bare records read as unverified. |
| CON-P3-10 | P3 | The report's CON-P2-2 description and verdict heading were inaccurate. | **Fixed (run 13)**: CON-P2-2 restated, the verdict heading names run 13, and these rows were added. |
| CON-P3-6 | P3 | A local-only create without an id was not explicitly handled; `create_failed` leaked internal error text. | **Fixed**: a missing id gets a server-generated UUID (a malformed id gets 400 `invalid_id`); `create_failed` returns a generic message and logs the details server-side only. |

## Tests
At the run-13 fix commit, `pnpm test` gives core 74, ac2-client 7, ac2-bridge 29, sdk 5 and console 24, all passing. `pnpm typecheck` and `pnpm build` pass.

## Verdict — runs 12–15 (eng hygiene / AI review)
- **Run 12:** `apps/console` was cleared for public TestNet hosting once CON-P2-1..P3-6 were fixed.
- **Run 13:** found CON-P2-8..P3-10, fixed in `d8f3095`.
- **Run 14:** the live end-to-end test on `01b9fde` passed 15/15. Step 15 confirmed CON-P2-8 live.
- **Run 15:** `d8f3095` has no review blockers for TestNet and no new findings.

`apps/console` at `d8f3095` is cleared for public TestNet hosting under the conditions below. Internal AI review, not a third-party audit, and not a MainNet claim.

## Hosting conditions
- `OPERATOR_ATTESTATION_MODE=signed-challenge` with a non-empty `OPERATOR_ALLOWLIST` and `OPERATOR_SIGNDATA_DOMAIN` set (startup refuses otherwise on a non-loopback bind).
- `NETWORK` is TestNet. No MainNet.
- A single console process behind Caddy (TLS + rate limiting). Set `AC2_BRIDGE_TRUSTED_PROXY_HOPS=1` only when Caddy is the sole ingress and appends X-Forwarded-For.
- `CORS_ORIGINS` is set to the exact web origin(s).
- `CONSOLE_DATA_DIR` is on persistent local disk, not shared between processes.

## Residuals
- The challenge store and write mutex are in-memory and single-process. Multi-instance hosting needs a shared store or lock.
- `.ceo-export/` remains in git history.
