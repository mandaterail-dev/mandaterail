# Audit: signed-challenge OperatorAttestation + GET /pending auth (2026-10-13)

> **Internal AI review (eng hygiene).** internal reviewer (/audit gate), the internal dual-model reviewer. Not a third-party audit. Public copy may only say \"AI security reviewed. Use at your own risk.\" TestNet-first. Not MainNet-hardened.

## Scope
- Repo: `<public-repo>`, branch `main`
- Range: `107bc4e..9ac1af0` (tip `9ac1af0`)
  - `3d8651a` feat(security): signed-challenge OperatorAttestation + GET /pending auth (P1-1/P1-3)
  - `9ac1af0` fix(openapi): OperatorAuth scheme duplicate keys; document attestation header
- Main files: `packages/core/src/operator-challenge.ts`, `packages/core/src/insecure-dev.ts`, `packages/core/src/operator-attestation.ts`, `packages/core/src/cors.ts`, `apps/ac2-bridge/src/index.ts`, `apps/web/src/api/ac2Bridge.ts`, `apps/web/src/hooks/useOperatorSigner.ts`, `apps/web/src/App.tsx`, `openapi/openapi.yaml`
- Reviewers: Qwen (`qwen3.8-max`, DashScope) + Claude (`claude-sonnet-4-5`), given the same code diff and full files; findings were merged, de-duplicated and each one checked by hand against the code.

## Tests (run in a scratch copy, pnpm 9.15.0)
| Command | Result |
|---|---|
| `pnpm install --frozen-lockfile` | PASS |
| `pnpm typecheck` (root) | **FAIL (tooling)**: `pnpm -r run typecheck --if-present` passes `--if-present` through to `tsc` (TS5023) in sdk/web/schema/facilitator-goplausible |
| `tsc -p tsconfig.json --noEmit` in packages/core, apps/ac2-bridge, apps/web, apps/demo-api | PASS (all 4) |
| `pnpm build` (root) | **FAIL**: `packages/middleware-express` TS2352/TS2322/TS2783. That package is not touched by this range (pre-existing) |
| `pnpm --filter @mandaterail/core build`, `pnpm --filter @mandaterail/web build` | PASS (ac2-bridge has no build script) |
| `pnpm test` (core + ac2-client) | PASS: core 52/52 (incl. operator-challenge 12, insecure-dev 17), ac2-client 4/4 |
| e2e (`e2e:paid`, `e2e:ac2-local`) | Not run: they need TestNet funds or a mnemonic; the payment path is not changed by this range |

## Verified correct
- Nonce: 192-bit random, TTL 120s by default, marked used *before* the expiry/signature checks, and replays return `replayed_nonce` (`operator-challenge.ts:92,108-119`).
- Binding: the verifier enforces action+subject (`operator-challenge.ts:235-239`); the subject comes from the route param. *(Corrected:* at `9ac1af0` the challenge was issued only for an existing pending id, which was the 200/404 oracle in P2-A. Since `6c70f99` any well-formed id gets a challenge and unknown ids fail with 404 only after operator auth.)
- Allowlist: entries are validated with `isValidAddress`, a non-allowlisted signer is denied, and the nonce is burned (`operator-challenge.ts:168-173,227-231`). Startup refuses signed-challenge with an empty allowlist (`insecure-dev.ts` `checkOperatorGate`).
- algosdk format: `algosdk.verifyBytes` uses the "MX" domain prefix, so this signature cannot be reused as a transaction signature (`operator-challenge.ts:251-256`).
- ARC-60: Ed25519 over `sha256(data)||sha256(authenticatorData)`, sig/pubkey lengths checked, SIWA `statement`/`nonce`/`account_address` bound (`operator-challenge.ts:177-193,263-285`).
- MainNet: the startup gate refuses token-lab and invalid modes, and runtime `authorizeOperator` refuses token auth on a MainNet profile (`insecure-dev.ts` `checkOperatorGate`/`authorizeOperator`).
- `/pending` is gated by `requireOperator("list")` (`index.ts:336`). The SPA does not sign automatically in the background (`App.tsx`). It holds no secret in signed-challenge mode.

## Findings / punchlist
### P0
- None.

### P1
- **P1-A ARC-60 origin binding is optional, and MainNet does not require it.** `apps/ac2-bridge/src/index.ts:151` passes `OPERATOR_SIGNDATA_DOMAIN || undefined`. When it is unset, `operator-challenge.ts:276-284` skips the `siwa.domain` and rpIdHash checks, so evidence signed through a phishing origin (which can relay a bridge challenge when the bridge is exposed for Pages) is accepted. `checkOperatorGate` does not require the domain on a MainNet profile. Fix: require `OPERATOR_SIGNDATA_DOMAIN` when the mode is signed-challenge on MainNet, or whenever the bridge binds to a non-loopback address. (Both reviewers noted this; Qwen rated it P2. Raised to P1 for the MainNet gate.)

### P2
- **P2-A Unauthenticated challenge issuance can fill the store.** `index.ts:233-254` together with `operator-challenge.ts:85-88` (max 10k entries, kept until expiry+60s) means a flood of `?action=list&id=pending` requests produces 503s for real operators. The endpoint also gives a 200/404 oracle on pending ids. Fix: rate-limit per IP and add a cap per subject. (Both reviewers; Claude rated it P0/P1, downgraded because the bridge binds to loopback by default and there is no auth bypass.)
- **P2-B `OPERATOR_CHALLENGE_TTL_MS` is not validated** (`index.ts:145`). `NaN`/`Infinity` make `new Date(...).toISOString()` throw, so every challenge returns 503 (verified; Qwen's "never expires" claim is incorrect). A huge finite value gives long-lived nonces. Fix: clamp to 10s–600s.
- **P2-C Approve and reject are not final.** `/reject/:id` (`index.ts:410-416`) overwrites any state, including approved. `/approve/:id` short-circuits only on `approved` (`index.ts:356`), so a rejected item can still be approved later with a fresh attestation. Fix: make terminal states immutable. (Qwen)
- **P2-D `useLocal:true` is not part of the attestation** (`index.ts:374`). An approve attestation can trigger signing with the local mnemonic whenever `ALGORAND_MNEMONIC` is set, even when auto-local is off. Fix: refuse `useLocal` unless auto-local/lab mode is on. (Qwen)
- **P2-E No `Cache-Control: no-store`** on `/operator/challenge` (`index.ts:250`) or `/pending` (`index.ts:336-350`). (Qwen)
- **P2-F Root `typecheck` script is broken** (`package.json`, `pnpm -r run typecheck --if-present` → TS5023), and `middleware-express` fails to build (pre-existing). The CI gate does not exercise typecheck.

### Rejected after verification
- Claude "P1 unbounded base64 decode in signature/data/authenticatorData": the evidence arrives in a header, and Node caps headers at 16 KB by default, so this is not exploitable.
- Claude "P1 chain_id 283 hardcoded = MainNet" (`apps/web/src/api/ac2Bridge.ts`): 283 is Algorand's SLIP-44/ARC-60 chain id, not tied to a network, and the bridge does not use it.
- Claude "P1 window.prompt phishable": this needs same-origin compromise. It is kept only as a residual risk.
- Qwen "auto-local /sign bypasses signed-challenge": pre-existing, and already gated to TestNet + `ALLOW_INSECURE_DEV` by `assertInsecureDevOrExit`.

## Seeded findings (claimed fixed around 107bc4e)
- **P0-1** MainNet gates for ALLOW_INSECURE_DEV + operator token (fix landed in `6c99852`, the parent of 107bc4e, and is strengthened in 3d8651a): **VERIFIED FIXED**. Insecure flags are refused outside TestNet (`insecure-dev.ts:76-141`), MainNet requires signed-challenge plus an allowlist (`checkOperatorGate`), and runtime token auth is refused on MainNet.
- **P1-2** SPA OperatorAuth header (`107bc4e`): **VERIFIED FIXED / SUPERSEDED**. In signed-challenge mode the SPA sends `X-MandateRail-Operator-Attestation` with no secret. `VITE_AC2_OPERATOR_TOKEN` is used only in token-lab mode (`apps/web/src/api/ac2Bridge.ts` `operatorAuthHeaders`). Residual: token-lab builds must never ship to Pages.
- **P1-4** demo-api binds to localhost (`107bc4e`): **VERIFIED FIXED**. The default `DEMO_API_HOST` is `127.0.0.1` (`apps/demo-api/src/index.ts:73`). A non-loopback bind only logs a warning (`:293`) and is not refused (residual).

## Verdict
- At `9ac1af0`: **PASS for TestNet / lab** (no P0), **FAIL for MainNet** (P1-A).
- At `6c70f99` (recheck): **TestNet PASS with a condition** (OA-N1: agent manual-approval polling broken in signed-challenge mode), **MainNet FAIL**.
- At `29977dd` / `4639717`: OA-N1, OA-P2-G and OA-P2-H fixed and covered by route tests.
- Round 3 (audit-store run 7, `6c70f99..4639717`): **TestNet PASS, no P0/P1.** Open: OA-P2-I, OA-P3-K, test gaps (fixed in `d77e4ee`); OA-P2-J accepted.
- At `d77e4ee`: round-3 items closed. **TestNet PASS; MainNet still blocked** on the residuals below and an independent external review. Not a third-party audit.
- Round 3 recheck (run 8, `4639717..6d0d1af`): TestNet PASS; OA-P2-I **PARTIAL**, OA-P2-M regression, OA-P2-N open. Fixed in `d502fda`.

## Residual risks
- The in-memory nonce store works for a single process only. Restarts or multiple replicas break single-use and availability.
- The manual algosdk path has no origin binding by design. Operators must check the message and its audience.
- The non-loopback bind for demo-api and ac2-bridge only warns.
- Token-lab remains available on TestNet.
- No external audit exists. **This document is an internal AI review, not a third-party audit, and must not be cited as one.**

## Remediation round 1 — `6c70f99` (on top of `9ac1af0`) — internal AI review
| Finding | Status | Change |
|---|---|---|
| P1-A | **FIXED** | `checkOperatorGate({ bindHost })` (default `AC2_BRIDGE_HOST`) refuses start in signed-challenge mode when `OPERATOR_SIGNDATA_DOMAIN` is unset/blank on a MainNet profile (MainNet `NETWORK` or `ALLOW_MAINNET=1`) **or** when the bridge binds non-loopback. When set, ARC-60 `siwa.domain` + rpIdHash are always enforced (missing/foreign domain and wrong rpIdHash rejected; tests in `operator-challenge-hardening.test.ts`). The `algosdk` (offline, "MX") path stays without origin binding by design (residual). |
| P2-A | **PARTIAL in `6c70f99`, FIXED in `29977dd`** (see OA-P2-G) | `GET /operator/challenge` is rate-limited by `FixedWindowRateLimiter` (60s window, 30/IP, 600 global; `OPERATOR_CHALLENGE_RATE_PER_IP` / `_GLOBAL`) → 429 + `Retry-After`. *(Corrected:* in `6c70f99` the limits were not clamped, so the 10k store cap held only under the default limits; a fixed window also allowed 2x at a boundary. Both fixed in `29977dd`.) No pending-id oracle: any well-formed id (`^[A-Za-z0-9-]{1,64}$`) gets a challenge; unknown ids fail with a uniform 404 only after operator auth. |
| P2-B | **FIXED** | `parseChallengeTtlMs`: integer 10000–600000 (default 120000); otherwise the startup gate refuses. |
| P2-C | **FIXED** | `/approve/:id` and `/reject/:id` return **409 `not_pending`** for any non-pending item; terminal states are immutable. (Behavior change: re-approving an approved item no longer returns the stored signature.) |
| P2-D | **FIXED** | `useLocal:true` returns 400 `use_local_disabled` unless `AC2_BRIDGE_AUTO_LOCAL` (TestNet lab, gated by `assertInsecureDevOrExit`). |
| P2-E | **FIXED** | `Cache-Control: no-store` on `/operator/challenge` (all responses) and `/pending` (incl. 401). |
| P2-F | **FIXED** | Root `typecheck` is now `pnpm -r --if-present run typecheck`; `middleware-express` builds (Express-only fields are stripped before building `MandatePaymentConfig`). **Behavior change:** the `middleware-express` 402 for a missing mandate now returns `error: "mandate_required"`. Before, the spread of `paymentRequiredBody` overwrote it with `error: "payment_required"` (TS2783). Clients that matched on `payment_required` for this case need updating. |

Tests after remediation: core 62/62 (+10), ac2-client 4/4, root `pnpm typecheck` PASS, root `pnpm build` PASS, per-package `tsc --noEmit` PASS (core, ac2-bridge, web, demo-api). No HTTP-level bridge tests exist yet (bridge routes verified by typecheck + review only). e2e not run.

Deferred / residual: in-memory nonce store + rate limiter (single process); ac2-bridge non-loopback bind still only warns (but now requires the signData domain in signed-challenge mode); independent recheck of this remediation by internal reviewer.

## Recheck of `9ac1af0..6c70f99` and remediation round 2 — `29977dd` — internal AI review
| Finding | Status | Change |
|---|---|---|
| OA-N1 (P1) ac2-client polled `GET /pending` without auth (`packages/ac2-client/src/http-bridge-signer.ts:127-150`); in signed-challenge mode it got 401 until timeout, so agent manual approval was broken | **FIXED** | `POST /sign` (queued) now returns `{ id, status, requesterToken, statusUrl }`. `requesterToken` is 256-bit, returned once, and stored only as sha256. New `GET /requests/{id}/status`: `X-MandateRail-Requester-Token` checked with `timingSafeEqual` over sha256 digests, or loopback in TestNet `token-lab`. Missing token → 401; unknown id and wrong token → the same 404. Returns only `{ id, status }`, plus `signature/publicKey/address` once approved. `Cache-Control: no-store`. `HttpAc2BridgeSigner` polls it and fails fast on rejected/401/404. The SDK adds `Ac2BridgeClient.requestStatus()` and an `operatorAttestation` option. OpenAPI is updated (new path, 202 schema, 409 on approve/reject, 429 on challenge). |
| OA-P2-G limiter hardening | **FIXED** | `RollingWindowRateLimiter`: an exact sliding log per key plus a global log, so a window boundary can't allow 2x. Memory is bounded by the global limit. Only well-formed requests are counted; unknown-id lookup is a single Map lookup at auth time. `OPERATOR_CHALLENGE_RATE_PER_IP` (default 30, 1..120) and `_GLOBAL` (default 600, 1..800, ≥ per-IP), or the gate refuses start. Cap math: live entries ≤ global × (ceil((TTL + 60s grace)/60s) + 1) = 800 × 12 = 9,600 < 10,000 at the max clamps (tested; `maxLiveChallenges`). New `AC2_BRIDGE_TRUSTED_PROXY_HOPS` (default 0 = off, max 5) takes the rate-limit key from `X-Forwarded-For`, n entries from the right. *(Corrected after run 9, OA-P1-O:* "never for loopback/auth decisions" was incomplete. Same-host proxies made every request look like loopback; since `b7a97be`, hops > 0 makes every request non-local.) **Misconfiguration risk:** setting hops > 0 when the bridge is NOT behind that many real proxies lets an attacker spoof `X-Forwarded-For` and pick any per-IP key, which defeats the per-IP limit. The global cap still holds. Leave it at 0 unless a trusted proxy appends the header. |
| OA-P2-H prefix loopback check (`insecure-dev.ts:174-177`) | **FIXED** | `isLoopbackHost` is strict: `localhost`, valid IPv4 127.0.0.0/8, `::1`, `::ffff:127.x.y.z` (brackets allowed). `127.example.com`, `127.0.0.1.nip.io` and `127.0.0.256` are rejected (tests). `isLoopbackAddress` and the bridge's bind warning use the same helper. |

Route tests (new, `apps/ac2-bridge/src/app.test.ts`, Hono `app.request` against `createBridgeApp()`): challenge no-store/400/no oracle, unknown id 404 after auth, `/pending` 401 + no-store + replay refused, approve/reject 409 (rejected can never be approved), `useLocal` 400, requester status flow (401 / 404 / cross-request token / approved payload), per-IP and global 429 + `Retry-After`, `X-Forwarded-For` ignored unless trusted hops are set, `/sign` loopback-only, and token-lab loopback status.

Tests at `29977dd`: core 68/68, ac2-client 7/7, ac2-bridge routes 9/9, sdk 4/4; root `pnpm typecheck` and `pnpm build` PASS. e2e not run.

Residual after round 2: nonce store, limiter and pending queue are in-memory (single process; a restart loses pending requests and tokens); the bridge non-loopback bind only warns; `POST /sign` has no rate limit (loopback-only in signed-challenge mode); the algosdk path has no origin binding; OpenAPI lint has pre-existing `nullable` / security-defined errors; independent external review still required.

## Round 3 (audit-store run 7, `6c70f99..4639717`) and remediation — `d77e4ee` — internal AI review
Verdict on `4639717`: **TestNet PASS, no P0/P1 remaining.**

| Finding | Status | Change |
|---|---|---|
| OA-P2-I ac2-bridge pending queue unbounded (no cap / TTL / eviction; `app.ts` ~L100, L264-320) | **PARTIAL in `d77e4ee`, FIXED in `d502fda`** (see OA-P2-M, OA-P2-N) | Current behavior (since `d502fda`): `parseBridgeQueueLimits` (the gate refuses out-of-range values). `AC2_BRIDGE_MAX_PENDING` (default 1000, 1..10000) caps queued + retained items. To make room, only items past retention or already collected by their requester can be evicted; uncollected results (including approved signatures) are never evicted early, and if no item qualifies `/sign` returns 503 `queue_full`. Per-client pending cap `AC2_BRIDGE_MAX_PENDING_PER_CLIENT` (default 50) → 429. `AC2_BRIDGE_PENDING_TTL_MS` (default 15 min, 1 min..24 h): pending items become `expired` (status endpoint reports it; approve/reject → 409; ac2-client fails fast). `AC2_BRIDGE_RETENTION_MS` (default 10 min, 1 min..24 h): approved/rejected/expired items and their requester-token hashes are deleted, after which status is 404. `POST /sign` is rate-limited after the auth gate (per-client default 10, global default 60, rolling) → 429. Why it was only partial in `d77e4ee`: the `/sign` limit ran before the auth gate with per-client = global (OA-P2-M), and a full queue could evict finished items by age even inside retention, including uncollected approved signatures (OA-P2-N). Tests: cap/503, uncollected result survives a full queue, TTL expiry, retention eviction, per-client cap, /sign 429, gate clamps. |
| OA-P2-J global challenge quota exhaustion | **ACCEPTED (residual)** | With per-IP 30 and the global cap (max 800), about 27 distinct source IPs can exhaust the global challenge quota for the rolling minute. Real operators then get 429 on `/operator/challenge` until the window rolls. This is availability only, not an auth bypass. Mitigations: keep the bridge loopback / behind an authenticated tunnel, keep the global cap, and front with edge rate limiting if exposed. |
| OA-P3-K demo-api own loopback check (`apps/demo-api/src/index.ts:293`) | **FIXED** | Uses the shared strict `isLoopbackHost`. |
| Test gaps | **FIXED** | Route tests: a forged signature and a valid signature from a non-allowlisted signer both get 401 on approve, reject and `/pending`. *(Corrected:* in `d77e4ee` only the non-allowlisted test checked that the item stays pending; since `d502fda` both do.) MainNet startup refusal via `checkOperatorGate` for a missing `OPERATOR_SIGNDATA_DOMAIN` and for token-lab. |

Tests at `d77e4ee`: core 68/68, ac2-client 7/7, ac2-bridge routes 18/18 (was 9), sdk 4/4; root `pnpm typecheck` and `pnpm build` PASS. e2e not run.

Residual after round 3: in-memory nonce store, limiters and queue (single process; restart loses pending requests and tokens); OA-P2-J (above); trusted-proxy hops misconfiguration (above); bridge non-loopback bind only warns; algosdk path has no origin binding; pre-existing OpenAPI lint errors; independent external review still required before MainNet.

## Round 3 recheck (run 8, `4639717..6d0d1af`) and remediation — `d502fda` — internal AI review
Verdict on `6d0d1af`: **TestNet PASS**; OA-P2-I PARTIAL.

| Finding | Status | Change |
|---|---|---|
| OA-P2-M (regression) `/sign` rate limit ran before the loopback/auth gate (`app.ts:318-321` vs `336-351`), and the per-client limit equaled the global one (`174-179`), so unauthenticated remote callers could drain the quota for local agents | **FIXED** | The limiter is now applied after the gate (and in the TestNet auto-local lab path). New `AC2_BRIDGE_SIGN_RATE_PER_CLIENT` (default 10, 1..600) and `AC2_BRIDGE_SIGN_RATE_PER_MIN` (global, default 60, 1..600); per-client ≤ global or the gate refuses start. Test: 20 unauthenticated non-loopback calls get 401 and a loopback agent keeps its full quota. |
| OA-P2-N `reserveSlot` (`132-142`) evicted finished items by age even inside retention, including **approved signatures nobody had collected** | **FIXED** | Items get a `collected` flag the first time `GET /requests/{id}/status` returns their final state (signature for approved). Room is made only by evicting items past retention (sweep) or already collected; otherwise `/sign` returns 503 `queue_full` and uncollected results are kept. New per-client pending cap `AC2_BRIDGE_MAX_PENDING_PER_CLIENT` (default 50, 1..10000, ≤ `AC2_BRIDGE_MAX_PENDING`) → 429 `client_pending_cap`. Tests: an uncollected approved item survives a full queue (503), is evicted only after collection; per-client cap; gate clamps. |

Tests at `d502fda`: core 68/68, ac2-client 7/7, ac2-bridge routes 21/21 (was 18), sdk 4/4; root `pnpm typecheck` and `pnpm build` PASS. e2e not run.

Residual after run 8: the per-client key is the socket address (or trusted-proxy XFF), so in signed-challenge mode all co-located loopback agents share one key and one per-client quota; with every slot held by uncollected results the queue answers 503 until retention expires (availability, by design); plus the earlier residuals (in-memory state, OA-P2-J, proxy-hops misconfiguration, bridge non-loopback bind warns only, algosdk path without origin binding, pre-existing OpenAPI lint errors, external review required before MainNet).

## Round 4 (run 9, `6d0d1af..4b18054`) and remediation — `b7a97be` — internal AI review
Verdict on `4b18054`: OA-P2-M, OA-P2-N and OA-P2-I **verified fixed**. **Loopback-only deployment: TestNet PASS. Tunneled / reverse-proxied deployment: FAIL** until OA-P1-O is fixed (fixed in `b7a97be`).

| Finding | Status | Change |
|---|---|---|
| OA-P1-O (P1; Claude rates the tokenless-lab case P0) A tunnel or reverse proxy on the same host (e.g. `cloudflared`) makes all internet traffic arrive from 127.0.0.1, so every localhost-trust check trusted everyone. Affected: `POST /sign` in signed-challenge mode (`app.ts:354-360`), tokenless token-lab (`insecure-dev.ts:399-408`), token-lab requester status (`app.ts:420-425`), the domain not being required on a loopback bind (`insecure-dev.ts:314-319`), and the misleading README note on hops | **FIXED** | A single helper, `isTrustedLocalRequest`, now makes every localhost-trust decision. A request is local only if the peer is loopback, `AC2_BRIDGE_TRUSTED_PROXY_HOPS=0`, and none of `X-Forwarded-For`, `Forwarded`, `CF-Connecting-IP`, `X-Real-IP` or `True-Client-IP` is present. `authorizeOperator` takes `isLocal` (default: no hops + bare loopback). Startup with hops > 0 requires `OPERATOR_SIGNDATA_DOMAIN` (in any mode) and refuses tokenless token-lab (`AC2_OPERATOR_TOKEN` required). README rewritten: **tokenless token-lab must never be tunneled or proxied**, and proxies that add no forwarding header (raw TCP, `ssh -R`) cannot be detected. Tests: each forwarding header on loopback is denied for `/sign` (signed-challenge and lab), operator routes and token-less requester status (lab); hops > 0 denies `/sign` with no headers; token-lab with a token still works through a proxy; startup refusals with hops > 0; core helper tests. |
| OA-P3-P per-client key treated each 127.x address separately | **FIXED** | `normalizeClientKey`: every 127.0.0.0/8, `::1` and `::ffff:127.x` peer maps to one `loopback` key (also applied to the trusted-proxy XFF key). The run-8 cap test that relied on 127.0.0.3 having its own quota now expects `client_pending_cap`; a new test checks that 127.0.0.1, 127.0.0.3, `::1` and `::ffff:127.9.9.9` share one quota. |

Tests at `b7a97be`: core 71/71, ac2-client 7/7, ac2-bridge routes 27/27 (was 21), sdk 4/4; root `pnpm typecheck` and `pnpm build` PASS. e2e not run.

Residual after run 9: all co-located loopback agents share one per-client `/sign` quota and pending cap (by design, OA-P3-P); proxies/tunnels that add no forwarding header are undetectable, so never expose a localhost-trusting bridge through them; with hops > 0, signed-challenge `POST /sign` is refused (agents need a separate loopback-only bridge); plus the earlier residuals (in-memory state, OA-P2-J, bridge non-loopback bind warns only, algosdk path without origin binding, pre-existing OpenAPI lint errors, independent external review required before MainNet).

## Run 10 (`4b18054..bd6b8f7`) and remediation — `4d8cee8` — internal AI review
Verdict on `bd6b8f7`: **TestNet PASS, no P0/P1.** OA-P2-Q and OA-P2-R open; both fixed in `4d8cee8`. The OA-P2-I row above was rewritten to describe current behavior (flagged in runs 8, 9 and 10).

| Finding | Status | Change |
|---|---|---|
| OA-P2-Q The forwarding-header list (`insecure-dev.ts:385-391`) missed common proxy headers, and `OPERATOR_SIGNDATA_DOMAIN` was optional for loopback signed-challenge (`insecure-dev.ts:336`) | **FIXED** | `PROXY_FORWARDING_HEADERS` now also includes `X-Forwarded-Host`, `X-Forwarded-Proto`, `Via`, `X-Client-IP` and `Fastly-Client-IP`. `checkOperatorGate` requires `OPERATOR_SIGNDATA_DOMAIN` for **every** signed-challenge deployment, whatever the network, bind or hops. Tests and `.env.example` updated (the domain is now documented as required; route tests set it). |
| OA-P2-R Auto-local `POST /sign` (`app.ts:351-361`) signed for any caller with no localhost-trust check, and was allowed with hops > 0 | **FIXED** | Startup refuses `AC2_BRIDGE_AUTO_LOCAL` when `AC2_BRIDGE_TRUSTED_PROXY_HOPS > 0`. Auto-local `POST /sign` calls `isTrustedLocalRequest` first and returns **403** for non-loopback peers, any forwarding header, or hops > 0. Tests: direct loopback 200; 403 for each of the 10 forwarding headers and for a non-loopback peer; 403 with hops > 0; gate refusal. |

Tests at `4d8cee8`: core 72/72, ac2-client 7/7, ac2-bridge routes 29/29, sdk 4/4; root `pnpm typecheck` and `pnpm build` PASS. e2e not run.

Residual after run 10: unchanged from run 9 (shared loopback quota, undetectable header-less proxies, in-memory state, OA-P2-J, non-loopback bind warns only, algosdk path without origin binding, pre-existing OpenAPI lint errors, independent external review required before MainNet).

## Run 11 (`bd6b8f7..e3289a9`) — final verdict — internal AI review
**Phase 1 OperatorAttestation is CLEAR for TestNet hosting** under the conditions below. **MainNet is NOT cleared** (independent external review and the residuals above still apply). This is an internal eng-hygiene review, not an audit.

Hosting conditions for TestNet (all required):
1. `OPERATOR_ATTESTATION_MODE=signed-challenge` with a non-empty `OPERATOR_ALLOWLIST` and `OPERATOR_SIGNDATA_DOMAIN` set.
2. `AC2_BRIDGE_TRUSTED_PROXY_HOPS` equal to the exact number of trusted proxies in front of the bridge.
3. No `AC2_BRIDGE_AUTO_LOCAL` and no tokenless token-lab behind any proxy or tunnel.
4. No header-less tunnels (`ssh -R`, socat, raw TCP forwarding) to the bridge.
5. Co-located agents use a separate loopback-only bridge (signed-challenge `POST /sign` is refused when hops > 0).
6. Public wording stays "TestNet" and (policy updated 2026-10-15) "AI security reviewed. Use at your own risk."; never imply a third-party audit firm; no MainNet-ready claims.

| Finding | Status | Change |
|---|---|---|
| OA-P3-S Docs: the header-less tunnel warning did not name `AC2_BRIDGE_AUTO_LOCAL`; `.env.example` had no local `OPERATOR_SIGNDATA_DOMAIN` example | **FIXED (docs only)** | Bridge README warning now covers `AC2_BRIDGE_AUTO_LOCAL` (header-less tunnels would let anyone get signatures from the bridge mnemonic). `.env.example` shows `OPERATOR_SIGNDATA_DOMAIN=localhost:5173` for the local console next to `mandaterail.pages.dev`. |

