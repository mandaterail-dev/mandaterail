# Phase 2: MainNet dry-run plan

> **Status: APPROVED by the owner on 2026-10-15** with the proposed limits:
> - `SPEND_CAP_PER_PAYMENT_USDC` = 0.01 (0.01 USDC per payment; lowered from 1.00 on 2026-10-19, R33)
> - `SPEND_CAP_PER_DAY_USDC` = 0.05 (0.05 USDC per day; lowered from 5.00 on 2026-10-19, R33)
> - at most 1 USDC at risk in the dry-run
>
> MainNet is still **NOT cleared**; it opens only after the internal reviewer gate (section I). Written 2026-10-13 against Chaos `main` `1a8e940`; approval recorded 2026-10-15. T1–T4 are implemented (see "Progress").
>
> **Security gate (the owner's decision, 2026-10-13):** internal reviewer, the internal dual-model reviewer, is the security gate for MainNet. There's no external audit firm. Public wording (the owner, 2026-10-15): public copy may say "AI security reviewed. Use at your own risk." It must never imply a third-party audit firm, formal verification or MainNet readiness. Internal reports stay labeled "eng hygiene / AI review".

## Goal

Run the full MandateRail flow on Algorand MainNet with **small, capped amounts**: agent sign request, human/operator AC2 approval, x402 payment through the facilitator, receipt. Run it from the existing ECS box with no localhost trust, no mnemonics on the server, persistent state, monitoring and a tested rollback. Then pass the internal reviewer gate.

**Non-goals:**
- open public MainNet traffic
- multi-region or HA
- device/HSM operator bindings (stay 501)
- a hosted multi-tenant merchant API

## Current state (what blocks MainNet today)

| Area | Today (TestNet, live on `8-221-97-26.sslip.io`) | MainNet blocker |
| --- | --- | --- |
| State | Challenge store, rate limiters and bridge queue are in-memory; console mandates are a single-process JSON file | Restart loses nonces/queue; replay protection is per process; can't run two processes |
| Agent signing | Co-located agents use a separate loopback-only bridge; signed-challenge `POST /sign` is refused when hops > 0 | Relies on localhost trust; remote agents can't sign |
| Gates | MainNet refuses token-lab / insecure-dev; signed-challenge requires allowlist + domain | No MainNet-specific startup checks for asset id, facilitator, spend caps or persistence |
| Keys | `ALGORAND_MNEMONIC` used by scripts / `LocalEd25519Signer` (TestNet) | No mnemonic may exist on the server |
| Asset | USDC TestNet ASA `10458941` | MainNet USDC ASA `31566704` (6 decimals; Circle docs) |
| Ops | Caddy logs only | No alerts, no rollback runbook |

## Workstreams

### A. Persistent shared state

What has to persist:
- **Challenge nonces:** issued, used and expired, so a nonce stays single-use across restarts and processes.
- **Rate-limit windows:** challenge, `/sign`, and console per-IP and global.
- **Bridge queue:** pending, approved/rejected/expired, requester-token hashes, retention.
- **Console mandates** plus the server-side `signatureVerified` flag.
- **Receipts.**

**Design:**
- Add storage interfaces to core: `ChallengeStore`, `RateLimitStore`, `QueueStore`, `MandateStore`, `ReceiptStore`. Keep the in-memory implementations for tests.
- **Consume a nonce atomically:**
  - Redis `SET key used NX PX` + `GETDEL`, or
  - Postgres `UPDATE ... WHERE used=false RETURNING`.
- **Rate limits:** Redis `INCR` + `PEXPIRE` sliding buckets, or a Postgres counter table.
- **Mandates and receipts:** Postgres rows; the mandate stays canonical JSON, with `server_verified` in a separate column. Use `SERIALIZABLE` or `SELECT ... FOR UPDATE` for create/revoke, and keep the store cap as a constraint check in the same transaction.

**Priced options** (budget: under $15/month incremental):

| Option | What | Est. cost/month | Notes |
| --- | --- | --- | --- |
| **1 (recommended)** | Postgres 16 + Redis 7 in Docker on the existing ECS box, loopback-only, with nightly `pg_dump` and Redis AOF | **$0 incremental**, plus ~$1–3 for extra disk/snapshots (check the ECS disk price) | Cheapest; same blast radius as the box; needs backups (A-4) and memory headroom (check `free -m`; ~300 MB total) |
| 2 | Postgres only on the box (nonces, limits, queue, mandates all in PG) | $0 incremental | One dependency. Rate limiting via PG adds a write per request, which is fine at dry-run volume |
| 3 | Upstash Redis (PAYG $0.20 / 100K commands, 1 GB free storage; Fixed 250 MB $10) + Postgres on the box | ~$0–10 | Managed Redis, but cross-cloud latency from ECS. Upstash is on AWS/GCP/Fly |
| 4 | Managed Postgres in the same cloud as the ECS | Usually above $15 for the smallest HA tier; verify the current price | Out of budget unless a small single-node tier exists |

Upstash prices are from upstash.com/pricing (checked 2026-10-13). Check every price again before buying anything.

**Recommendation:** Option 1. Dry-run volume is tiny, so Option 2 is the fallback if box memory is tight.

### B. Deployment without localhost trust

- **Remote agent signing via requester keys.** Each agent gets an Ed25519 **requester key**. The public key goes on `AGENT_REQUESTER_ALLOWLIST`; the agent never holds payer or operator keys.
  - `POST /sign` requires a requester signature over `(method, path, sha256(body), timestamp, nonce)` in `X-MandateRail-Requester-Signature`. That's the same challenge-free pattern as HttpSignature, with a ±60 s skew window and the nonce stored in A.
  - The per-request requester token for `GET /requests/{id}/status` stays.
  - Quotas are keyed per requester key, not per IP.
- **Remove loopback-only paths on MainNet:**
  - no `AC2_BRIDGE_AUTO_LOCAL`, no `useLocal`
  - no "co-located loopback bridge"
  - `isTrustedLocalRequest` grants nothing on MainNet; the startup gate refuses local-only mode
- **Caddy stays the only ingress.** `AC2_BRIDGE_TRUSTED_PROXY_HOPS=1`; services bind 127.0.0.1; the firewall allows only 80/443 and SSH from the admin IP.

### C. MainNet env and startup gates

All services refuse to start on MainNet (`NETWORK=algorand:wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=` or `ALLOW_MAINNET=1`) unless every one of these holds:
- `OPERATOR_ATTESTATION_MODE=signed-challenge`, a non-empty `OPERATOR_ALLOWLIST`, and `OPERATOR_SIGNDATA_DOMAIN` set. This is already enforced.
- `USDC_ASA_ID=31566704`. Refuse `10458941`, and refuse any other id unless `ALLOW_NONSTANDARD_ASSET=1`, which is itself refused on MainNet.
- `MANDATERAIL_STATE_URL` (Postgres/Redis) is set and reachable, and in-memory stores are refused.
- **Spend caps:**
  - `MAINNET_MAX_PAYMENT_USDC`: default and hard max **1.00** (approved 2026-10-15)
  - `MAINNET_DAILY_CAP_USDC`: default and hard max **5.00** (approved 2026-10-15), enforced in middleware against persisted receipts
  - Lower values are always allowed. Raising either hard max needs the owner's written approval and an internal reviewer review.
  - `IntentMandate.maxAmount` above the per-payment cap is rejected at create
- No `ALGORAND_MNEMONIC`, `AC2_OPERATOR_TOKEN`, `ALLOW_INSECURE_DEV`, `AC2_BRIDGE_AUTO_LOCAL` or `DEV_ALLOW_UNSIGNED` in the environment.
- `CORS_ORIGINS` is exact origins only.
- `GOPLAUSIBLE_BASE_URL` is https, `FEE_PAYER` matches the facilitator's `GET /supported` for MainNet, and `MERCHANT_ADDRESS` is opted into ASA `31566704` (checked against algod at startup).
- `/health` reports `network`, `asset`, `stateBackend` and `gate: "mainnet-dry-run"`, and never reports secrets or paths.

### D. Key custody

| Key | Holder | Rule |
| --- | --- | --- |
| Operator wallet(s) | the owner (hardware-backed wallet, e.g. Ledger via Pera/Defly, or Lute with a Ledger) | Signs operator challenges with ARC-60 from `mandaterail.pages.dev`. Allowlist ≤ 2 addresses. Never on the server |
| Payer / principal wallet | Human principal's own wallet | Signs IntentMandates + AC2 approvals on device. For the dry-run, funded with **≤ 1 USDC** (the approved maximum at risk) plus a few ALGO for fees. Never on the server |
| Merchant wallet | Receive-only address; key offline (hardware wallet) | Server holds only `MERCHANT_ADDRESS`. Sweep to cold storage after the dry-run |
| Agent requester keys | Agent runtime (env or KMS of the agent host) | Can only request signatures; can't move funds; revocable via allowlist |
| Facilitator fee payer | GoPlausible | Not ours |
| Server | none | No mnemonics on the server. Secrets limited to DB credentials (file mode 0600, root-owned, not in git). `scripts/create-wallet.ts` and `ALGORAND_MNEMONIC` stay TestNet/dev only |

### E. USDC MainNet assets

- USDC MainNet ASA **`31566704`**, 6 decimals; TestNet ASA `10458941` (Circle).
- Select both from `NETWORK`: a `networkProfile()` helper returns `{caip2, usdcAsaId, explorerBase}`. Never allow a mix, such as the MainNet network with the TestNet ASA.
- Check `explorerUrl` in receipts (MainNet explorer vs TestNet), and `/paid/resource` `accepts[]` asset and network.

### F. Monitoring and alerts

- **Uptime:** an external check of `/health` on the 3 hosts every 1 min, e.g. UptimeRobot / Better Stack free tier ($0). Alert after 2 failures, to the owner's email/Telegram.
- **Structured logs:** JSON logs with request id. Counters:
  - 401 by `error` code
  - 429s
  - `replayed_nonce`
  - `invalid_signature`
  - `store_full`
  - queue depth
  - payments and USDC per day
- **Alerts:**
  - any MainNet payment over the cap (should be impossible)
  - daily spend > 80% of `MAINNET_DAILY_CAP_USDC`
  - more than 20 `operator_not_allowlisted` or more than 20 `invalid_signature` in 10 min
  - any 5xx burst
  - Postgres/Redis down
  - disk > 80%
  - certificate expiry < 14 d
- **On-chain watcher:** a cron (every 5 min) compares the merchant address's MainNet USDC inflows from indexer against `receipts`. Alert on any mismatch.
- **Cost:** $0 on free tiers; the log volume fits the box.

### G. Rollback

- Every deploy is a git SHA from Chaos `main` with a matching bundle. Keep the last 3 releases as directories; `current` is a symlink; switch the symlink and restart (systemd) in under 1 min.
- **Kill switch:** `MANDATERAIL_PAUSE=1` makes demo-api return 503 on paid routes and the bridge refuse `/sign`. Reads and `/health` stay up. Flip it with one command.
- **DB:**
  - migrations are forward-only and backward-compatible for one release (expand/contract)
  - `pg_dump` before every deploy
  - Redis can be dropped safely; only nonces and limits live there, and all outstanding challenges expire within 120 s
- **Funds:** if anything looks wrong, pause, then revoke the operator allowlist (restart with the allowlist emptied, which refuses to start, so the service stays down), then sweep the merchant wallet.
- Rehearse rollback once on TestNet before the MainNet dry-run.

### H. Dry-run script

`scripts/mainnet-dry-run.ts` makes no server-side keys. It runs from the owner's laptop with a hardware-wallet flow where human signing is needed.

1. **Preflight:**
   - `/health` on all 3 hosts says `network` = MainNet, `asset` = `31566704`, `gate` = `mainnet-dry-run`
   - caps are set
   - the merchant is opted in
   - the payer has ≤ 1 USDC
2. **Negative checks:**
   - unauthenticated / forged / non-allowlisted calls get 401
   - a TestNet-ASA payment is refused
   - an over-cap mandate is refused
   - a bridge nonce at the console gets 401
3. Create a **signed IntentMandate** (principal = payer address, `maxAmount` 0.10 USDC, 1 h expiry, merchant allowlisted) through `POST /mandates`; authorize-check returns 200.
4. The agent requests `/paid/resource` (price 0.01 USDC), gets 402, then the AC2 sign request comes from a remote agent with a requester key.
5. the owner approves on device (operator challenge via Pages, ARC-60). The payment settles via the facilitator.
6. Check:
   - the receipt
   - the indexer shows exactly 0.01 USDC to the merchant
   - the watcher reports no mismatch
7. Repeat steps 4–6 three times, then **revoke** the mandate. The next payment must be refused.
8. **Daily cap check without spending more:** restart with a temporary `MAINNET_DAILY_CAP_USDC=0.05`, then make tiny payments until the next one would cross the cap; it must be refused. Then restore 5.00.
9. Pause switch check. Restart all services mid-flow; confirm the nonces, queue and mandates survived and that a used nonce is still rejected.
10. Write a report (amounts, tx ids, timings) to `docs/ops/runs/<date>-mainnet-dry-run.md`.

Total at risk: **≤ 1 USDC** (approved maximum; the payer wallet holds no more), plus ALGO fees (< 0.1 ALGO). Planned spend is about 0.05–0.10 USDC.

### I. internal reviewer gate criteria (internal security gate for MainNet)

internal reviewer (internal dual-model reviewer) must record, in `docs/security/audits/<date>-mainnet-gate.md`:

1. Review of every commit since `1a8e940`, covering A–H. There must be **zero open P0/P1**. P2s are fixed, or accepted in writing by the owner with a compensating control.
2. Route tests for every new gate:
   - startup refusals (C)
   - requester-key auth: missing, forged, replayed, skewed and revoked keys
   - persistent nonce replay across restart / two processes
   - store cap and concurrency on Postgres
   - spend caps
3. `pnpm test`, `pnpm typecheck` and `pnpm build` are green, and the TestNet live E2E passes on the release SHA.
4. A rollback rehearsal and a restart-persistence test were done on TestNet, with notes.
5. Key custody checklist (D) signed off by the owner: no mnemonic on the server (verified by `env`/file scan), and the operator allowlist is hardware-backed.
6. Monitoring (F) is live and a test alert was received.
7. The MainNet dry-run (H) completed, and its report was reviewed by internal reviewer with no new P0/P1.
8. Public wording check: Pages, README, wiki and SDK use only "AI security reviewed. Use at your own risk.". There's no implied third-party audit, no "verified" and no "MainNet-ready".

Only after 1–8 may MainNet be opened beyond the dry-run, and still with caps. The verdict format matches the TestNet reports: "eng hygiene / AI review".

## Tickets (in order)

Estimates are engineering days (d) for one engineer plus agents. They include tests and docs.

| # | Ticket | Depends on | Est. |
|---|---|---|---|
| P2-T1 | Storage interfaces in core (`ChallengeStore`, `RateLimitStore`, `QueueStore`, `MandateStore`, `ReceiptStore`) + in-memory impls; refactor bridge/console/demo-api onto them (no behaviour change) | — | 2 d |
| P2-T2 | Provision Postgres 16 (+ Redis 7 if Option 1) on the ECS box in Docker, loopback-only, with credentials file, nightly `pg_dump`, AOF; memory check | — | 0.5 d |
| P2-T3 | Postgres/Redis implementations: atomic nonce consume, sliding-window limiters, queue with retention, mandates with `server_verified` + transactional cap, receipts; migrations | T1, T2 | 3 d |
| P2-T4 | Restart/multi-process tests: nonce replay across two processes, queue survives restart, concurrent create/revoke on PG | T3 | 1 d |
| P2-T5 | `networkProfile()` (CAIP-2 → USDC ASA `31566704` / `10458941`, explorer); refuse mixed network/asset | — | 0.5 d |
| P2-T6 | MainNet startup gate (C): asset, state backend, caps, forbidden env vars, merchant opt-in + fee payer check, `/health` gate field | T3, T5 | 1.5 d |
| P2-T7 | Spend caps in middleware (per-payment + daily from receipts) + mandate `maxAmount` cap at create | T3, T5 | 1 d |
| P2-T8 | Requester-key auth for `POST /sign` (signed request, skew, nonce in store, per-key quotas, allowlist), SDK + ac2-client support | T3 | 2.5 d |
| P2-T9 | Remove localhost trust on MainNet: refuse local-only / auto-local / `useLocal`; `isTrustedLocalRequest` no-op on MainNet; tests | T6, T8 | 1 d |
| P2-T10 | Kill switch `MANDATERAIL_PAUSE`, release layout + symlink rollback script, pre-deploy `pg_dump` hook | T3 | 1 d |
| P2-T11 | Monitoring: JSON logs + counters, external uptime checks, alert rules, on-chain receipt watcher cron | T3, T5 | 1.5 d |
| P2-T12 | Key custody: hardware-backed operator allowlist, merchant receive-only cold address opted into `31566704`, server env/file scan for mnemonics | T6 | 0.5 d (+ the owner's time) |
| P2-T13 | TestNet rehearsal: deploy T1–T12 to the live TestNet hosts, run the TestNet E2E, rollback drill, restart-persistence drill | T1–T12 | 1 d |
| P2-T14 | `scripts/mainnet-dry-run.ts` (preflight, negatives, signed mandate, 3 × 0.01 USDC, revoke, cap, pause, restart, report) — rehearsed on TestNet first | T13 | 1.5 d |
| P2-T15 | internal reviewer gate review (I.1–I.6) and fixes | T13, T14 | 1–3 d |
| P2-T16 | MainNet dry-run (≤ 1 USDC at risk) + report + internal reviewer sign-off (I.7–I.8) | T15 | 0.5 d |

**Total:** about 20–23 engineer-days. The critical path is T1, then T3, then T8, then T9, then T13, then T14, then T15, then T16.

**Incremental cost:** about $0–3/month with Option 1 (self-hosted on the existing ECS), and free-tier monitoring. Recheck prices before buying.

## Progress

**T1–T4 done (2026-10-15).** T2 (provisioning on ECS) is **not** done; it waits for the internal reviewer review. The new backends are **not wired** into any app entrypoint yet; that happens in T6, behind an env gate.

- **T1 interfaces** (`packages/core/src/storage.ts`): `ChallengeStore`, `RateLimitStore`, `QueueStore`, `MandateStore`, `ReceiptStore`, all typed `MaybePromise`. Callers always `await`.
  - The in-memory and file implementations keep the Phase-1 behavior: `OperatorChallengeStore`, `RollingWindowRateLimiter`, `InMemoryQueueStore`, `FileMandateStore` and `FileReceiptStore`.
  - Bridge and console accept `opts.stores`.
- **T3 backends** (`packages/storage`):
  - Postgres (`pg`):
    - A nonce is single-use through an atomic `UPDATE … WHERE used=false RETURNING`.
    - Limiter and queue caps, and the mandate cap, are checked inside a transaction holding `pg_advisory_xact_lock`.
    - Queue finalize is a compare-and-set from `pending`, with TTL expiry, retention sweep, and global and per-client caps.
    - The mandates table carries a `server_verified` column that is set only by the server-side signature check.
  - Redis (`ioredis`): Lua scripts make nonce consume and the sliding-window limiter atomic.
  - Recommended layout: Redis for nonces and limiters; Postgres for the queue, mandates and receipts. Postgres alone also works.
- **T4 tests**:
  - One conformance suite runs on memory, Postgres and Redis.
  - Restart tests: state survives a new process.
  - Multi-process races: exactly one nonce consume wins, limiter admits are exact, the mandate cap holds, and exactly one finalize wins.
  - App-level: two bridge instances and two console instances share state; a nonce issued by one instance and replayed on the other is rejected.
  - Run with `pnpm test:storage`. It starts a throwaway local Postgres and redis-server on loopback.
  - `pnpm test` runs the unit tests only; the integration tests skip when the services aren't available.
- **Caveats**:
  - The caller passes `now` in, so hosts must be NTP-synced.
  - The advisory lock serializes each limiter and each cap check. That is fine at dry-run volume.

**T5, T7 and T8 done (2026-10-15).** Not deployed. Loopback queueing on TestNet is unchanged; T9 removes it.

- **T5 `networkProfile()`** (`packages/core/src/network.ts`)
  - TestNet: `NETWORK` unset, `testnet`, or the TestNet CAIP-2 id → USDC ASA 10458941, as before. `USDC_ASA_ID` can override it for lab tokens, but never with the MainNet ASA.
  - MainNet: `mainnet` or the MainNet CAIP-2 id → USDC ASA **31566704** and the mainnet explorer. Any other `USDC_ASA_ID` is refused.
  - Startup throws on an unknown `NETWORK`, or on `ALLOW_MAINNET` set while `NETWORK` isn't MainNet.
  - Used by the payment-requirements builder, demo-api, and the receipt explorer links.
  - MainNet also needs an explicit `FEE_PAYER`; there is no TestNet default on MainNet.
- **T7 spend caps** (`packages/core/src/spend-caps.ts`, checked in `evaluateMandate` after the AC2 signature check)
  - Per payment ≤ `SPEND_CAP_PER_PAYMENT_USDC`; per payer (the mandate principal) per UTC day ≤ `SPEND_CAP_PER_DAY_USDC`.
  - Defaults are also the hard maxima: 1.00 and 5.00 USDC. Env can only lower them; values above the maximum, zero, or malformed values refuse to start.
  - A lowered daily cap also bounds each single payment. That makes the 0.05 dry-run check work.
  - Amounts are compared in exact micro-units.
  - The daily cap uses the receipts store through `ReceiptSpendLedger`: Postgres sums in SQL; file and in-memory stores scan, and deny if the scan was truncated.
  - Within one process, the check and the reservation are atomic per payer. The reservation is held until the receipt is written.
  - On MainNet the middleware refuses to start without a ledger. If the ledger is unavailable, payments are denied.
- **T8 requester-key auth for `POST /sign`** (`packages/core/src/requester-auth.ts`, used by ac2-bridge)
  - `REQUESTER_ALLOWLIST` lists the allowed Algorand addresses (Ed25519 keys).
  - `GET /requester/challenge?address=` returns a single-use nonce from the shared challenge store, bound to action `request.sign` and to that address.
  - The requester runs `algosdk.signBytes` over the canonical request (audience, method, path, address, nonce, ISO timestamp, sha256 of the exact body) and sends it in `X-MandateRail-Requester-Auth`.
  - The bridge rejects:
    - keys not on the allowlist (and burns their nonce);
    - replayed or expired nonces;
    - a nonce issued for a different address, action or audience;
    - timestamps more than ±60 s off;
    - a body that was changed after signing.
  - Requester and operator nonces can't be swapped for each other.
  - On MainNet, `/sign` requires this header; loopback alone is refused.
- **Residuals**
  - The daily cap is only race-free within one process. Two demo-api processes could each pass the check before either writes a receipt. Before scaling past one instance, add a Postgres reservation that takes an advisory lock per payer (planned with T6).
  - The SDK and ac2-client don't yet sign requester requests. `signRequesterRequest` in core is the helper to use.

**internal reviewer run 17 fixes and T6 (2026-10-15).** Not deployed and not provisioned.

- **T7-P2-2 – spend reservations**
  - `evaluateMandate` writes a `pending` spend reservation (`SpendStore`) before settle. The middleware then finalizes it:
    - no payload, or verify fails or throws → `released`;
    - settle returns not-ok, throws, or takes longer than `spend.settleTimeoutMs` (30 s) → `ambiguous`;
    - settle succeeds → `settled` with the txId, before the route handler runs.
  - `pending`, `settled` and `ambiguous` all count toward the daily cap. A handler or receipt write that fails after settle can't un-count the payment.
  - `reconcileSpend(store, check)` resolves `ambiguous` and stale `pending` reservations. `indexerTxCheck(indexerUrl)` marks confirmed transactions as `settled`; everything else stays counted until an operator decides.
- **T7-P2-1 – Postgres cap across processes:** `PgSpendStore.reserve` checks the cap and inserts the reservation in one transaction, holding a per-payer `pg_advisory_xact_lock`. Test: 4 processes each fire 10 parallel 1-USDC reserves against a 5 USDC cap, and exactly 5 succeed.
- **T5-P3 – algod check:** at startup, demo-api checks that algod's `/versions` genesis hash matches the profile and that `/v2/assets/<USDC>` reports 6 decimals; otherwise it refuses to start.
  - The check always runs on MainNet. On TestNet it runs only with `ALGOD_CHECK=1`.
  - `ALGOD_URL` / `ALGOD_TOKEN` are optional; the default is algonode. Errors never echo the URL or token.
- **T8-P3-1 – requester auth:** the signature hash covers the raw body bytes; invalid UTF-8 is rejected with 400. A non-allowlisted key and a bad signature both get the same `requester_auth_failed` error.
- **ST-P3-4 – migrations:** migrations are versioned (`MIGRATIONS` in `packages/storage/src/pg.ts`; v1 core tables, v2 `mr_spend`).
  - They run under an advisory lock and are recorded in `mr_schema`.
  - A database newer than the build is refused.
  - **Apps never migrate**: service roles can't create tables, so apps only check the schema version and refuse to start if it's behind or ahead.
  - Migrate separately: `pnpm --filter @mandaterail/storage migrate`. It uses `MIGRATE_DATABASE_URL` (falling back to `DATABASE_URL`) from `STATE_ENV_FILE`, which defaults to `/etc/mandaterail/state-migrate.env`.
- **ST-P3-5 – JSON import:** `pnpm --filter @mandaterail/storage import-json -- --console <mandates.json> --receipts <receipts.json>` is idempotent and keeps file order.
  - A mandate is imported as server-verified only if the file says so **and** its AC2 signature re-verifies.
  - Each imported receipt also becomes a `settled` spend row, so today's spend keeps counting.
  - A restart test bounces the throwaway Postgres and Redis (Redis runs with AOF): nonces stay single-use, limiter counts persist, mandates and spend survive, and the existing clients reconnect.
- **T6 – `STATE_BACKEND`** (`memory` | `postgres` | `redis+postgres`)
  - `memory` is the default on TestNet. MainNet refuses `memory`.
  - Each service reads `/etc/mandaterail/state-{bridge,console,demo-api}.env`, or `STATE_ENV_FILE`. Only these keys are taken: `STATE_BACKEND`, `DATABASE_URL`, `REDIS_URL`, `DATABASE_URL_FILE`, `REDIS_URL_FILE`, `PG_POOL_MAX` (plus `MIGRATE_DATABASE_URL` for migrate). Variables already set in the environment win.
  - With `redis+postgres`: nonces and limiters live in Redis; the queue, mandates, receipts and spend in Postgres.
  - Redis connects with `enableReadyCheck: false`, because service users can't run INFO; it uses PING only.
  - Connection URLs, users, passwords and hosts are redacted from every error and log line.
  - On the memory backend, demo-api seeds today's spend from the receipts file at startup.
- **Residuals**
  - Reconciliation is a library function; there is no scheduled job or CLI yet.
  - Ambiguous reservations without a txId need an operator decision.
  - The SDK and ac2-client don't sign requester requests yet.

### R18 (eng hygiene / AI review follow-ups)

- **Spend reconcile (R18-P3-2).** Before settle, the middleware stores the txId of the payment group's first transaction and its `lastValid` on the pending reservation. `pnpm --filter @mandaterail/storage spend reconcile` checks pending (older than `--pending-older-than-ms`, default 10 min) and ambiguous rows against the indexer by txId: confirmed → `settled`; not found and indexer round > lastValid + 10 → `released`; else left alone. Every change writes an `mr_spend_audit` row. Overlapping runs are skipped (advisory lock). `--dry-run` reports without changing anything.
- Manual release: `spend release --id <id> --operator <name> --reason "<≥8 chars>"` (pending/ambiguous only, audited with actor `operator:<name>`).
- Env: `/etc/mandaterail/state-reconcile.env` with `DATABASE_URL`, `INDEXER_URL`, optional `INDEXER_TOKEN`, `PG_SSL_CA_FILE`. Output is one JSON line, with URLs redacted; exit 1 on error.
- Cron-ready (T11 schedules it), e.g. `*/5 * * * * cd /opt/mandaterail && pnpm --filter @mandaterail/storage spend reconcile >> /var/log/mandaterail/reconcile.log 2>&1`.
- **TLS (R18-P3-3).** Non-loopback `DATABASE_URL` uses TLS with `rejectUnauthorized: true` (`sslmode=disable|allow|prefer|no-verify` refused; CA via `PG_SSL_CA_FILE`). Non-loopback Redis must be `rediss://` (CA via `REDIS_TLS_CA_FILE`). `MIGRATE_DATABASE_URL` is read only by the migrate/import CLIs, never by the apps.
- **MainNet env gate (T6).** The apps refuse ALLOW_INSECURE_DEV, AC2_BRIDGE_AUTO_LOCAL, DEV_ALLOW_UNSIGNED, DEMO_MOCK_FACILITATOR, token-lab / AC2_OPERATOR_TOKEN, and any `*MNEMONIC*` variable. They require `STATE_BACKEND=postgres|redis+postgres`, FEE_PAYER (demo-api) and REQUESTER_ALLOWLIST (bridge). Only names are reported.
- **T9.** There is no localhost trust on MainNet. `/sign` needs a requester key; SDK `Ac2BridgeClient({ requester: { address, signBytes } })` and ac2-client `HttpAc2BridgeSigner({ requester: { address, sk } })` sign requests.
- **Tests (R18-P3-1).** Test PG/Redis clients have error listeners. `scripts/with-state-services.sh` and the Vitest setup redact connection strings and passwords.

### the owner's decisions for the MainNet dry run (2026-10-15)

- **R25-P2-1 trust decision (dry run ONLY):** the host operator (whoever has root on the ECS box) is accepted as trusted. Proof observations from the indexer/algod providers remain self-reported; signed attestations are still required before any MainNet launch beyond the dry run. This acceptance expires with the dry-run report.
- **Operator allowlist (MainNet):** `JXPW…GXP5R4` only. The internal reviewer test operator `C5N67…CAXWRA` stays on TestNet only.
- **Pager:** ntfy (`MONITOR_PAGER_FORMAT=ntfy`), unguessable topic; URL lives only in root 0600 env files.
- **Custody:** `mr_release` and `mr_admin` passwords live in `<local-path>` on the owner's Mac (0600 files, 0700 dir). The box copy of `mr_release.pw` is shredded. The host keeps `/root/.mr-state-secrets/mr_admin.pw` (needed by deploys; documented in TESTNET-HOST.md).
- **Dry-run wallets:** a fresh payer and a fresh merchant MainNet wallet were generated on the agent box (never on the ECS server); mnemonics in 0600 files on the box and in the Mac `.secrets` dir only. This deviates from section D (hardware payer/merchant) for the ≤ 1 USDC dry run only; sweep the merchant after the run.

### P2-T10 kill switch (implemented)

`pauseState()` in `packages/core/src/pause.ts`. demo-api `/paid/*` and bridge `POST /sign` return **503 `{"error":"paused"}`** when `MANDATERAIL_PAUSE=1` is in the env **or** the pause file exists (default `/etc/mandaterail/PAUSE`, per-service override `MANDATERAIL_PAUSE_FILE`). The file is checked on every request, so `touch` pauses and `rm` resumes with no restart. Any stat error other than ENOENT counts as paused (fail closed). `/health` and reads stay up.
