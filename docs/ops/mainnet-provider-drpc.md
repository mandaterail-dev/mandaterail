# MainNet operator 4: dRPC free (the v12 co-signer's independent operator)

Chosen by the owner on Oct 21 2026 (free, no signup, no key, no card). It replaces Blockdaemon, which is paid and NOT USED
(its code stays in place for a possible future paid setup).

| | |
|---|---|
| Host / operator | `algorand.drpc.org` / `drpc` (allowlist, mr_network_provider + mr_signer_operator via v15) |
| API | algod only, no indexer, no key. `/v2/blocks/{r}/txids` is paid-only ("method is not available on free plan") |
| Probe kind | `blockscan-full`: `/v2/status` + `/v2/transactions/params` (genesis) + `/v2/blocks/{r}?format=msgpack` for every round in [fv, lv]; txids computed locally (algosdk; gen restored when hgi, gh always), each block's round and genesis checked |
| DB method | `blockscan-full`, same rule as `blockscan` (idxRound = lastValid exactly); v15 patches the v11/v12 functions |
| Free limits | 210M CU / 30 days, ~100 RPS, public nodes only (drpc.org/docs/pricing/requests, /docs/howitworks/ratelimiting) |

Wiring: the signer keeps nodely (indexer) + getblock (algod); the verifier pins dRPC only, so its observation uses an
operator the signer does not (verifier startup refuses otherwise):
```json
{ "host": "algorand.drpc.org", "operator": "drpc", "kind": "blockscan-full", "baseUrl": "https://algorand.drpc.org" }
```
`algorand.drpc.org` is in both egress lists. The config holds no secret.

Cost / timing: about lv - fv + 3 requests per check. R58-P3-2 / R59-P3-2: the whole probe (status, params and every
block, timed from probe() entry) has one overall deadline, default 240 s (below Node's 300 s server requestTimeout).
At the deadline all in-flight requests are aborted and the probe returns error "scan deadline" (a refusal, never
"absent"). blockscan-full fetches at most 4 blocks in flight (well under dRPC free's ~100 RPS). Both are set in the
signer/verifier config: `"scan": { "deadlineS": 240, "concurrency": 4 }` (deadlineS 30..240, concurrency 1..8).
Live checks (1,001-round window, a known-absent txid, result absent, 1,003 requests):
- Oct 21 2026 ~7:20 AM ET, sequential: 153.5 s
- Oct 21 2026 ~7:40 AM ET, 4 in flight: 39.1 s (~26 req/s)

**attestTtlS >= 600 (R58-P3-2).** The co-signer's observation must be taken before the primary attestation expires
(expiry - now <= attestTtlS, max 900). With a scan of up to 240 s plus the request round-trips, the signer's
`attestTtlS` must be at least 600 s on MainNet (enforced by validateConfig since R59-P3-1; 900 is the cap). Keep the payment validity window <= 1000 rounds.

Txids (R58-P3-1) are computed from the RAW txn map of the msgpack block (canonical re-encode, gen restored when hgi,
gh always), not an SDK model round-trip, so fields the SDK does not know are still hashed.

Accepted risk (the owner, Oct 21): dRPC aggregates node providers; which node answers is not visible and could in future be
an operator the signer also uses (today the build branch is `rel/stable`, Nodely's is `AVAIL`).
