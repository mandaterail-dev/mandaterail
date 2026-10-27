# MainNet operator 3: Blockdaemon (v12 co-signer independence)

> **NOT USED (Oct 21 2026):** Blockdaemon is paid for our needs and the owner rejected it. The co-signer uses dRPC free
> (docs/ops/mainnet-provider-drpc.md). The Blockdaemon code (X-API-Key auth, allowlist entry, v14 rows) stays in place but no config pins it.

Why: the v11 primary signer needs >= 2 distinct operators (nodely + getblock) and the v12 co-signer must use an
operator the primary did not (v12-cosign.ts). With only nodely + getblock a co-signed MainNet release always fails
closed. Blockdaemon is operator 3 and is pinned by the **verifier** (co-signer).

| | |
|---|---|
| Host | `svc.blockdaemon.com` (operator id `blockdaemon`; allowlist + mr_network_provider + mr_signer_operator via v14) |
| algod base | `https://svc.blockdaemon.com/algorand/mainnet/native` |
| indexer base | `https://svc.blockdaemon.com/algorand/mainnet/native/indexer` |
| Auth | `X-API-Key: <key>` header (Bearer also accepted by Blockdaemon); never `?apiKey=` in a URL |
| Key env var | `BLOCKDAEMON_API_KEY` (signer/verifier: `"apiKeyEnv": "BLOCKDAEMON_API_KEY"` in the provider entry; spend CLI: `PROOF2_TOKEN`) |
| Free tier | 3M compute units / month (one docs page says 1M), 5 RPS, 1 test key; paywall when exceeded (no auto-charge on free) |

Use the **indexer** kind for the verifier (idx404 = a few requests per check). The algod `blockscan` method makes up to
~1,000 block requests per check and would be slow at 5 RPS.

Verifier provider entry (config holds no secret):
```json
{ "host": "svc.blockdaemon.com", "operator": "blockdaemon", "kind": "indexer",
  "baseUrl": "https://svc.blockdaemon.com/algorand/mainnet/native/indexer", "apiKeyEnv": "BLOCKDAEMON_API_KEY" }
```
`BLOCKDAEMON_API_KEY` goes in the verifier's root-owned 0600 EnvironmentFile. The signer keeps nodely + getblock.
A signer/verifier config whose baseUrl carries a path token (GetBlock) must be 0600 or the process refuses to start (R54-P3-4).

Sources: docs.blockdaemon.com/docs/access-algorand-rpc-via-algod-api, /docs/access-algorand-rpc-via-indexer-api,
/docs/authentication, /docs/rate-limits, /docs/api-suite-dashboard, /docs/subscription-management; blockdaemon.com/api/pricing (checked 2026-10-20).

## Recovery: database at the pre-release renamed v13 (R56-P3-1)

A database migrated by the unreleased `2f90684` build recorded v13 under the combined name and already holds the Blockdaemon rows. Current builds refuse it with `SchemaNameMismatchError`. To recover, as the schema owner:

```sql
UPDATE mr_schema SET name = 'mainnet-provider-getblock' WHERE version = 13;
```

Then run the migration again. v14 (`mainnet-provider-blockdaemon`) is idempotent for the Blockdaemon rows and is a no-op on such a database, and it still stops with an error if an existing row is pinned to a different operator.
