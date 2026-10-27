# Signer rehearsal A1–A6 (internal reviewer run 44), TestNet, on the box

Run: Oct 19, 2026, 8:25:48–8:26:19 PM EDT. Raw proofs: `2026-10-19-signer-rehearsal-A1-A6.json` (same directory;
includes the full off-host-format audit chain, 15 events). Harness: `packages/signer/rehearsal/a1-a6.rehearsal.test.ts`
(opt-in, `MR_REHEARSAL=1`) and `ops/signer/rehearsal/a3-gate-other-uid.sh`. Result: **all six pass**.

## Real vs stand-in

| Piece | Rehearsal | Production |
|---|---|---|
| Chain providers | **Real**: Nodely TestNet indexer (`testnet-idx.4160.nodely.dev`, genesis read from the head block header) and algod blockscan on `testnet-api.algonode.cloud`; CLI's independent check on `testnet-idx.algonode.cloud` | second operator |
| Second operator | **STAND-IN**: `testnet-api.algonode.cloud` is the *same operator* as Nodely, given the id `standin-same-operator-nodely-algonode` in the local test DB only | needs an account (e.g. GetBlock) |
| Pager | **Real** ntfy.sh publishes to a new TestNet-only topic (`mr-signer-testnet-<random>`, stored 0600 at `<workdir>/mandaterail-deploy/testnet-ntfy.env`, never printed) | MainNet topic, separate |
| Audit sink | **STAND-IN**: `TESTNET-ONLY STAND-IN (not off-host, not Object Lock)` local append file, same `AuditSink` interface | `B2ObjectLockSink` (implemented, tested against a fake S3); **needs a B2 account in the owner's name** |
| Dead-man ping | counted locally | needs a free Healthchecks.io account (`MR_HC_PING_URL`) |
| Attestation key | SoftwareEd25519Backend, TESTNET-ONLY | YubiKey PIV |
| Clock | offset from algod's HTTP `Date` header (no chrony on the box) | chrony |
| Presence proof / helper clock | harness flag; helper clock advanced to skip the 10-min lockout waits | PIN + touch |
| DB | local PG18 + mr_ed25519 + v11 test DB (never ECS) | — |
| Transport | mr-signer `main` (real HTTP server, heartbeat timer), helper over a real Unix socket | + peercred gate, systemd socket |

## Results

- **Boot**: audit chain opened, boot event seq 1, first heartbeat passed with a real ntfy test publish; 1 dead-man ping.
- **A1** never-submitted signed USDC axfer from a fresh account, fv 68434995 / lv 68435010 (head 68435025 when built),
  txId `RKOE6T5MAOPAXHN67JZN3AXHFG2K6EDEL2UKPQUDWL4MZF7NZXKQ`. Absence observed live (indexer 404, algod blockscan),
  CLI echo + independent check, two-phase confirm, helper signed, `mr_spend_release_attested` → `released`, audit row
  `attested-release`. Re-checked after the run: 404 on both indexers.
- **A2** signer: forged, replayed (the A1 confirm) and stale (−120 s) confirms → 403. Helper (own nonces): `request
  signature`, `request nonce replay`, `request timestamp outside the window`; the 4th request → `locked`.
- **A3** real other uid: `sudo -u nobody` connecting through `mr-peercred-gate` → exit 77, 0 bytes; own uid passes.
- **A4** restoring the pre-A1 `policy.json` → boot refused (`policy 0 < off-host 1`). 4 labeled synthetic nonce rows
  (inserted by the table owner in the harness; the guard refused a plain insert) + A1 = 5; the 6th, signed by the
  signer, → DB `limit of 5 attested releases per 24 h reached`, row stays `ambiguous`.
- **A5** pager pointed at an unreachable address: heartbeat `false`, **0 pings**; the release attempt → signature
  withheld (403), signer paused (`page failed (signed)`), row `ambiguous`. Then a real publish to the TestNet topic
  → HTTP 200.
- **A6** three lockouts in an hour → hard lock; a sign attempt → `hard-locked`; unlock without presence → refused;
  with presence → unlocked; the next spend is signed again (the DB then refused it on the 5/24 h limit, as expected).

## Findings from the rehearsal

1. **Fixed in this run**: the boot event did not carry the helper counter, so the helper anchor reset on every
   restart. Boot now carries it forward (proof: boot seq 4 and 12 have `helper`).
2. In A5 the `signed` event is in the audit log before the failed page; the signature is still withheld and a
   `refusal` follows. Reviewers should read `signed` as "helper signed", not "released to the requester".
3. A6 shows a surge risk: the anomaly/ambiguous path can use the 5/24 h budget (here 4 synthetic + 1), after which
   legitimate releases wait 24 h. See doc §14.2.
