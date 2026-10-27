# Signer rehearsal, run 46 (A1–A7 + A7-own), TestNet, on the box

Run: Oct 19, 2026, 9:23:10–9:24:55 PM EDT. Raw proofs: `2026-10-19-signer-rehearsal-r46.json` (main audit chain
`auditLog`, plus A7's own chain `auditLogA7` and A7-own's `auditLogA7own`). Result: **all seven pass**.
Stand-ins as in run 44, except the DB line now reads "migrations through v12; TestNet quorum 1, so the 2-of-2
co-sign path is not exercised here (only in test/verifier.test.ts)".

## New: A7-own, our own payment, submitted and confirmed, then detected
- Payer `FLJXFD7MTRJCDVANCA55C4DNHHWE4VTH6WKT4SCFWNYPW56OOFW356RGME`: the TestNet `pnpm e2e:paid` payer
  (TestNet only; the mnemonic is read from its 0600 file and never printed). Merchant
  `SK7X44DFL4C35E7WEF577RJWHVAM3FF5QISKRESK6VCA7Y56GNJEHWBIRI`. 1000 micro-USDC (asset 10458941), the payer
  pays its own fee (0.001 ALGO), and there is no group.
- Txn `CRF3BV5ENWSYQTMKHW3N6DRFUZECPX4ZPEPEAX5JOJU2NHLKMFQA`, fv 68436311 / lv 68436323. The row was stored
  first, with the real submit round 68436311. Submitted at 9:23:46 PM EDT (algod 200), confirmed in round 68436313
  (9:23:48 PM EDT). The row was then set to `ambiguous` (lost ack).
- **Real timing:** we waited until head > lv + margin and until the submit-time lv_est had passed (no lv − 1 shortcut).
- Release attempt: 403, and the signer **auto-paused** with `anomaly: provider testnet-idx.4160.nodely.dev (nodely)
  shows the transaction present`. Indexer `present`, algod blockscan `present`. The row stayed `ambiguous`, and
  nothing was signed. Audit chain: seq 1 `boot`, seq 2 `refusal-anomaly`.
- Limit: only the confirmed case. Public TestNet confirms a valid submitted txn within a round or two, so
  "submitted, then expired" can't be forced honestly; the never-submitted expiry is A1. The run-45 note "no funded
  TestNet account" was wrong: this payer was funded (3.997 ALGO, 19.98 USDC before the run).

## A7 (third-party confirmed payment)
Same as run 45 (`64UOAJY5…NZARQ`). Its audit chain is now in the proof: seq 1 `boot`, seq 2 `refusal-anomaly`.

## A1–A6
Same results as run 44/45.
