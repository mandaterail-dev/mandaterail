# Signer rehearsal, run 45 re-run (A1–A7), TestNet, on the box

Run: Oct 19, 2026, 9:02:25–9:03:00 PM EDT. Raw proofs: `2026-10-19-signer-rehearsal-r45.json` (includes the full
audit chain, and now the A1 attestation body + signature). Code: v12 schema, CLI 8-argument release path.
Result: **all seven pass**. Stand-ins as in `2026-10-19-signer-rehearsal-A1-A6.md` (unchanged: stand-in sink,
same-operator second provider, software key, Date-header clock, harness presence flag, local test DB).

## New: A7 — a real submission that confirmed, detected
- Payment `64UOAJY5ZD6AL63WOMHZDCJ2VJCF4FTURMPAV6TA2R5GQRSNZARQ` (TestNet USDC, confirmed in round 48960137,
  fv 48960135 / lv 48961135, Feb 22, 2025). Rebuilt byte-exact from the indexer (txID of the rebuilt transaction
  equals the chain txID) and stored in an ambiguous row exactly as the app would store it.
- Release attempt → the signer refused (403) and **auto-paused**: `anomaly: provider testnet-idx.4160.nodely.dev
  (nodely) shows the transaction present` (logged as `refusal-anomaly`). Both probes see it: indexer `present`,
  algod blockscan `present`. The row stayed `ambiguous`; nothing was signed.
- Limits (honest): it is a third party's payment, not our own submit — the box has no funded TestNet account
  (the TestNet dispensers need a captcha or a GitHub login). The "submitted, then expired" path is A1's
  never-submitted case. As in A1, the harness sets submit_round = lv − 1 so lv_est has passed (the real submit
  time predates the row). To run our own in-flight case: fund one TestNet account (free, by hand) and re-run.

## A1–A6
Same results as the run-44 proofs (released / refused / locked / paused as listed there), now via the v12 entry point.
