/**
 * CLI attested release path (§1.1 echo checks, R41-a return verification, R41-c independent absence check).
 * Runs as mr_release. Order (each step fail-closed, every refusal pages):
 *   A. read the row + DB clock snapshot; re-derive from signed_txn and require equality with the app-derived columns
 *   B. signed candidate request -> echoed message; strict decode; every field equal to the row and pins
 *   C. independent absence check from the CLI's own pinned provider(s) (any present / error / low round refuses)
 *   D. signed confirm(msgHash) -> (msg, sig): msg must be byte-identical to the verified echo, sig must verify
 *      against the DB's pinned, unrevoked key (keyId = the CLI's pin)
 *   E. SELECT mr_spend_release_attested(...)
 */
import { createHash, randomBytes, type KeyObject } from "node:crypto";
import type pg from "pg";
import { decodeAttestation, decodeCosign, isoSeconds, keyIdOf, verifyAttestation, type JcsValue, type SignedTxnKind } from "@mandaterail/storage";
import { GENESIS_PINS, type SignerConfig } from "../config.js";
import { checkSignedTxn } from "../txcheck.js";
import type { ChainProbe } from "../providers.js";
import { signRequest, type SignedRequest } from "../requests.js";
import type { CandidateResponse, ConfirmResponse } from "../signer.js";

export interface SignerTransport {
  candidate(r: SignedRequest): Promise<CandidateResponse>;
  confirm(r: SignedRequest): Promise<ConfirmResponse>;
}
export interface CliDeps {
  db: pg.Pool | pg.PoolClient; // mr_release
  cfg: SignerConfig; // the CLI's own copy of the pins (same values as the signer's)
  pinnedPubkey: Uint8Array; // R43-P3: the attestation pubkey pinned in the CLI config, not only via the DB keyId
  requesterId: string;
  requesterKey: KeyObject;
  transport: SignerTransport;
  ownProbes: ChainProbe[]; // R41-c: pinned, preferably another operator than the signer's
  page: (subject: string, body: string) => Promise<void>;
  label: string;
  reason: string;
  /** v12: the second verifier (required where the DB quorum is 2, i.e. MainNet) and its pinned public key */
  cosigner?: { cosign(r: SignedRequest): Promise<{ msg: string; sig: string }>; pinnedPubkey: Uint8Array };
}
export class CliRefused extends Error {}

export async function attestedRelease(d: CliDeps, store: string, spendId: string): Promise<{ ok: boolean; fromStatus: string | null; msgHash: string }> {
  const fail = async (why: string): Promise<never> => {
    try { await d.page("[signer CLI] release refused", `${store}/${spendId}: ${why}`); } catch { /* still refuse */ }
    throw new CliRefused(why);
  };
  const c = d.cfg;
  // A
  const { rows } = await d.db.query(
    `SELECT status, amount_micro::text, signed_txn, signed_txn_kind, tx_id, first_valid::int, last_valid::int, group_id, sender,
            submit_round::int, submit_at, clock_timestamp() AS now FROM mr_spend WHERE store = $1 AND id = $2`, [store, spendId]);
  const r = rows[0];
  if (!r) return fail("no such spend");
  if (r.status !== "ambiguous") return fail(`status ${r.status}`);
  if (!r.signed_txn) return fail("no stored signed_txn");
  const f = checkSignedTxn(r.signed_txn, r.signed_txn_kind as SignedTxnKind, c);
  if (f.txId !== r.tx_id || f.firstValid !== r.first_valid || f.lastValid !== r.last_valid || f.groupId !== r.group_id || f.sender !== r.sender || f.amountMicro.toString() !== r.amount_micro) {
    return fail("echo A: stored derived columns differ from the signed bytes");
  }
  const req = (body: Record<string, JcsValue>) => signRequest({ requester: d.requesterId, network: c.network, ts: isoSeconds(Date.now()), reqNonce: randomBytes(32).toString("base64url"), store, spendId, ...body }, d.requesterKey);
  // B
  const cand = await d.transport.candidate(req({
    op: "candidate", kind: r.signed_txn_kind, signedTxn: Buffer.from(r.signed_txn).toString("base64"), snapshotAt: isoSeconds(new Date(r.now).getTime()),
    row: { status: r.status, txId: r.tx_id, firstValid: r.first_valid, lastValid: r.last_valid, groupId: r.group_id, sender: r.sender, amountMicro: r.amount_micro, submitRound: r.submit_round, submitAt: isoSeconds(new Date(r.submit_at).getTime()) },
  }));
  const echo = Buffer.from(cand.msg, "base64");
  const msgHash = createHash("sha256").update(echo).digest("hex");
  if (msgHash !== cand.msgHash) return fail("echo B: msgHash");
  let b;
  try { b = decodeAttestation(echo); } catch (e) { return fail(`echo B: ${(e as Error).message}`); }
  if (b.network !== c.network || b.genesisHash !== GENESIS_PINS[c.network] || b.keyId !== c.keyId || b.store !== store || b.spendId !== spendId
      || b.txId !== r.tx_id || b.firstValid !== r.first_valid || b.lastValid !== r.last_valid || b.groupId !== r.group_id || b.sender !== r.sender) {
    return fail("echo B: attested fields differ from the row / pins");
  }
  const need = b.lastValid + c.margin;
  const ops = new Set(b.observations.map((o) => o.operator));
  if (b.round < need || ops.size < 2 || b.observations.some((o) => o.round < need || (o.method === "idx404" ? o.idxRound < need : o.idxRound !== b.lastValid))
      || b.observations.some((o) => !c.providers.some((p) => p.host === o.provider && p.operator === o.operator))) {
    return fail("echo B: observations do not meet the rules");
  }
  // C: independent check before confirm, and again right before the DB call (R43-P3)
  const independent = async (): Promise<void> => {
    if (d.ownProbes.length < 1) return fail("no independent provider configured");
    for (const p of d.ownProbes) {
      const x = await p.probe(f.memberTxIds, f.firstValid, f.lastValid);
      if (x.kind === "present") return fail(`independent check: ${p.provider.host} shows the transaction present`);
      if (x.kind === "error") return fail(`independent check: ${p.provider.host} unavailable (${x.reason})`);
      if (x.genesis !== GENESIS_PINS[c.network] || x.round < need) return fail(`independent check: ${p.provider.host} genesis / round below lastValid + margin`);
    }
  };
  await independent();
  // D
  const conf = await d.transport.confirm(req({ op: "confirm", msgHash }));
  const ret = Buffer.from(conf.msg, "base64");
  if (!ret.equals(echo)) return fail("return: signed message differs from the verified echo");
  const k = (await d.db.query("SELECT pubkey, revoked_at FROM mr_signer_key WHERE key_id = $1", [c.keyId])).rows[0];
  if (!k || k.revoked_at) return fail("pinned key unknown or revoked in the DB");
  if (!Buffer.from(k.pubkey).equals(Buffer.from(d.pinnedPubkey)) || keyIdOf(d.pinnedPubkey) !== c.keyId) return fail("DB key differs from the CLI-pinned pubkey");
  const sig = Buffer.from(conf.sig, "base64");
  if (!verifyAttestation(ret, sig, k.pubkey)) return fail("return: signature does not verify");
  await independent(); // right before mr_spend_release_attested, as §1.1 says
  // D2 (v12): the second verifier re-derives and re-proves absence itself; the CLI checks the binding + signature
  let cmsg: Buffer | null = null, csig: Buffer | null = null;
  if (d.cosigner) {
    const cr = await d.cosigner.cosign(req({
      op: "cosign", kind: r.signed_txn_kind, signedTxn: Buffer.from(r.signed_txn).toString("base64"), attestMsg: ret.toString("base64"), attestSig: sig.toString("base64"),
      row: { submitRound: r.submit_round, submitAt: isoSeconds(new Date(r.submit_at).getTime()) },
    }));
    cmsg = Buffer.from(cr.msg, "base64"); csig = Buffer.from(cr.sig, "base64");
    let cb;
    try { cb = decodeCosign(cmsg); } catch (e) { return fail(`co-signature: ${(e as Error).message}`); }
    if (cb.attestHash !== createHash("sha256").update(ret).digest("hex") || cb.store !== store || cb.spendId !== spendId || cb.txId !== r.tx_id
        || cb.keyId !== keyIdOf(d.cosigner.pinnedPubkey) || cb.keyId === c.keyId) return fail("co-signature is not bound to this attestation / pinned key");
    if (!verifyAttestation(cmsg, csig, d.cosigner.pinnedPubkey)) return fail("co-signature does not verify");
  }
  // E
  const out = await d.db.query("SELECT * FROM mr_spend_release_attested($1, $2, $3, $4, $5, $6, $7, $8)", [store, spendId, ret, sig, cmsg, csig, d.label, d.reason]);
  return { ok: out.rows[0].ok === true, fromStatus: out.rows[0].from_status, msgHash };
}

/**
 * R42-P3-1: the DB's list for a used.db rebuild — every spend already attested (nonce rows + stored attestations).
 * Run as mr_release or mr_monitor; output "store/spendId" lines, fed to UsedStore.rebuild on the signer.
 */
export async function exportAttestedSpends(db: pg.Pool | pg.PoolClient): Promise<string[]> {
  const { rows } = await db.query<{ k: string }>(
    `SELECT store || '/' || spend_id AS k FROM mr_release_nonce
     UNION SELECT store || '/' || id FROM mr_spend WHERE attestation_msg IS NOT NULL ORDER BY 1`);
  return rows.map((x) => x.k);
}
