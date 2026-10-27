import { describe, expect, it } from "vitest";
import { keyIdOf } from "@mandaterail/storage";
import { ChainedAudit, AuditUnavailable } from "../src/audit.js";
import { SecondVerifier } from "../src/verifier/verifier.js";
import { MemSink, edKey } from "./fixtures.js";

const noPage = async () => {};

describe("R48-P2-1: verifier key placement", () => {
  it("MainNet verifier refuses cloudkms, software, and (R75-P2-1) awskms / yubikey: only the gated aliyun-softkey", () => {
    const k = edKey();
    const c = { signer: { network: "mainnet", keyId: keyIdOf(k.pub) }, primaryPubkey: k.pub, cosignerKeyId: "f".repeat(32), maxPerHour: 3, maxPer24h: 5 } as never;
    const mk = (kind: string) => () => new SecondVerifier(c, { backend: { kind } } as never);
    expect(mk("cloudkms")).toThrow(/aliyun-softkey \(got cloudkms\).*cloudkms is refused/);
    expect(mk("software-testnet-only")).toThrow(/must be the manifest-gated aliyun-softkey/);
    expect(mk("awskms")).toThrow(/awskms is a locked backup/);
    expect(mk("yubikey-piv")).toThrow(/aliyun-softkey/);
  });
});

describe("R47-P3: audit append edge cases", () => {
  it("an append that landed but whose ack was lost is adopted (seq advances, no fork, no wedge)", async () => {
    const s = new MemSink();
    let lose = false;
    const sink = { append: async (l: string) => { await s.append(l); if (lose) { lose = false; throw new Error("timeout after store"); } }, last: () => s.last(), at: (n: number) => s.at(n) };
    const a = await ChainedAudit.open(sink, noPage);
    await a.log({ kind: "one" } as never);
    lose = true;
    await expect(a.log({ kind: "two" } as never)).rejects.toBeInstanceOf(AuditUnavailable);
    await a.log({ kind: "three" } as never);
    expect(s.lines.map((l) => JSON.parse(l.split("\t")[0]!)).map((j) => [j.seq, j.kind])).toEqual([[1, "one"], [2, "two"], [3, "three"]]);
    expect((await ChainedAudit.open(s, noPage, { minSeq: 3 })).headSeq()).toBe(3);
  });
  it("a foreign line at the ambiguous seq is a fork: refused", async () => {
    const s = new MemSink();
    let fail = false;
    const sink = { append: async (l: string) => { if (fail) { fail = false; throw new Error("down"); } await s.append(l); }, last: () => s.last(), at: (n: number) => s.at(n) };
    const a = await ChainedAudit.open(sink, noPage);
    await a.log({ kind: "one" } as never);
    fail = true;
    await expect(a.log({ kind: "two" } as never)).rejects.toBeInstanceOf(AuditUnavailable);
    await s.append(JSON.stringify({ seq: 2, kind: "foreign", prev: "x" }) + "\tbad");
    await expect(a.log({ kind: "three" } as never)).rejects.toThrow(/did not write: fork/);
  });
  it("a slow page does not hold the append lock", async () => {
    const s = new MemSink();
    let release!: () => void;
    const slow = new Promise<void>((r) => { release = r; });
    let first = true;
    const a = await ChainedAudit.open(s, async () => { if (first) { first = false; await slow; } });
    const p1 = a.log({ kind: "alert" } as never, true);
    await new Promise((r) => setTimeout(r, 20));
    await a.log({ kind: "next" } as never); // completes while the first page is still pending
    expect(s.lines.length).toBe(2);
    release();
    await p1;
  });
});
