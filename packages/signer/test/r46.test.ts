import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { ChainedAudit, AuditUnavailable } from "../src/audit.js";
import { MemSink } from "./fixtures.js";

const noPage = async () => {};
class SlowSink extends MemSink {
  fail = new Set<number>(); calls = 0;
  override async append(l: string) {
    const n = ++this.calls;
    await new Promise((r) => setTimeout(r, Math.floor(Math.random() * 15)));
    if (this.fail.has(n)) throw new Error("injected outage");
    await super.append(l);
  }
}

describe("R46-P2-1: ChainedAudit.log() is serialized", () => {
  it("40 concurrent requests get unique, consecutive seqs and an unbroken prev chain", async () => {
    const s = new SlowSink();
    const a = await ChainedAudit.open(s, noPage);
    await Promise.all(Array.from({ length: 40 }, (_, i) => a.log({ kind: "request", reason: `r${i}` } as never)));
    const recs = s.lines.map((l) => { const [j, h] = l.split("\t"); return { r: JSON.parse(j!), j: j!, h: h! }; });
    expect(recs.map((x) => x.r.seq)).toEqual(Array.from({ length: 40 }, (_, i) => i + 1));
    for (let i = 1; i < recs.length; i++) expect(recs[i]!.r.prev).toBe(recs[i - 1]!.h);
    for (const x of recs) expect(x.h).toBe(createHash("sha256").update(x.j).digest("hex"));
    expect(a.headSeq()).toBe(40);
    expect((await ChainedAudit.open(s, noPage, { minSeq: 40 })).headSeq()).toBe(40);
  });
  it("a failed append does not consume a seq or stall later requests", async () => {
    const s = new SlowSink(); s.fail.add(3);
    const a = await ChainedAudit.open(s, noPage);
    const rs = await Promise.allSettled(Array.from({ length: 6 }, () => a.log({ kind: "request" } as never)));
    expect(rs.filter((r) => r.status === "rejected").map((r) => (r as PromiseRejectedResult).reason)).toEqual([expect.any(AuditUnavailable)]);
    expect(s.lines.map((l) => JSON.parse(l.split("\t")[0]!).seq)).toEqual([1, 2, 3, 4, 5]);
  });
});
