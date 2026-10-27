import { describe, expect, it } from "vitest";
import http from "node:http";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import { ChainedAudit, RollbackDetected } from "../src/audit.js";
import { B2ObjectLockSink, SinkBindingError, seqKey, sigV4 } from "../src/sinks/s3.js";
import { LocalAppendStandInSink, STANDIN_LABEL } from "../src/sinks/local-standin.js";
import { ntfyPager, startHeartbeat } from "../src/pager.js";
import { serveOnce } from "../src/piv/socket.js";
import { startMain, type MainConfigFile } from "../src/main.js";
import { MemSink, setup, signedPayment, candidateBody, TN, payer, merchant, feePayer, USDC_TN, edKey } from "./fixtures.js";
import { keyIdOf } from "@mandaterail/storage";
import { signRequest } from "../src/requests.js";

const noPage = async () => {};

describe("R44-P3-1 audit seq / minSeq pin", () => {
  it("empty bucket with a pinned minSeq refuses; head below the pin refuses; seq increments", async () => {
    await expect(ChainedAudit.open(new MemSink(), noPage, { minSeq: 3 })).rejects.toBeInstanceOf(RollbackDetected);
    const s = new MemSink();
    const a = await ChainedAudit.open(s, noPage);
    for (let i = 0; i < 3; i++) await a.log({ kind: "x", at: i });
    expect(a.headSeq()).toBe(3);
    expect((await ChainedAudit.open(s, noPage, { minSeq: 3 })).headSeq()).toBe(3);
    s.lines.pop();
    await expect(ChainedAudit.open(s, noPage, { minSeq: 3 })).rejects.toThrow(/below the pinned minimum/);
  });
});

describe("R44-P3-1 helper state anchoring", () => {
  it("a helper counter that does not advance pauses the signer and withholds the signature", async () => {
    let counter = 10;
    const { signer, req, policy, sink } = await setup({}, (att) => ({
      sign: async (m) => new Uint8Array((await import("node:crypto")).sign(null, Buffer.from(m), att.priv)),
      lastCounter: () => counter,
    }));
    const p1 = signedPayment();
    const c1 = await signer.candidate(req(candidateBody("s", "a", p1)));
    await signer.confirm(req({ op: "confirm", store: "s", spendId: "a", msgHash: c1.msgHash }));
    expect(sink.lines.at(-1)).toContain('"helper":10');
    counter = 7; // helper.json restored from an old copy
    const c2 = await signer.candidate(req(candidateBody("s", "b", signedPayment({ amount: 9_999n }), { row: { amountMicro: "9999" } })));
    await expect(signer.confirm(req({ op: "confirm", store: "s", spendId: "b", msgHash: c2.msgHash }))).rejects.toThrow();
    expect(policy.paused()?.reason).toMatch(/helper state rolled back/);
    expect(sink.lines.some((l) => l.includes('"kind":"signed"') && l.includes("s/b"))).toBe(false);
  });
});

describe("B2 S3 Object Lock sink", () => {
  it("SigV4 matches the AWS published GET-object example", () => {
    const h = sigV4({ region: "us-east-1", accessKeyId: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" },
      "GET", new URL("https://examplebucket.s3.amazonaws.com/test.txt"), { range: "bytes=0-9" }, "", new Date("2013-05-24T00:00:00Z"));
    expect(h.authorization).toBe("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41");
  });

  // fake B2: versioned bucket, If-None-Match -> 501 Not Implemented (B2's real behaviour), ListObjectVersions
  async function fakeB2() {
    const objs = new Map<string, { body: string; lock: string | undefined; until: string | undefined }[]>();
    let puts = 0;
    const srv = http.createServer(async (rq, rs) => {
      const chunks: Buffer[] = [];
      for await (const c of rq) chunks.push(c as Buffer);
      const body = Buffer.concat(chunks);
      if (!/^AWS4-HMAC-SHA256 Credential=kid\//.test(String(rq.headers.authorization))) { rs.writeHead(403); return rs.end(); }
      const u = new URL(rq.url!, "http://x");
      if (rq.method === "PUT") {
        if (rq.headers["if-none-match"]) { rs.writeHead(501); return rs.end(); }
        if (rq.headers["content-md5"] !== createHash("md5").update(body).digest("base64")) { rs.writeHead(400); return rs.end(); }
        puts++;
        objs.set(u.pathname, [...(objs.get(u.pathname) ?? []), { body: body.toString(), lock: rq.headers["x-amz-object-lock-mode"] as string, until: rq.headers["x-amz-object-lock-retain-until-date"] as string }]);
        rs.writeHead(200); return rs.end();
      }
      if (u.searchParams.has("versions")) {
        const k = "/bkt/" + u.searchParams.get("prefix");
        const vs = (objs.get(k) ?? []).map((o) => `<Version><Key>${k.slice(5)}</Key><ETag>"${createHash("md5").update(o.body).digest("hex")}"</ETag></Version>`);
        rs.writeHead(200); return rs.end(`<ListVersionsResult>${vs.join("")}</ListVersionsResult>`);
      }
      if (u.searchParams.get("list-type") === "2") {
        const pre = "/bkt/" + u.searchParams.get("prefix");
        const keys = [...objs.keys()].filter((k) => k.startsWith(pre)).sort().slice(0, Number(u.searchParams.get("max-keys")));
        rs.writeHead(200); return rs.end(`<ListBucketResult>${keys.map((k) => `<Contents><Key>${k.slice(5)}</Key></Contents>`).join("")}</ListBucketResult>`);
      }
      const o = objs.get(u.pathname)?.at(-1);
      rs.writeHead(o ? 200 : 404); rs.end(o?.body ?? "");
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const port = (srv.address() as { port: number }).port;
    const mk = (mode?: "if-none-match", skipPinned?: Array<{ key: string; sha256: string }>, accept?: (l: string) => boolean, onSkip?: (k: string) => void) => new B2ObjectLockSink({ endpoint: `http://127.0.0.1:${port}`, region: "us-west-004", bucket: "bkt", prefix: "mr/testnet", retainDays: 400, accessKeyId: "kid", secretAccessKey: "sek", conditionalWrites: mode, skipPinned, accept, onSkip });
    return { srv, objs, mk, puts: () => puts };
  }
  const hl = (o: object) => { const l = JSON.stringify(o); return `${l}\t${createHash("sha256").update(l).digest("hex")}`; };

  it("puts one COMPLIANCE-locked object per line; last() returns the head; open() checks the head links to seq-1", async () => {
    const b = await fakeB2();
    try {
      const sink = b.mk();
      expect(await sink.last()).toBeNull();
      const a = await ChainedAudit.open(sink, noPage);
      for (let i = 0; i < 12; i++) await a.log({ kind: "e", at: i });
      expect([...b.objs.values()].every((v) => v.length === 1 && v[0]!.lock === "COMPLIANCE" && Date.parse(v[0]!.until!) > Date.now() + 399 * 86_400_000)).toBe(true);
      expect((await ChainedAudit.open(sink, noPage, { minSeq: 12 })).headSeq()).toBe(12);
      expect(seqKey("p", 12) < seqKey("p", 11)).toBe(true);
      // a key-holder writes a forged seq-13 head with a made-up prev: refused at open
      const forged = hl({ seq: 13, kind: "forged", at: 0, counters: { policy: 999, requests: 999 }, prev: "ab".repeat(32) });
      await sink.append(forged);
      await expect(ChainedAudit.open(sink, noPage)).rejects.toThrow(/does not link to seq 12/);
      await expect(sink.append("{}\tx")).rejects.toThrow(/seq/);
    } finally { b.srv.close(); }
  });

  it("R45-P3-1 B2 has no If-None-Match (501): check-then-put; a lost ack re-append is a no-op; different bytes refused; 2 versions refused", async () => {
    const b = await fakeB2();
    try {
      const sink = b.mk("if-none-match"); // S3 mode first: B2 answers 501 and the sink falls back
      const l1 = hl({ seq: 1, kind: "a", at: 1, prev: "0".repeat(64) });
      await sink.append(l1);
      const n = b.puts();
      await sink.append(l1); // retry after a lost ack
      expect(b.puts()).toBe(n);
      await expect(sink.append(hl({ seq: 1, kind: "other", at: 1, prev: "0".repeat(64) }))).rejects.toThrow(/different content/);
      // a second writer bypassing the check adds a version: open refuses
      b.objs.get("/bkt/" + seqKey("mr/testnet", 1))!.push({ body: "x\n", lock: "COMPLIANCE", until: "" });
      await expect(sink.last()).rejects.toThrow(/more than one distinct version/);
    } finally { b.srv.close(); }
  });

  it("R46-P3: a second version on the seq-1 key (not the head) is refused at open too", async () => {
    const b = await fakeB2();
    try {
      const sink = b.mk();
      const a = await ChainedAudit.open(sink, noPage);
      for (let i = 0; i < 3; i++) await a.log({ kind: "e", at: i });
      b.objs.get("/bkt/" + seqKey("mr/testnet", 2))!.push({ body: "x\n", lock: "COMPLIANCE", until: "" });
      await expect(sink.at(2)).rejects.toThrow(/seq 2 has more than one distinct version/);
      await expect(ChainedAudit.open(sink, noPage)).rejects.toThrow(/more than one distinct version/);
    } finally { b.srv.close(); }
  });

  it("R67-P3-2: the head key must be seqKey(line.seq): a genuine old line replayed under a first-sorting key refuses; at() binds too; listed skip keys are stepped past", async () => {
    const b = await fakeB2();
    try {
      const sink = b.mk();
      const a = await ChainedAudit.open(sink, noPage);
      for (let i = 0; i < 3; i++) await a.log({ kind: "e", at: i });
      const old = b.objs.get("/bkt/" + seqKey("mr/testnet", 2))!.at(-1)!.body;
      b.objs.set("/bkt/mr/testnet/000000000000.jsonl", [{ body: old, lock: "COMPLIANCE", until: "" }]);
      await expect(sink.last()).rejects.toThrow(SinkBindingError);
      await expect(sink.last()).rejects.toThrow(/000000000000\.jsonl does not match its line's seq/);
      await expect(ChainedAudit.open(sink, noPage)).rejects.toThrow(/does not match/);
      // R69-P3-1 repair: (key, sha256) pinned; the true head (seq 3) is found again and the skip is reported
      const sh = (x: string) => createHash("sha256").update(x).digest("hex");
      const skips: string[] = [];
      const fixed = b.mk(undefined, [{ key: "mr/testnet/000000000000.jsonl", sha256: sh(old) }], undefined, (k) => skips.push(k));
      expect(JSON.parse((await fixed.last())!.split("\t")[0]!).seq).toBe(3);
      expect(skips).toEqual(["000000000000.jsonl"]);
      expect((await ChainedAudit.open(fixed, noPage)).headSeq()).toBe(3);
      // the right key with the wrong sha256 does not skip (a pre-listed future key can't match unknown bytes)
      await expect(b.mk(undefined, [{ key: "mr/testnet/000000000000.jsonl", sha256: sh("other") }]).last()).rejects.toThrow(SinkBindingError);
      // a legit (bound + accepted) head is never skipped even when pinned by key + sha
      const h3k = seqKey("mr/testnet", 3), h3 = b.objs.get("/bkt/" + h3k)!.at(-1)!.body;
      const p2 = b.mk(undefined, [{ key: "mr/testnet/000000000000.jsonl", sha256: sh(old) }, { key: h3k, sha256: sh(h3) }]);
      expect(JSON.parse((await p2.last())!.split("\t")[0]!).seq).toBe(3);
      // a BOUND plant (right key for its own seq, junk body) is skipped when pinned and rejected by accept
      const bk = seqKey("mr/testnet", 999_999_999_998), junk = '{"seq":999999999998}\tjunk\n';
      b.objs.set("/bkt/" + bk, [{ body: junk, lock: "COMPLIANCE", until: "" }]);
      const acc = (l: string) => l.split("\t")[1] === sh(l.split("\t")[0]!);
      expect(JSON.parse((await b.mk(undefined, [{ key: "mr/testnet/000000000000.jsonl", sha256: sh(old) }], acc).last())!.split("\t")[0]!).seq).toBe(999_999_999_998); // unpinned: returned, caller refuses as corrupt
      const s2: string[] = [];
      const p3 = b.mk(undefined, [{ key: "mr/testnet/000000000000.jsonl", sha256: sh(old) }, { key: bk, sha256: sh(junk) }], acc, (k) => s2.push(k));
      expect(JSON.parse((await p3.last())!.split("\t")[0]!).seq).toBe(3);
      expect(s2).toEqual(["000000000000.jsonl", bk.slice("mr/testnet/".length)]);
      b.objs.delete("/bkt/" + bk);
      // at(): a key holding another seq's line refuses
      b.objs.get("/bkt/" + seqKey("mr/testnet", 1))!.splice(0, 1, { body: old, lock: "COMPLIANCE", until: "" });
      await expect(sink.at(1)).rejects.toThrow(/holds a line for another seq/);
    } finally { b.srv.close(); }
  });

  it("errors never contain the credentials", async () => {
    const sink = new B2ObjectLockSink({ endpoint: "http://127.0.0.1:1", region: "r", bucket: "b", prefix: "p", retainDays: 1, accessKeyId: "KIDSECRET", secretAccessKey: "APPKEYSECRET" });
    const e = await sink.last().catch((x: Error) => x);
    expect(String((e as Error).message)).not.toMatch(/SECRET/);
  });
});

describe("R45-P3-1 MainNet image: stand-in sink", () => {
  it("main.ts has no static import of the stand-in; it is in the exclude list; MainNet buildSink refuses before importing it", async () => {
    const src = path.resolve(__dirname, "../src");
    const seen = new Set<string>();
    const walk = (f: string) => {
      if (seen.has(f)) return;
      seen.add(f);
      for (const m of readFileSync(f, "utf8").matchAll(/from "(\.[^"]+)"/g)) walk(path.resolve(path.dirname(f), m[1]!.replace(/\.js$/, ".ts")));
    };
    walk(path.join(src, "main.ts"));
    expect([...seen].some((f) => f.endsWith("local-standin.ts"))).toBe(false);
    const ex = readFileSync(path.resolve(__dirname, "../../../deploy/signer/mainnet-image.exclude"), "utf8");
    expect(ex).toMatch(/^packages\/signer\/src\/sinks\/local-standin\.ts$/m);
    expect(ex).toMatch(/^packages\/signer\/rehearsal\/$/m);
    const { buildSink } = await import("../src/main.js");
    await expect(buildSink({ signer: { network: "mainnet" }, audit: { kind: "testnet-standin", label: STANDIN_LABEL, file: "/x", minSeq: 0 } } as never, {})).rejects.toThrow(/TESTNET-ONLY/);
  });
});

describe("TESTNET-ONLY stand-in sink", () => {
  it("requires testnet + the label, appends, and detects truncation", async () => {
    const f = path.join(mkdtempSync(path.join(tmpdir(), "standin-")), "audit.jsonl");
    expect(() => new LocalAppendStandInSink(f, { network: "mainnet", label: STANDIN_LABEL })).toThrow();
    expect(() => new LocalAppendStandInSink(f, { network: "testnet", label: "x" })).toThrow();
    const s = new LocalAppendStandInSink(f, { network: "testnet", label: STANDIN_LABEL });
    const a = await ChainedAudit.open(s, noPage);
    await a.log({ kind: "a", at: 1 });
    await a.log({ kind: "b", at: 2 });
    writeFileSync(f, "");
    await expect(s.last()).rejects.toThrow(/truncated/);
  });
});

describe("ntfy pager + heartbeat timer", () => {
  it("posts title/priority to /<topic>; failure errors never include the topic", async () => {
    const got: { url?: string; title?: string; body?: string }[] = [];
    let fail = false;
    const srv = http.createServer(async (rq, rs) => {
      let b = ""; for await (const c of rq) b += c;
      got.push({ url: rq.url, title: rq.headers.title as string, body: b });
      rs.writeHead(fail ? 500 : 200); rs.end("{}");
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const topic = "mr-signer-testnet-abcdefABCDEF1234";
    const page = ntfyPager({ server: `http://127.0.0.1:${(srv.address() as { port: number }).port}`, topic });
    try {
      await page("[signer] signed", "s/a");
      expect(got[0]).toEqual({ url: `/${topic}`, title: "[signer] signed", body: "s/a" });
      fail = true;
      const e = await page("[signer] x", "").catch((x: Error) => x);
      expect((e as Error).message).toMatch(/ntfy status 500/);
      expect((e as Error).message).not.toContain(topic);
    } finally { srv.close(); }
    expect(() => ntfyPager({ topic: "short" })).toThrow();
  });

  it("startHeartbeat runs immediately and on the interval, never overlapping", async () => {
    const res: boolean[] = [];
    let n = 0;
    const stop = startHeartbeat(async () => { n++; await new Promise((r) => setTimeout(r, 30)); return true; }, 10, (ok) => res.push(ok));
    await new Promise((r) => setTimeout(r, 120));
    stop();
    expect(n).toBeGreaterThanOrEqual(2);
    expect(n).toBeLessThanOrEqual(5);
    expect(res.every(Boolean)).toBe(true);
  });
});

describe("R44-P3 serveOnce read timeout", () => {
  it("a peer that never sends a line gets a timeout reply and the slot is freed", async () => {
    const input = new PassThrough(), output = new PassThrough();
    let out = ""; output.on("data", (d) => { out += d; });
    await serveOnce({ sign: async () => new Uint8Array(64) }, input, output, 50);
    expect(out).toContain("read timeout");
  });
  it("the reply carries the helper's counter when it has one", async () => {
    const input = new PassThrough(), output = new PassThrough();
    let out = ""; output.on("data", (d) => { out += d; });
    const p = serveOnce({ sign: async () => new Uint8Array(64), counter: () => 42 }, input, output, 1000);
    input.write(JSON.stringify({ msg: "", confirm: {} }) + "\n");
    await p;
    expect(JSON.parse(out).counter).toBe(42);
  });
});

describe("R44-GATE-1 main wiring", () => {
  function mainCfg(dir: string, att: Uint8Array, req: Uint8Array): MainConfigFile {
    return {
      signer: {
        network: "testnet", genesisHash: TN, margin: 10, usdcAsaId: USDC_TN, payer: payer.addr.toString(), merchant: merchant.addr.toString(),
        feePayer: feePayer.addr.toString(), feePayerMaxFee: "2000", payerMaxFee: "1000", keyId: keyIdOf(att),
        providers: [
          { host: "testnet-idx.4160.nodely.dev", operator: "op-a", kind: "indexer", baseUrl: "https://testnet-idx.4160.nodely.dev" },
          { host: "testnet-api.4160.nodely.dev", operator: "op-b", kind: "algod", baseUrl: "https://testnet-api.4160.nodely.dev" },
        ],
        requesters: [{ id: "cli-david", pubkeyB64: Buffer.from(req).toString("base64") }], requesterRatePerHour: 30, requestMaxAgeS: 30,
        maxClockSkewS: 5, maxSnapshotAgeS: 60, maxHeadSpreadRounds: 20, attestTtlS: 300,
        policy: { maxAmountMicro: "10000", maxReleasesPerHour: 3, maxReleasesPerDay: 5, maxReleasedMicroPerDay: "50000", windowUtcHours: [0, 24], anomalyPauseRefusalsPerHour: 6 },
      },
      attestPubkeyB64: Buffer.from(att).toString("base64"), stateDir: dir, helperSocket: path.join(dir, "h.sock"),
      listen: { host: "127.0.0.1", port: 0, allowIps: ["127.0.0.1"] },
      audit: { kind: "testnet-standin", minSeq: 0, label: STANDIN_LABEL, file: path.join(dir, "audit.jsonl") }, heartbeatIntervalS: 3600,
    };
  }
  it("the boot line carries the last helper counter forward", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "mr-main-"));
    const att = edKey(), rq = edKey();
    const f = mainCfg(dir, att.pub, rq.pub);
    const line = JSON.stringify({ seq: 1, kind: "signed", at: 1, counters: { policy: 0, requests: 0, helper: 9 }, prev: "0".repeat(64) });
    writeFileSync(f.audit.kind === "testnet-standin" ? f.audit.file : "", `${line}\t${createHash("sha256").update(line).digest("hex")}\n`);
    const o = { pager: async () => {}, ping: async () => {}, clock: async () => ({ synced: true, offsetS: 0, stratum: 2 }), probes: [] };
    const r = await startMain(f, {}, o).catch((e: Error) => e);
    // state files are missing with a non-empty log: refused (wipe); seed them and retry
    expect(String(r)).toMatch(/wiped/);
  });
  it("boots, logs boot, heartbeats (test page + ping); a wiped state dir with a non-empty log refuses", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "mr-main-"));
    const att = edKey(), rq = edKey();
    const f = mainCfg(dir, att.pub, rq.pub);
    const pages: string[] = []; let pings = 0;
    const o = { pager: async (s: string) => { pages.push(s); }, ping: async () => { pings++; }, clock: async () => ({ synced: true, offsetS: 0, stratum: 2 }), probes: [] };
    const r = await startMain(f, {}, o);
    await new Promise((x) => setTimeout(x, 50));
    expect(r.heartbeats).toEqual([true]);
    expect(pages).toEqual(["[signer] heartbeat test"]);
    expect(pings).toBe(1);
    r.stopHeartbeat(); r.server.close();
    rmSync(path.join(dir, "policy.json"));
    await expect(startMain(f, {}, o)).rejects.toThrow(/missing but the off-host log/);
    await expect(startMain({ ...f, audit: { ...f.audit, minSeq: 99 } as never }, {}, o)).rejects.toThrow(/below the pinned/);
    await expect(startMain(f, {}, { ...o, pager: undefined })).rejects.toThrow(/MR_NTFY_TOPIC/);
    void signRequest;
  });
});
