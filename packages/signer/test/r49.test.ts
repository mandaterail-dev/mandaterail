import { createHash } from "node:crypto";
import { mkdtempSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import type { AuditSink } from "../src/audit.js";
import { DurableJson } from "../src/state.js";
import { checkForwarderHeartbeat, gcpLoggingSource, initialReconcileState, ntfyHeartbeatSource, Reconciler, type KmsSignEntry, type ReconcileState } from "../src/verifier/reconcile.js";
import { signerServer } from "../src/server.js";
import type { MrSigner } from "../src/signer.js";

const H = (l: string) => createHash("sha256").update(l).digest("hex");
function chainOf(evs: { kind: string; at: number }[]): AuditSink & { lines: string[] } {
  const lines: string[] = [];
  let prev = "0".repeat(64);
  evs.forEach((e, i) => { const l = JSON.stringify({ seq: i + 1, prev, ...e }); prev = H(l); lines.push(`${l}\t${prev}`); });
  return { lines, append: async () => {}, last: async () => lines.at(-1) ?? null, at: async (s) => lines[s - 1] ?? null };
}
const KV = "projects/p/locations/us-east1/keyRings/mr/cryptoKeys/attest/cryptoKeyVersions/1";
const pins = { keyVersion: KV, signerSa: "mr-signer@p.iam.gserviceaccount.com", signerIp: "10.10.0.5", signerNetwork: "projects/p/global/networks/mr-vpc" };
const ent = (id: string, at: number, o: Partial<KmsSignEntry> = {}): KmsSignEntry => ({ insertId: id, at, principal: pins.signerSa, callerIp: pins.signerIp, callerNetwork: pins.signerNetwork, keyVersion: KV, ...o });
const T0 = Date.parse("2026-10-20T00:00:00Z");
function st(start = T0) { const f = path.join(mkdtempSync(path.join(tmpdir(), "r49-")), "r.json"); DurableJson.init<ReconcileState>(f, initialReconcileState(start)); return new DurableJson<ReconcileState>(f); }

describe("R49-P2-1 KMS audit ↔ chain reconcile", () => {
  it("clean when every AsymmetricSign matches one 'signed' event; cursor advances; state survives restart", async () => {
    const chain = chainOf([{ kind: "candidate", at: T0 + 1000 }, { kind: "signed", at: T0 + 60_000 }, { kind: "signed", at: T0 + 120_000 }]);
    const s = st(), pages: string[] = [];
    const r = new Reconciler(pins, { kms: { list: async () => [ent("a", T0 + 61_000), ent("b", T0 + 119_000)] }, chain, st: s, page: async (x) => { pages.push(x); }, now: () => T0 + 3_600_000 });
    expect(await r.tick()).toEqual([]);
    expect(pages).toEqual([]);
    expect(s.get().cursorMs).toBe(T0 + 3_000_000);
    expect(s.get().seq).toBe(3);
  });
  it("pages on an extra KMS sign, a missing one, a foreign SA, and a sign not from the reserved IP + VPC", async () => {
    const chain = chainOf([{ kind: "signed", at: T0 + 60_000 }, { kind: "signed", at: T0 + 900_000 }]);
    const s = st(), pages: string[] = [];
    const kms = [ent("ok", T0 + 60_500), ent("extra", T0 + 400_000), ent("evil", T0 + 500_000, { principal: "x@y" }), ent("ip", T0 + 600_000, { callerIp: "gce-internal-ip" })];
    const r = new Reconciler(pins, { kms: { list: async () => kms }, chain, st: s, page: async (x, b) => { pages.push(`${x}\n${b}`); }, now: () => T0 + 3_600_000 });
    const p = await r.tick();
    expect(p.join("\n")).toMatch(/extra.*no 'signed'/);
    expect(p.join("\n")).toMatch(/seq 2 has no AsymmetricSign/);
    expect(p.join("\n")).toMatch(/x@y \(not the signer SA\)/);
    expect(p.join("\n")).toMatch(/gce-internal-ip.*not the signer VM's reserved IP/);
    expect(pages[0]).toMatch(/ANOMALY KMS\/chain mismatch/);
    expect(s.get().cursorMs).toBe(T0); // not advanced: re-checked until fixed
  });
  it("a broken chain link or a source error pages", async () => {
    const chain = chainOf([{ kind: "signed", at: T0 + 1 }, { kind: "signed", at: T0 + 2 }]);
    chain.lines[1] = chain.lines[1]!.replace('"signed"', '"other"');
    const pages: string[] = [];
    const r = new Reconciler(pins, { kms: { list: async () => [] }, chain, st: st(), page: async (x, b) => { pages.push(b); }, now: () => T0 + 3_600_000 });
    expect((await r.tick())[0]).toMatch(/chain link broken at seq 2/);
    const r2 = new Reconciler(pins, { kms: { list: async () => { throw new Error("403"); } }, chain: chainOf([]), st: st(), page: async (x, b) => { pages.push(b); }, now: () => T0 + 3_600_000 });
    expect((await r2.tick())[0]).toMatch(/source error: 403/);
  });
  it("gcpLoggingSource builds the pinned filter and parses entries", async () => {
    let body: any;
    const f = (async (_u: string, i: RequestInit) => { body = JSON.parse(String(i.body)); return new Response(JSON.stringify({ entries: [{ insertId: "i1", timestamp: "2026-10-20T00:01:00Z", protoPayload: { resourceName: KV, authenticationInfo: { principalEmail: pins.signerSa }, requestMetadata: { callerIp: "10.10.0.5", callerNetwork: pins.signerNetwork } } }] }), { status: 200 }); }) as typeof fetch;
    const out = await gcpLoggingSource({ project: "p", keyVersion: KV, token: async () => "t", fetch: f }).list(T0, T0 + 1000);
    expect(body.filter).toContain(`protoPayload.resourceName="${KV}"`);
    expect(out[0]).toMatchObject({ insertId: "i1", callerIp: "10.10.0.5", principal: pins.signerSa });
  });
});

describe("R49-P2-2 forwarder heartbeat dead-man", () => {
  it("pages once when stale, once on recovery; poll errors page without leaking the topic", async () => {
    const s = st(), pages: string[] = [];
    let t = T0 + 3_600_000, latest: number | null = T0 + 3_000_000;
    const d = { latest: async () => latest, st: s, page: async (x: string, b: string) => { pages.push(`${x} ${b}`); }, now: () => t };
    expect(await checkForwarderHeartbeat(d)).toBe(true);
    t += 27 * 3_600_000;
    expect(await checkForwarderHeartbeat(d)).toBe(false);
    expect(await checkForwarderHeartbeat(d)).toBe(false);
    expect(pages.length).toBe(1);
    latest = t - 1000;
    expect(await checkForwarderHeartbeat(d)).toBe(true);
    expect(pages[1]).toMatch(/heartbeat back/);
    const topic = "Abcdefghijklmnop1234";
    const src = ntfyHeartbeatSource({ topic, fetch: (async () => { throw new Error(`connect https://ntfy.sh/${topic}`); }) as typeof fetch });
    await expect(src()).rejects.toThrow(/<topic>/);
    const ok = ntfyHeartbeatSource({ topic, fetch: (async () => new Response('{"event":"message","time":100,"tags":["heartbeat"]}\n{"event":"message","time":200,"tags":["x"]}\n', { status: 200 })) as typeof fetch });
    expect(await ok()).toBe(100_000);
  });
});

