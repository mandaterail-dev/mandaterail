/** R73-P3-1: B2ObjectLockSink hashes the stored bytes (arrayBuffer) for the skip pin, in rawAt and last(). */
import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { B2ObjectLockSink, seqKey } from "./b2-sink.js";

const PREFIX = "mr-monitor-anchor/testnet";
const junk = Buffer.from("7bfffe7d096a", "hex"); // not UTF-8: text decoding would replace bytes with U+FFFD
const key3 = seqKey(PREFIX, 3);
const fakeFetch = (async (u: URL | string) => {
  const url = new URL(String(u));
  const path = decodeURIComponent(url.pathname.replace(/^\/bkt\//, ""));
  if (url.searchParams.has("versions")) return new Response(`<ListVersionsResult><Version><Key>${key3}</Key><ETag>"e1"</ETag></Version></ListVersionsResult>`, { status: 200 });
  if (url.searchParams.get("list-type") === "2") return new Response(`<ListBucketResult><Key>${key3}</Key></ListBucketResult>`, { status: 200 });
  if (path === key3) return new Response(junk, { status: 200 });
  return new Response("", { status: 404 });
}) as unknown as typeof fetch;
const mk = (sha: string, onSkip?: (k: string) => void) => new B2ObjectLockSink({ endpoint: "https://s3.example.invalid", region: "r", bucket: "bkt", prefix: PREFIX, retainDays: 400,
  accessKeyId: "test-id", secretAccessKey: "test-not-a-secret", skipPinned: [{ key: key3, sha256: sha }], accept: () => false, onSkip }, fakeFetch);

describe("R73-P3-1 skip-pin sha over raw bytes", () => {
  const byBytes = createHash("sha256").update(junk).digest("hex");
  const byText = createHash("sha256").update(junk.toString("utf8")).digest("hex");
  it("rawAt returns the exact stored bytes", async () => {
    const r = await mk(byBytes).rawAt(3);
    expect(Buffer.from(r!).equals(junk)).toBe(true);
  });
  it("last() steps over a binary plant pinned by sha256sum of the object, not by the decoded-text hash", async () => {
    expect(byBytes).not.toBe(byText);
    const seen: string[] = [];
    expect(await mk(byBytes, (k) => seen.push(k)).last()).toBeNull();
    expect(seen).toHaveLength(1);
    const seen2: string[] = [];
    await mk(byText, (k) => seen2.push(k)).last().catch(() => null);
    expect(seen2).toEqual([]);
  });
});
