import { describe, expect, it } from "vitest";
import { HttpAc2BridgeSigner, REQUESTER_TOKEN_HEADER } from "./index.js";

const unsigned = { id: "m-1", principal: "P" } as never;

function fakeBridge(statuses: Array<{ code: number; body: unknown }>) {
  const calls: Array<{ url: string; headers: Record<string, string> }> = [];
  const f = (async (url: string, init?: RequestInit) => {
    const headers = (init?.headers ?? {}) as Record<string, string>;
    calls.push({ url, headers });
    if (url.endsWith("/sign")) {
      return new Response(JSON.stringify({ id: "r1", status: "pending", requesterToken: "tok" }), { status: 202 });
    }
    if (url.endsWith("/pending")) throw new Error("must not poll /pending");
    const next = statuses.shift() ?? { code: 200, body: { id: "r1", status: "pending" } };
    return new Response(JSON.stringify(next.body), { status: next.code });
  }) as unknown as typeof fetch;
  return { f, calls };
}

describe("HttpAc2BridgeSigner requester status polling (OA-N1)", () => {
  it("polls /requests/:id/status with the requester token until approved", async () => {
    const { f, calls } = fakeBridge([
      { code: 200, body: { id: "r1", status: "pending" } },
      { code: 200, body: { id: "r1", status: "approved", signature: "c2ln", publicKey: "cGs=", address: "A" } },
    ]);
    const s = new HttpAc2BridgeSigner({ baseUrl: "http://b", fetch: f, pollIntervalMs: 1, timeoutMs: 5000 });
    expect(await s.signIntentMandate(unsigned)).toEqual({ signature: "c2ln", publicKey: "cGs=", address: "A" });
    const polls = calls.filter((c) => c.url === "http://b/requests/r1/status");
    expect(polls.length).toBe(2);
    expect(polls[0]!.headers[REQUESTER_TOKEN_HEADER]).toBe("tok");
  });

  it("fails fast on rejected", async () => {
    const { f } = fakeBridge([{ code: 200, body: { id: "r1", status: "rejected" } }]);
    const s = new HttpAc2BridgeSigner({ baseUrl: "http://b", fetch: f, pollIntervalMs: 1, timeoutMs: 5000 });
    await expect(s.signIntentMandate(unsigned)).rejects.toThrow(/rejected/);
  });

  it("fails fast on 401/404 instead of polling until timeout", async () => {
    const { f } = fakeBridge([{ code: 404, body: { error: "not_found" } }]);
    const s = new HttpAc2BridgeSigner({ baseUrl: "http://b", fetch: f, pollIntervalMs: 1, timeoutMs: 5000 });
    await expect(s.signIntentMandate(unsigned)).rejects.toThrow(/HTTP 404/);
  });
});

describe("HttpAc2BridgeSigner requester key (T9)", () => {
  it("fetches /requester/challenge and signs the exact /sign body", async () => {
    const algosdk = (await import("algosdk")).default;
    const core = await import("@mandaterail/core");
    const acct = algosdk.generateAccount();
    const address = acct.addr.toString();
    let header = "";
    let sent = "";
    const f = (async (url: string, init?: RequestInit) => {
      if (url.startsWith("http://b/requester/challenge?address=")) {
        expect(url).toContain(address);
        return new Response(JSON.stringify({ nonce: "n1", audience: "mandaterail-ac2-bridge" }), { status: 200 });
      }
      if (url === "http://b/sign") {
        header = (init!.headers as Record<string, string>)[core.REQUESTER_AUTH_HEADER]!;
        sent = String(init!.body);
        return new Response(JSON.stringify({ signature: "c2ln", publicKey: "cGs=" }), { status: 200 });
      }
      throw new Error(`unexpected ${url}`);
    }) as unknown as typeof fetch;
    const s = new HttpAc2BridgeSigner({ baseUrl: "http://b", fetch: f, requester: { address, sk: acct.sk } });
    await s.signIntentMandate(unsigned);
    const ev = core.decodeRequesterAuthHeader(header)!;
    expect(ev).toMatchObject({ address, nonce: "n1" });
    const msg = core.buildRequesterMessage({ audience: "mandaterail-ac2-bridge", method: "POST", path: "/sign", address, nonce: "n1", timestamp: ev.timestamp, bodySha256Hex: core.bodySha256Hex(sent) });
    expect(algosdk.verifyBytes(new TextEncoder().encode(msg), Buffer.from(ev.signature, "base64"), address)).toBe(true);
  });
});
