import { describe, it, expect, vi } from "vitest";
import { DemoApiClient } from "./clients/demo-api.js";
import { Ac2BridgeClient } from "./clients/ac2-bridge.js";
import { ConsoleClient } from "./clients/console.js";
import { MandateRailHttpError } from "./http.js";
import { OPERATOR_TOKEN_HEADER, API_KEY_HEADER, TESTNET_AC2_BRIDGE_URL, TESTNET_CONSOLE_URL, encodeOperatorAttestation } from "./types.js";

function mockFetch(handler: (url: string, init?: RequestInit) => unknown) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const result = await handler(url, init);
    if (result instanceof Response) return result;
    const { status = 200, body = null, headers = {} } = (result ?? {}) as {
      status?: number;
      body?: unknown;
      headers?: Record<string, string>;
    };
    return new Response(body === null ? null : JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json", ...headers },
    });
  }) as unknown as typeof fetch;
}

describe("DemoApiClient", () => {
  it("health + list/get receipts", async () => {
    const fetchImpl = mockFetch((url) => {
      if (url.endsWith("/health")) {
        return { body: { ok: true, service: "mandaterail-demo-api" } };
      }
      if (url.includes("/receipts?") || url.endsWith("/receipts")) {
        expect(url).toContain("limit=10");
        return {
          body: {
            receipts: [
              {
                receiptId: "r1",
                mandateId: "m1",
                txId: "tx",
                network: "algorand:testnet",
                payer: "P",
                merchant: "M",
                amount: "0.01",
                asset: "USDC",
                createdAt: "2026-01-01T00:00:00Z",
                explorerUrl: "https://example.test/tx",
              },
            ],
          },
        };
      }
      if (url.endsWith("/receipts/r1")) {
        return {
          body: {
            receiptId: "r1",
            mandateId: "m1",
            txId: "tx",
            network: "algorand:testnet",
            payer: "P",
            merchant: "M",
            amount: "0.01",
            asset: "USDC",
            createdAt: "2026-01-01T00:00:00Z",
            explorerUrl: "https://example.test/tx",
          },
        };
      }
      throw new Error(`unexpected ${url}`);
    });

    const client = new DemoApiClient({
      baseUrl: "http://demo.test",
      fetch: fetchImpl,
    });
    expect((await client.health()).ok).toBe(true);
    const list = await client.listReceipts(10);
    expect(list.receipts[0]!.receiptId).toBe("r1");
    expect((await client.getReceipt("r1")).txId).toBe("tx");
  });
});

describe("Ac2BridgeClient OperatorAuth", () => {
  it("pairStatus, pending, sign; approve/reject send operator token", async () => {
    const seen: Array<{ url: string; headers: Headers | undefined; method?: string }> =
      [];
    const fetchImpl = mockFetch((url, init) => {
      const headers = new Headers(init?.headers);
      seen.push({ url, headers, method: init?.method });
      if (url.endsWith("/pair/status")) {
        return { body: { paired: true, mode: "manual" } };
      }
      if (url.endsWith("/pending")) {
        return { body: { pending: [{ id: "p1", status: "pending" }] } };
      }
      if (url.endsWith("/sign")) {
        return {
          status: 202,
          body: { id: "p1", status: "pending" },
        };
      }
      if (url.endsWith("/approve/p1")) {
        return {
          body: {
            id: "p1",
            status: "approved",
            signature: "sig",
            publicKey: "pk",
          },
        };
      }
      if (url.endsWith("/reject/p1")) {
        return { body: { id: "p1", status: "rejected" } };
      }
      if (url.endsWith("/requests/p1/status")) {
        return { body: { id: "p1", status: "approved", signature: "sig" } };
      }
      throw new Error(`unexpected ${url}`);
    });

    const client = new Ac2BridgeClient({
      baseUrl: "http://bridge.test",
      fetch: fetchImpl,
      operatorToken: "op-secret",
      apiKey: "merchant-should-not-be-used-for-operator",
    });

    expect((await client.pairStatus()).mode).toBe("manual");
    expect((await client.pending()).pending[0]!.id).toBe("p1");
    const pendingSign = await client.sign({ message: "hello" });
    expect(pendingSign).toEqual({ id: "p1", status: "pending" });

    const st = await client.requestStatus("p1", "req-tok");
    expect(st.status).toBe("approved");
    expect(
      seen.find((x) => x.url.endsWith("/requests/p1/status"))?.headers?.get("X-MandateRail-Requester-Token"),
    ).toBe("req-tok");

    await client.approve("p1", { useLocal: true });
    await client.reject("p1", { operatorToken: "per-call" });

    const approve = seen.find((s) => s.url.endsWith("/approve/p1"));
    const reject = seen.find((s) => s.url.endsWith("/reject/p1"));
    expect(approve?.headers?.get(OPERATOR_TOKEN_HEADER)).toBe("op-secret");
    expect(reject?.headers?.get(OPERATOR_TOKEN_HEADER)).toBe("per-call");
    // Merchant key may be present as default client header, but operator routes
    // must carry OperatorAuth — assert operator header is set (not ApiKeyAuth-only).
    expect(approve?.headers?.get(OPERATOR_TOKEN_HEADER)).toBeTruthy();
    expect(API_KEY_HEADER).toBe("X-MandateRail-Key");
  });

  it("throws MandateRailHttpError on 401", async () => {
    const fetchImpl = mockFetch(() => ({
      status: 401,
      body: { error: "unauthorized", message: "token required" },
    }));
    const client = new Ac2BridgeClient({
      baseUrl: "http://bridge.test",
      fetch: fetchImpl,
    });
    await expect(client.approve("x")).rejects.toBeInstanceOf(
      MandateRailHttpError,
    );
  });
});

describe("ConsoleClient (DEV ONLY)", () => {
  it("list/get/create/revoke mandates", async () => {
    const mandate = {
      id: "m1",
      principal: "P",
      agent: "A",
      maxAmount: "1.00",
      asset: "USDC",
      allowlist: ["demo"],
      expiresAt: "2099-01-01T00:00:00Z",
      revoked: false,
      nonce: "n",
      createdAt: "2026-01-01T00:00:00Z",
    };
    const fetchImpl = mockFetch((url, init) => {
      if (url.endsWith("/mandates") && (init?.method ?? "GET") === "GET") {
        return { body: { items: [mandate] } };
      }
      if (url.endsWith("/mandates") && init?.method === "POST") {
        return { status: 201, body: mandate };
      }
      if (url.endsWith("/mandates/m1")) {
        return { body: mandate };
      }
      if (url.endsWith("/mandates/m1/revoke")) {
        return { body: { ...mandate, revoked: true } };
      }
      throw new Error(`unexpected ${url} ${init?.method}`);
    });

    const client = new ConsoleClient({
      baseUrl: "http://console.test",
      fetch: fetchImpl,
    });
    expect((await client.listMandates()).items[0]!.id).toBe("m1");
    expect((await client.getMandate("m1")).id).toBe("m1");
    expect((await client.createMandate(mandate)).id).toBe("m1");
    expect((await client.revokeMandate("m1")).revoked).toBe(true);
  });

  it("challenge + operatorAttestation header on console calls", async () => {
    const seen: Array<{ url: string; att: string | null }> = [];
    const fetchImpl = mockFetch((url, init) => {
      seen.push({ url, att: new Headers(init?.headers).get("X-MandateRail-Operator-Attestation") });
      if (url.includes("/operator/challenge")) {
        return { body: { nonce: "n", action: "mandate.revoke", subjectId: "m1", audience: "mandaterail-console", issuedAt: "", expiresAt: "", message: "msg" } };
      }
      if (url.endsWith("/mandates/m1/revoke")) return { body: { id: "m1", revoked: true } };
      if (url.endsWith("/mandates")) return { body: { items: [] } };
      throw new Error(`unexpected ${url}`);
    });
    const client = new ConsoleClient({ baseUrl: "http://console.test", fetch: fetchImpl });
    const ch = await client.challenge("mandate.revoke", "m1");
    expect(ch.audience).toBe("mandaterail-console");
    expect(seen[0]!.url).toBe("http://console.test/operator/challenge?action=mandate.revoke&id=m1");
    await client.revokeMandate("m1", { operatorAttestation: "ev1" });
    await client.listMandates({ operatorAttestation: "ev2" });
    expect(seen[1]!.att).toBe("ev1");
    expect(seen[2]!.att).toBe("ev2");
  });
});

describe("live TestNet helpers", () => {
  it("testnet() factories, bridge challenge() and encodeOperatorAttestation", async () => {
    const calls: string[] = [];
    const fetchImpl = (async (url: string | URL | Request) => {
      calls.push(String(url));
      return new Response(JSON.stringify({ nonce: "n", action: "list", subjectId: "pending", audience: "a", issuedAt: "", expiresAt: "", message: "m" }), { status: 200, headers: { "content-type": "application/json" } });
    }) as typeof fetch;
    const bridge = Ac2BridgeClient.testnet({ fetch: fetchImpl });
    const ch = await bridge.challenge("list", "pending");
    expect(calls[0]).toBe(`${TESTNET_AC2_BRIDGE_URL}/operator/challenge?action=list&id=pending`);
    expect(ch.nonce).toBe("n");
    const cCalls: string[] = [];
    await ConsoleClient.testnet({ fetch: (async (u: string | URL | Request) => { cCalls.push(String(u)); return new Response("{}", { status: 200, headers: { "content-type": "application/json" } }); }) as typeof fetch }).challenge("mandate.list", "mandates");
    expect(cCalls[0]!.startsWith(TESTNET_CONSOLE_URL)).toBe(true);
    const h = encodeOperatorAttestation({ nonce: "n", address: "A", format: "algosdk", signature: "c2ln" });
    expect(JSON.parse(Buffer.from(h, "base64").toString("utf8"))).toEqual({ nonce: "n", address: "A", format: "algosdk", signature: "c2ln" });
    expect(DemoApiClient.testnet).toBeTypeOf("function");
  });
});

describe("T9 requester signing (SDK)", () => {
  it("matches the core canonical message and header format", async () => {
    const algosdk = (await import("algosdk")).default;
    const core = await import("@mandaterail/core");
    const sdk = await import("./index.js");
    const acct = algosdk.generateAccount();
    const address = acct.addr.toString();
    const body = JSON.stringify({ message: "héllo" });
    const ts = "2026-10-15T12:00:00.000Z";
    const h = await sdk.signRequesterRequest({ signer: { address, signBytes: (b) => algosdk.signBytes(b, acct.sk) }, nonce: "n", audience: "aud", body, timestamp: ts });
    expect(h).toBe(core.signRequesterRequest({ sk: acct.sk, address, nonce: "n", audience: "aud", body, timestamp: ts }));
    expect(sdk.REQUESTER_AUTH_HEADER).toBe(core.REQUESTER_AUTH_HEADER);
  });
});
