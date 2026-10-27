/**
 * T5-P3-1 / T5-P3-2: at startup, prove that the configured algod serves the
 * chain the profile names (genesis hash) and that the USDC ASA has 6
 * decimals. Refuse to start otherwise. Errors never echo the algod URL/token.
 */
import { providerAuthHeaders, type NetworkProfile } from "./network.js";
import { USDC_DECIMALS } from "./spend-caps.js";

export class AlgodProfileError extends Error {}

export const DEFAULT_ALGOD_URLS: Record<NetworkProfile["name"], string> = {
  testnet: "https://testnet-api.algonode.cloud",
  mainnet: "https://mainnet-api.algonode.cloud",
};

export function profileGenesisHash(p: NetworkProfile): string {
  return p.caip2.slice("algorand:".length);
}

export async function verifyAlgodMatchesProfile(
  profile: NetworkProfile,
  opts: { algodUrl?: string; token?: string; fetchImpl?: typeof fetch; timeoutMs?: number } = {},
): Promise<{ genesisHash: string; decimals: number }> {
  const base = (opts.algodUrl || DEFAULT_ALGOD_URLS[profile.name]).replace(/\/$/, "");
  const f = opts.fetchImpl ?? fetch;
  const headers: Record<string, string> = providerAuthHeaders(base, "algod", opts.token);
  const get = async (path: string): Promise<unknown> => {
    let res: Response;
    try {
      res = await f(`${base}${path}`, { headers, signal: AbortSignal.timeout(opts.timeoutMs ?? 10_000) });
    } catch {
      throw new AlgodProfileError(`algod unreachable (${path})`);
    }
    if (!res.ok) throw new AlgodProfileError(`algod ${path} returned HTTP ${res.status}`);
    return res.json();
  };
  const versions = (await get("/versions")) as { genesis_hash_b64?: string };
  const want = profileGenesisHash(profile);
  if (versions.genesis_hash_b64 !== want) {
    throw new AlgodProfileError(
      `algod genesis hash ${String(versions.genesis_hash_b64)} does not match ${profile.name} (${want}); refusing to start`,
    );
  }
  const asset = (await get(`/v2/assets/${encodeURIComponent(profile.usdcAsaId)}`)) as { params?: { decimals?: number } };
  const decimals = asset.params?.decimals;
  if (decimals !== USDC_DECIMALS) {
    throw new AlgodProfileError(
      `ASA ${profile.usdcAsaId} has decimals ${String(decimals)}, expected ${USDC_DECIMALS}; refusing to start`,
    );
  }
  return { genesisHash: want, decimals };
}

/**
 * Startup policy: always on MainNet; on TestNet only with ALGOD_CHECK=1
 * (keeps offline TestNet labs/CI working). ALGOD_URL / ALGOD_TOKEN optional.
 */
export function algodCheckRequired(profile: NetworkProfile, env: Record<string, string | undefined> = process.env): boolean {
  if (profile.isMainnet) return true;
  const v = env.ALGOD_CHECK ?? "";
  return v === "1" || v.toLowerCase() === "true";
}
