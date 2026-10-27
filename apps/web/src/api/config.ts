export const DEMO_API_URL =
  import.meta.env.VITE_DEMO_API_URL ?? "http://127.0.0.1:8787";
export const AC2_BRIDGE_URL =
  import.meta.env.VITE_AC2_BRIDGE_URL ?? "http://127.0.0.1:8790";
export const CONSOLE_API_URL =
  import.meta.env.VITE_CONSOLE_API_URL ?? "http://127.0.0.1:8788";

const isPagesDev =
  typeof window !== "undefined" &&
  /(?:^|\.)pages\.dev$/i.test(window.location.hostname);

// Cloudflare Pages is a public demo: its browser cannot reach localhost. Keep
// the localhost URLs above as local overrides, but default Pages to API mocks
// when a production build forgot to provide an explicit setting.
const configuredApiMocks =
  import.meta.env.VITE_USE_API_MOCKS ?? import.meta.env.VITE_USE_MOCKS;

export const USE_API_MOCKS =
  configuredApiMocks === undefined
    ? isPagesDev
    : configuredApiMocks.toLowerCase() === "true";

// Backwards-compatible alias for API modules that still use the old name.
export const USE_MOCKS = USE_API_MOCKS;

// API demo mode and wallet connectivity are intentionally separate. Pages
// ships mock API data while still allowing real Pera/Defly connections.
export const WALLET_MOCKS =
  (import.meta.env.VITE_WALLET_MOCKS ?? "false").toLowerCase() === "true";
