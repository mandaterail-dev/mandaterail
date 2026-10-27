/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_DEMO_API_URL: string;
  readonly VITE_AC2_BRIDGE_URL: string;
  readonly VITE_CONSOLE_API_URL: string;
  readonly VITE_USE_MOCKS: string;
  readonly VITE_USE_API_MOCKS: string;
  readonly VITE_WALLET_MOCKS: string;
  readonly VITE_WALLETCONNECT_PROJECT_ID: string;
  /** token-lab only (local TestNet). Never set on public Pages. */
  readonly VITE_AC2_OPERATOR_TOKEN?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
