import {
  NetworkId,
  WalletId,
  WalletManager,
  type SupportedWallet,
  type WalletConnectOptions,
} from "@txnlab/use-wallet-react";

/**
 * Algorand TestNet wallet manager — multi-wallet Connect picker.
 *
 * Registered: Pera, Defly, Defly Web, Lute, Exodus, Kibisis.
 * Optional WalletConnect when VITE_WALLETCONNECT_PROJECT_ID is non-empty.
 * Never MAGIC / MNEMONIC / KMD / WEB3AUTH.
 *
 * Display identity only; IntentMandate signing stays on AC2 bridge / OperatorAuth.
 */
const wallets: SupportedWallet[] = [
  WalletId.PERA,
  WalletId.DEFLY,
  WalletId.DEFLY_WEB,
  { id: WalletId.LUTE, options: { siteName: "MandateRail" } },
  WalletId.EXODUS,
  WalletId.KIBISIS,
];

const wcProjectId = (import.meta.env.VITE_WALLETCONNECT_PROJECT_ID ?? "").trim();
if (wcProjectId) {
  // SDK docs accept projectId alone; modal fields are optional at runtime.
  wallets.push({
    id: WalletId.WALLETCONNECT,
    options: { projectId: wcProjectId } as WalletConnectOptions,
  });
}

export const walletManager = new WalletManager({
  wallets,
  defaultNetwork: NetworkId.TESTNET,
});
