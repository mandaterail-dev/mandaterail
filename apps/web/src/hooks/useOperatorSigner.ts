import { useMemo } from "react";
import { ScopeType, useWallet } from "@txnlab/use-wallet-react";
import type { OperatorSigner } from "../api/operatorAuth";

/**
 * Builds an OperatorSigner from the connected wallet.
 * - Wallets with canSignData (Lute in use-wallet 4.6.0): ARC-60 signData.
 * - Others (Pera, Defly, Exodus, Kibisis…): manual fallback — operator signs
 *   the shown challenge offline with algosdk.signBytes and pastes base64.
 * Never touches key material.
 */
export function useOperatorSigner(): OperatorSigner | null {
  const { activeAddress, activeWallet, signData } = useWallet();
  return useMemo(() => {
    if (!activeAddress) return null;
    if (activeWallet?.canSignData) {
      return {
        address: activeAddress,
        signData: async (data: string) => {
          const r = await signData(data, { scope: ScopeType.AUTH, encoding: "base64" });
          return { signature: r.signature, authenticatorData: r.authenticatorData };
        },
      };
    }
    return {
      address: activeAddress,
      manualSign: async (message: string) =>
        window.prompt(
          `Your wallet cannot sign operator challenges. Sign this exact message offline with algosdk.signBytes using ${activeAddress} and paste the base64 signature (expires in ~2 min):\n\n${message}`,
        ),
    };
  }, [activeAddress, activeWallet, signData]);
}
