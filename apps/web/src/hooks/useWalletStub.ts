import { useCallback, useState } from "react";
import { DEMO_PRINCIPAL } from "../lib/fixtures";

/**
 * Offline / CI wallet mock. Prefer useWalletConnect (respects VITE_WALLET_MOCKS).
 * No mnemonics; connect provides a display-identity session only.
 */
export function useWalletStub() {
  const [address, setAddress] = useState<string | null>(null);

  const connect = useCallback(() => {
    setAddress(DEMO_PRINCIPAL);
  }, []);

  const disconnect = useCallback(() => {
    setAddress(null);
  }, []);

  return {
    connected: Boolean(address),
    address,
    providerName: address ? "Mock" : null,
    connect,
    disconnect,
  };
}
