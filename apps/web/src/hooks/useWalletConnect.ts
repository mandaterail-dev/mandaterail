import { useCallback, useMemo, useState } from "react";
import { useWallet, WalletId, type Wallet } from "@txnlab/use-wallet-react";
import { WALLET_MOCKS } from "../api/config";
import { DEMO_PRINCIPAL } from "../lib/fixtures";

/** Display-only labels if manager wallets are not yet ready under mocks. */
const MOCK_PICKER_LABELS: { id: WalletId; name: string }[] = [
  { id: WalletId.PERA, name: "Pera" },
  { id: WalletId.DEFLY, name: "Defly" },
  { id: WalletId.DEFLY_WEB, name: "Defly Web" },
  { id: WalletId.LUTE, name: "Lute" },
  { id: WalletId.EXODUS, name: "Exodus" },
  { id: WalletId.KIBISIS, name: "Kibisis" },
];

export type WalletConnectState = {
  connected: boolean;
  address: string | null;
  providerName: string | null;
  /** Opens the Connect picker (does not auto-chain wallets). */
  connect: () => void | Promise<void>;
  disconnect: () => void | Promise<void>;
  /** Whether the wallet manager finished initializing. */
  isReady: boolean;
  pickerOpen: boolean;
  closePicker: () => void;
  /** Wallets to list in the picker (from useWallet().wallets). */
  pickerWallets: Wallet[];
  selectWallet: (wallet: Wallet) => Promise<void>;
  connectError: string | null;
  connecting: boolean;
};

/**
 * Display-identity multi-wallet connect via WalletPicker.
 * Deletes Pera→Defly auto-chain: the user chooses an explicit wallet.
 * When VITE_WALLET_MOCKS=true, the six registered wallets are still listed;
 * choosing any yields DEMO_PRINCIPAL with providerName exactly "Mock".
 * Never surfaces mnemonics; mandate signing remains AC2 / OperatorAuth.
 */
export function useWalletConnect(): WalletConnectState {
  const { wallets, activeAddress, activeWallet, isReady } = useWallet();

  const [stubAddress, setStubAddress] = useState<string | null>(null);
  const [pickerOpen, setPickerOpen] = useState(false);
  const [connectError, setConnectError] = useState<string | null>(null);
  const [connecting, setConnecting] = useState(false);


  const pickerWallets = useMemo(() => {
    if (wallets.length > 0) return wallets;
    if (!WALLET_MOCKS) return wallets;
    // Rare: manager not ready yet — still show six so mocks keep the picker UX.
    return MOCK_PICKER_LABELS.map(
      ({ id, name }) =>
        ({
          id,
          walletKey: id,
          metadata: { name, icon: "" },
          accounts: [],
          activeAccount: null,
          isConnected: false,
          isActive: false,
          canSignData: false,
          canUsePrivateKey: false,
          connect: async () => [],
          disconnect: async () => undefined,
          setActive: () => undefined,
          setActiveAccount: () => undefined,
        }) as Wallet,
    );
  }, [wallets]);

  const connect = useCallback(() => {
    setConnectError(null);
    setPickerOpen(true);
  }, []);

  const closePicker = useCallback(() => {
    if (connecting) return;
    setPickerOpen(false);
  }, [connecting]);

  const selectWallet = useCallback(async (wallet: Wallet) => {
    setConnectError(null);
    setConnecting(true);
    try {
      if (WALLET_MOCKS) {
        setStubAddress(DEMO_PRINCIPAL);
        setPickerOpen(false);
        return;
      }
      await wallet.connect();
      setPickerOpen(false);
    } catch (e) {
      const message =
        e instanceof Error
          ? e.message
          : typeof e === "string"
            ? e
            : "Wallet connect failed.";
      setConnectError(message);
      throw e instanceof Error ? e : new Error(message);
    } finally {
      setConnecting(false);
    }
  }, []);

  const disconnect = useCallback(async () => {
    setConnectError(null);
    if (WALLET_MOCKS) {
      setStubAddress(null);
      return;
    }
    if (activeWallet) {
      await activeWallet.disconnect();
    }
  }, [activeWallet]);

  if (WALLET_MOCKS) {
    return {
      connected: Boolean(stubAddress),
      address: stubAddress,
      providerName: stubAddress ? "Mock" : null,
      connect,
      disconnect,
      isReady: true,
      pickerOpen,
      closePicker,
      pickerWallets,
      selectWallet,
      connectError,
      connecting,
    };
  }

  return {
    connected: Boolean(activeAddress),
    address: activeAddress ?? null,
    providerName: activeWallet?.metadata?.name ?? null,
    connect: isReady ? connect : () => undefined,
    disconnect,
    isReady,
    pickerOpen,
    closePicker,
    pickerWallets,
    selectWallet,
    connectError,
    connecting,
  };
}
