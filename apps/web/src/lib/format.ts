export function shortAddress(addr: string | null | undefined, n = 4): string {
  if (!addr) return "—";
  if (addr.length <= n * 2 + 1) return addr;
  return `${addr.slice(0, n)}…${addr.slice(-n)}`;
}

export function formatTime(iso: string): string {
  try {
    return new Date(iso).toLocaleString("en-US", {
      timeZone: "America/New_York",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}
