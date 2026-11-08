export type ApiMode = "demo" | "live";

export function getApiMode(): ApiMode {
  return process.env.NEXT_PUBLIC_SIGNALZERO_API_MODE === "live" ? "live" : "demo";
}

export function isDemoMode() {
  return getApiMode() === "demo";
}

export function getApiBaseUrl() {
  const value = process.env.NEXT_PUBLIC_SIGNALZERO_API_BASE_URL?.trim();
  if (!value) throw new Error("NEXT_PUBLIC_SIGNALZERO_API_BASE_URL is required when NEXT_PUBLIC_SIGNALZERO_API_MODE=live.");
  return value.replace(/\/$/, "");
}
