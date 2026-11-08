export type ApiMode = "demo" | "live";

export function getApiMode(): ApiMode {
  return process.env.NEXT_PUBLIC_SIGNALZERO_API_MODE === "demo" ? "demo" : "live";
}

export function isDemoMode() {
  return getApiMode() === "demo";
}

function isLoopbackUrl(url: string): boolean {
  return /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?(\/|$)/i.test(url);
}

export function getApiBaseUrl() {
  const value = process.env.NEXT_PUBLIC_SIGNALZERO_API_BASE_URL?.trim();
  if (!value) return "";
  if (
    typeof window !== "undefined" &&
    isLoopbackUrl(value) &&
    window.location.hostname !== "localhost" &&
    window.location.hostname !== "127.0.0.1"
  ) {
    return "";
  }
  return value.replace(/\/$/, "");
}
