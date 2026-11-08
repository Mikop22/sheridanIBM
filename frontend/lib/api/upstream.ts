const DEFAULT_UPSTREAM_BACKEND = "https://educators-foam-kiss-austin.trycloudflare.com";

export function getUpstreamBackendUrl(): string {
  const configured = process.env.SIGNALZERO_UPSTREAM_BACKEND_URL?.trim();
  return (configured || DEFAULT_UPSTREAM_BACKEND).replace(/\/$/, "");
}

export async function proxyBackendJson(
  path: string,
  init?: RequestInit,
  timeoutMs = 20000,
): Promise<unknown | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`${getUpstreamBackendUrl()}${path}`, {
      ...init,
      headers: {
        Accept: "application/json",
        ...(init?.headers ?? {}),
      },
      cache: "no-store",
      signal: controller.signal,
    });
    if (!response.ok) return null;
    return await response.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
