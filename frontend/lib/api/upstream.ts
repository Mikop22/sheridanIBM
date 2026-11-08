const DEFAULT_UPSTREAM_BACKEND =
  "https://dakota-preparation-everywhere-gregory.trycloudflare.com";

function isVercelRuntime(): boolean {
  return process.env.VERCEL === "1" || process.env.NITRO_PRESET === "vercel";
}

export function getUpstreamBackendUrl(): string {
  const configured = process.env.SIGNALZERO_UPSTREAM_BACKEND_URL?.trim();
  if (configured) {
    return configured.replace(/\/$/, "");
  }
  // Local Next/Vinext should talk to FastAPI directly so Scenario lab can post Slack.
  if (!isVercelRuntime()) {
    return "http://127.0.0.1:8000";
  }
  return DEFAULT_UPSTREAM_BACKEND.replace(/\/$/, "");
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
