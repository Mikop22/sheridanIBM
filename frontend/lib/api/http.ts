import type { z } from "zod";
import { apiErrorResponseSchema } from "@/lib/types/contracts";
import { getApiBaseUrl } from "@/lib/api/config";

export class SignalZeroApiError extends Error {
  constructor(message: string, public readonly status: number | null, public readonly code: string, public readonly details: unknown = null) {
    super(message);
    this.name = "SignalZeroApiError";
  }
}

export async function fetchValidated<T>(path: string, schema: z.ZodType<T>, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${getApiBaseUrl()}${path}`, { ...init, headers: { Accept: "application/json", ...init?.headers } });
  } catch (error) {
    throw new SignalZeroApiError(error instanceof Error ? error.message : "Backend request failed.", null, "network_error");
  }

  let payload: unknown;
  try { payload = await response.json(); } catch { throw new SignalZeroApiError("Backend returned a non-JSON response.", response.status, "invalid_json"); }
  if (!response.ok) {
    const parsedError = apiErrorResponseSchema.safeParse(payload);
    throw new SignalZeroApiError(parsedError.success ? parsedError.data.error.message : `Backend request failed with status ${response.status}.`, response.status, parsedError.success ? parsedError.data.error.code : "http_error", parsedError.success ? parsedError.data.error.details : payload);
  }
  const parsed = schema.safeParse(payload);
  if (!parsed.success) throw new SignalZeroApiError("Backend response did not match the SignalZero API contract.", response.status, "response_validation_error", parsed.error.flatten());
  return parsed.data;
}
