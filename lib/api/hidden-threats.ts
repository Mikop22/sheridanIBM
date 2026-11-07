import { mockHiddenThreats } from "@/lib/data/mock-hidden-threats";
import type { HiddenThreatResponse } from "@/lib/types/hidden-threat";

/** Replace with GET /hidden-threats when the FastAPI endpoint is available. */
export async function fetchHiddenThreats(): Promise<HiddenThreatResponse> {
  await new Promise((resolve) => setTimeout(resolve, 220));
  return { threats: mockHiddenThreats, generatedAt: "2026-11-07T00:00:00Z", source: "simulated" };
}
