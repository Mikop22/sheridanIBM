import { mockAlerts } from "@/lib/data/mock-alerts";
import type { AlertActivityResponse } from "@/lib/types/alert";

/** Replace with the teammate-owned alert activity endpoint when available. */
export async function fetchAlertActivity(): Promise<AlertActivityResponse> {
  await new Promise((resolve) => setTimeout(resolve, 260));
  return { alerts: structuredClone(mockAlerts), source: "simulated" };
}
