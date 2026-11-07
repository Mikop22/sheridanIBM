import { createMockSnapshot } from "@/lib/data/mock-time-machine";
import type { HistoricalSnapshot } from "@/lib/types/time-machine";

/** Replace this function with GET /historical-predictions?month=YYYY-MM when FastAPI is ready. */
export async function fetchHistoricalSnapshot(month: string): Promise<HistoricalSnapshot> {
  await new Promise((resolve) => setTimeout(resolve, 260));
  return createMockSnapshot(month);
}
