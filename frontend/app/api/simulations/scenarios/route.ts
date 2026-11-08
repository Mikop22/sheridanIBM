import { NextResponse } from "next/server";
import { DEFAULT_SCENARIOS } from "@/lib/api/simulations";
import { proxyBackendJson } from "@/lib/api/upstream";

export async function GET() {
  const upstream = await proxyBackendJson("/api/simulations/scenarios");
  return NextResponse.json(upstream ?? DEFAULT_SCENARIOS);
}
