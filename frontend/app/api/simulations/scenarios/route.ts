import { NextResponse } from "next/server";
import { DEFAULT_SCENARIOS } from "@/lib/api/simulations";

export async function GET() {
  return NextResponse.json(DEFAULT_SCENARIOS);
}
