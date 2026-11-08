import { NextResponse } from "next/server";
import liveSnapshot from "@/lib/data/live-snapshot.json";

export async function GET() {
  return NextResponse.json(liveSnapshot.vulnerabilities);
}
