import { NextResponse } from "next/server";
import { proxyBackendJson } from "@/lib/api/upstream";
import liveSnapshot from "@/lib/data/live-snapshot.json";

export async function GET() {
  const upstream = await proxyBackendJson("/api/vulnerabilities");
  return NextResponse.json(upstream ?? liveSnapshot.vulnerabilities);
}
