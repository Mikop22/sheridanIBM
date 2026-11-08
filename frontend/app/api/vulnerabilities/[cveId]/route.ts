import { NextResponse } from "next/server";
import liveSnapshot from "@/lib/data/live-snapshot.json";

export async function GET(
  _request: Request,
  context: { params: Promise<{ cveId: string }> },
) {
  const { cveId } = await context.params;
  const match = liveSnapshot.vulnerabilities.vulnerabilities.find(
    (item) => item.cveId.toUpperCase() === cveId.toUpperCase(),
  );
  if (!match) {
    return NextResponse.json(
      {
        error: {
          code: "not_found",
          message: `Vulnerability ${cveId} not found.`,
          details: null,
        },
      },
      { status: 404 },
    );
  }
  return NextResponse.json({
    vulnerability: match,
    source: "live",
  });
}
