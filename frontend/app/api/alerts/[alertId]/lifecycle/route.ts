import { NextResponse } from "next/server";
import { proxyBackendJson } from "@/lib/api/upstream";

export async function POST(
  request: Request,
  context: { params: Promise<{ alertId: string }> },
) {
  const { alertId } = await context.params;
  const body = (await request.json().catch(() => ({}))) as { lifecycle?: string };
  const upstream = await proxyBackendJson(
    `/api/alerts/${encodeURIComponent(alertId)}/lifecycle`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    },
  );
  return NextResponse.json(
    upstream ?? {
      alertId,
      lifecycle: body.lifecycle ?? "Resolved",
    },
  );
}
