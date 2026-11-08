import { NextResponse } from "next/server";

export async function POST(
  request: Request,
  context: { params: Promise<{ alertId: string }> },
) {
  const { alertId } = await context.params;
  const body = (await request.json().catch(() => ({}))) as { lifecycle?: string };
  return NextResponse.json({
    alertId,
    lifecycle: body.lifecycle ?? "Resolved",
  });
}
