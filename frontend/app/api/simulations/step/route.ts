import { NextResponse } from "next/server";
import { proxyBackendJson } from "@/lib/api/upstream";

export async function POST(request: Request) {
  const body = (await request.json().catch(() => ({}))) as {
    scenarioId?: string;
    stage?: number;
  };
  const scenarioId = body.scenarioId ?? "code_patch";
  const stage = Number(body.stage ?? 1);
  if (!Number.isInteger(stage) || stage < 1 || stage > 8) {
    return NextResponse.json(
      { error: { code: "invalid_stage", message: "Stage must be 1..8", details: null } },
      { status: 400 },
    );
  }

  // Live pipeline stages (Slack / Jira / Entire / GitHub) must not fake success.
  // Slack CLI can take longer than a normal API read, so allow a wider timeout.
  const upstream = await proxyBackendJson(
    "/api/simulations/step",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenarioId, stage }),
    },
    60000,
  );
  if (upstream) {
    return NextResponse.json(upstream);
  }

  return NextResponse.json(
    {
      error: {
        code: "upstream_unavailable",
        message:
          "Live simulation backend is unreachable, so Slack/Jira/Entire/GitHub were not executed.",
        details: [{ scenarioId, stage }],
      },
    },
    { status: 502 },
  );
}
