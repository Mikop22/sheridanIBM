import { NextResponse } from "next/server";
import {
  DEFAULT_SCENARIOS,
  findingKeyForScenario,
  type SimulationStepResponse,
} from "@/lib/api/simulations";

const STAGE_LABELS: Record<number, string> = {
  1: "Threat detected",
  2: "Asset identified",
  3: "Slack notification",
  4: "Jira issue created or updated",
  5: "Coding agent + Entire checkpoint",
  6: "Draft GitHub PR updated",
  7: "Automated verification tests",
  8: "Awaiting human approval",
};

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
  const scenario =
    DEFAULT_SCENARIOS.find((item) => item.id === scenarioId) ?? DEFAULT_SCENARIOS[0];
  const findingKey = findingKeyForScenario(scenario.id);
  const prNumber =
    scenario.id === "gateway_auth"
      ? 3
      : scenario.id === "code_patch"
        ? 2
        : scenario.id === "dependency_upgrade"
          ? 1
          : null;
  const prUrl = prNumber ? `https://github.com/Mikop22/securitydemo/pull/${prNumber}` : null;
  const commitSha =
    scenario.id === "gateway_auth"
      ? "0b68ade"
      : scenario.id === "code_patch"
        ? "0696418"
        : scenario.id === "dependency_upgrade"
          ? "ba6cbd2"
          : null;
  const commitUrl = commitSha
    ? `https://github.com/Mikop22/securitydemo/commit/${commitSha}`
    : null;
  const checkpointId =
    scenario.id === "gateway_auth"
      ? "bb97da379501"
      : scenario.id === "code_patch"
        ? "39b0a47abb14"
        : null;
  const jiraKey =
    scenario.id === "appliance_kev"
      ? "SEC-22"
      : scenario.id === "dependency_upgrade"
        ? "SEC-24"
        : scenario.id === "unmatched_guardrail"
          ? null
          : "SEC-25";

  const payload: SimulationStepResponse = {
    scenarioId: scenario.id,
    findingKey,
    cveId: scenario.cveId,
    stage,
    stageLabel: STAGE_LABELS[stage] ?? `Stage ${stage}`,
    status:
      scenario.id === "unmatched_guardrail" && stage >= 2
        ? "Unavailable"
        : scenario.id === "appliance_kev" && stage >= 5 && stage <= 7
          ? "Manual path"
          : stage === 8
            ? "Pending"
            : "Succeeded",
    detail: scenario.summary,
    jiraKey: stage === 4 || stage === 8 ? jiraKey : null,
    jiraUrl:
      (stage === 4 || stage === 8) && jiraKey
        ? `https://securitydemo.atlassian.net/browse/${jiraKey}`
        : null,
    prUrl: stage >= 6 ? prUrl : null,
    prNumber: stage >= 6 ? prNumber : null,
    entireCheckpointId: stage === 5 || stage === 6 ? checkpointId : null,
    commitSha: stage === 5 || stage === 6 ? commitSha : null,
    commitUrl: stage === 5 || stage === 6 ? commitUrl : null,
  };
  return NextResponse.json(payload);
}
