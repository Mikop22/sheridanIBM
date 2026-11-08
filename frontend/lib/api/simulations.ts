import { getApiBaseUrl } from "@/lib/api/config";
import type { AlertLifecycle } from "@/lib/types/alert";

export interface ScenarioCatalogItem {
  id: string;
  category: string;
  label: string;
  cveId: string;
  assetName: string;
  routeLabel: string;
  summary: string;
}

export interface SimulationStepResponse {
  scenarioId: string;
  findingKey: string;
  cveId: string;
  stage: number;
  stageLabel: string;
  status: string;
  detail: string;
  slackUrl?: string | null;
  jiraKey?: string | null;
  jiraUrl?: string | null;
  prUrl?: string | null;
  prNumber?: number | null;
  entireCheckpointId?: string | null;
  commitSha?: string | null;
  commitUrl?: string | null;
  verificationCommand?: string | null;
}

export const DEFAULT_SCENARIOS: ScenarioCatalogItem[] = [
  {
    id: "gateway_auth",
    category: "Gateway Auth Bypass (#1 Ranked CVE)",
    label: "ShareFile SZC Config Guard (CVE-2026-2699)",
    cveId: "CVE-2026-2699",
    assetName: "File gateway",
    routeLabel: "Jira Story · Entire CLI + Gateway Guard · GitHub Draft PR #3",
    summary:
      "Blocks unauthenticated access to restricted SZC config pages in gateway/szc_config_guard.py with an Entire checkpoint, runs check_gateway_fix.py, updates GitHub PR #3, and alerts Slack & Jira.",
  },
  {
    id: "code_patch",
    category: "First-Party Code Vulnerability",
    label: "Path Traversal in Config Loader (CVE-2026-22739)",
    cveId: "CVE-2026-22739",
    assetName: "Customer Portal config loader",
    routeLabel: "Jira Story · Entire CLI + Code Patch · GitHub Draft PR #2",
    summary:
      "Rewrites portal/config_loader.py with Entire checkpoint provenance, runs check_code_fix.py, updates GitHub PR #2, and alerts Slack & Jira.",
  },
  {
    id: "dependency_upgrade",
    category: "Open-Source Dependency Vulnerability",
    label: "Spring Cloud Config Server Pin Bump (CVE-2026-22739)",
    cveId: "CVE-2026-22739",
    assetName: "Customer Portal",
    routeLabel: "Jira Task · Entire CLI + Dependency Pin · GitHub Draft PR #1",
    summary:
      "Bumps spring-cloud-config-server 4.3.1 → 4.3.2 in pom.xml with an Entire checkpoint, runs check_version.py, updates GitHub PR #1, and alerts Slack & Jira.",
  },
  {
    id: "appliance_kev",
    category: "Managed Appliance / CISA KEV RCE",
    label: "Progress LoadMaster Unauthenticated RCE (CVE-2026-8037)",
    cveId: "CVE-2026-8037",
    assetName: "Edge load balancer",
    routeLabel: "Jira Highest Bug · Urgent KEV Slack · Manual Firmware Route",
    summary:
      "Escalates a CISA KEV network appliance vulnerability to Network Ops via Slack & Jira Bug SEC-22 while routing stages 5–7 to Manual Path.",
  },
  {
    id: "unmatched_guardrail",
    category: "Unmatched Asset Guardrail",
    label: "Missing Inventory Asset Edge Case (CVE-X)",
    cveId: "CVE-2026-9999",
    assetName: "Unknown asset",
    routeLabel: "Policy Guardrail · Halts Unverified Remediation",
    summary:
      "Demonstrates safe failure handling when a CVE has no matching company asset in the inventory.",
  },
];

const SCENARIO_FINDING_KEYS: Record<string, string> = {
  gateway_auth: "CVE-2026-2699::file-gateway",
  code_patch: "CVE-2026-22739::customer-portal-config-loader",
  dependency_upgrade: "CVE-2026-22739::customer-portal",
  appliance_kev: "CVE-2026-8037::edge-load-balancer",
  unmatched_guardrail: "CVE-X::missing-asset",
};

export function findingKeyForScenario(scenarioId: string): string {
  return SCENARIO_FINDING_KEYS[scenarioId] ?? "CVE-2026-22739::customer-portal";
}

export function scenarioIdForCve(
  cveId: string,
  affectedService?: string | null,
  affectedProduct?: string | null,
): string {
  const normalized = cveId.toUpperCase();
  if (normalized === "CVE-2026-2699") return "gateway_auth";
  if (normalized === "CVE-2026-8037") return "appliance_kev";
  if (normalized === "CVE-2026-22739") {
    const context = `${affectedService ?? ""} ${affectedProduct ?? ""}`.toLowerCase();
    if (context.includes("config_loader") || context.includes("config loader")) {
      return "code_patch";
    }
    return "dependency_upgrade";
  }
  return "gateway_auth";
}

export async function fetchSimulationScenarios(): Promise<ScenarioCatalogItem[]> {
  try {
    const response = await fetch(`${getApiBaseUrl()}/api/simulations/scenarios`, {
      headers: { Accept: "application/json" },
    });
    if (!response.ok) return DEFAULT_SCENARIOS;
    return (await response.json()) as ScenarioCatalogItem[];
  } catch {
    return DEFAULT_SCENARIOS;
  }
}

export async function executeSimulationStage(
  scenarioId: string,
  stage: number,
): Promise<SimulationStepResponse> {
  const response = await fetch(`${getApiBaseUrl()}/api/simulations/step`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({ scenarioId, stage }),
  });
  if (!response.ok) {
    throw new Error(`Simulation stage ${stage} failed with status ${response.status}.`);
  }
  return (await response.json()) as SimulationStepResponse;
}

export async function updateAlertLifecycle(
  alertId: string,
  lifecycle: AlertLifecycle,
): Promise<void> {
  try {
    await fetch(`${getApiBaseUrl()}/api/alerts/${encodeURIComponent(alertId)}/lifecycle`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ lifecycle }),
    });
  } catch {
    // Optimistic UI update still applies
  }
}
