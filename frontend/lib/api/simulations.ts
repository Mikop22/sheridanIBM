import { getApiBaseUrl } from "@/lib/api/config";

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
