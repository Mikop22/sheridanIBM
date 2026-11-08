import { getOverview, getVulnerability, getVulnerabilities } from "@/lib/api/service";
import type { Priority, Vulnerability } from "@/lib/types/vulnerability";

function toPriority(value: string | null): Priority {
  if (value === "Critical" || value === "High" || value === "Medium" || value === "Low") return value;
  return value === "Elevated" || value === "Moderate" ? "Medium" : "Unknown";
}

function toViewModel(
  item: Awaited<ReturnType<typeof getVulnerabilities>>["vulnerabilities"][number],
): Vulnerability {
  return {
    id: item.cveId,
    title: item.description ?? "Description unavailable",
    asset: item.affectedAsset?.name ?? null,
    service: item.affectedAsset?.service ?? null,
    modelRank: item.modelRank,
    rankingScore: item.rankingScore,
    rankingScoreKind: item.rankingScoreKind,
    snapshotMonth: item.snapshotMonth,
    priority: toPriority(item.predictedRisk),
  };
}

export async function fetchVulnerabilityOverview() {
  const response = await getOverview();
  return {
    summary: response.summary,
    vulnerabilities: response.priorityVulnerabilities.map(toViewModel),
    generatedAt: response.generatedAt,
    source: response.source === "demo" ? ("simulated" as const) : ("api" as const),
  };
}

export async function fetchVulnerabilities(): Promise<Vulnerability[]> {
  const response = await getVulnerabilities();
  return response.vulnerabilities.map(toViewModel);
}

export { getVulnerability };
