import { getVulnerabilities } from "@/lib/api/service";
import type { HiddenThreat, HiddenThreatResponse, HiddenThreatRisk } from "@/lib/types/hidden-threat";

function toRisk(value: string | null): HiddenThreatRisk {
  return value === "Critical" || value === "High" || value === "Elevated" ? value : "Unknown";
}

export async function fetchHiddenThreats(): Promise<HiddenThreatResponse> {
  const response = await getVulnerabilities();
  const threats: HiddenThreat[] = response.vulnerabilities.map((item) => ({
    id: item.cveId,
    description: item.description ?? "Description unavailable",
    cvss: item.cvss,
    epss: item.epss,
    modelRank: item.modelRank,
    rankingScore: item.rankingScore,
    traditionalRank: item.traditionalRank,
    predictedRisk: toRisk(item.predictedRisk),
    affectedProduct: item.affectedAsset?.name ?? null,
    affectedAssetId: item.affectedAsset?.id ?? null,
    affectedService: item.affectedAsset?.service ?? null,
    signals: item.evidenceIndicators.map((signal) => ({
      label: signal.label,
      value: String(signal.value ?? "Unknown"),
      explanation: signal.explanation ?? "No explanation supplied.",
      source: signal.source,
      status: signal.status,
      observedAt: signal.observedAt,
    })),
  }));
  return {
    threats,
    generatedAt: response.generatedAt ?? new Date().toISOString(),
    source: response.source === "demo" ? "simulated" : "api",
  };
}
