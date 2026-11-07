import { getVulnerabilities } from "@/lib/api/service";
import type { HiddenThreat, HiddenThreatResponse, HiddenThreatRisk } from "@/lib/types/hidden-threat";

function toRisk(value: string | null): HiddenThreatRisk { return value === "Critical" || value === "High" ? value : "Elevated"; }

export async function fetchHiddenThreats(): Promise<HiddenThreatResponse> {
  const response = await getVulnerabilities();
  const threats: HiddenThreat[] = response.vulnerabilities.filter((item) => item.traditionalRank === null || item.traditionalRank > 500).filter((item) => item.modelRank !== null).map((item) => ({ id: item.cveId, description: item.description, cvss: item.cvss ?? 0, epss: item.epss ?? 0, modelRank: item.modelRank ?? Number.MAX_SAFE_INTEGER, traditionalRank: item.traditionalRank, predictedRisk: toRisk(item.predictedRisk), affectedProduct: item.affectedAsset?.name ?? "Unknown product", signals: item.evidenceIndicators.map((signal) => ({ label: signal.label, value: String(signal.value ?? "Unknown"), explanation: signal.explanation ?? "No explanation supplied." })) }));
  return { threats, generatedAt: response.generatedAt, source: response.source === "demo" ? "simulated" : "api" };
}
