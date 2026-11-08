import { getVulnerabilities } from "@/lib/api/service";
import type { HiddenThreat, HiddenThreatResponse, HiddenThreatRisk } from "@/lib/types/hidden-threat";

function toRisk(value: string | null): HiddenThreatRisk { return value === "Critical" || value === "High" || value === "Elevated" ? value : "Unknown"; }

export async function fetchHiddenThreats(): Promise<HiddenThreatResponse> {
  const response = await getVulnerabilities();
  // A missing baseline rank is unknown, not evidence that the CVE fell outside its top 500.
  const threats: HiddenThreat[] = response.vulnerabilities.filter((item) => item.modelRank !== null && item.traditionalRank !== null && item.traditionalRank > 500).map((item) => ({ id: item.cveId, description: item.description, cvss: item.cvss, epss: item.epss, modelRank: item.modelRank, traditionalRank: item.traditionalRank, predictedRisk: toRisk(item.predictedRisk), affectedProduct: item.affectedAsset?.name ?? null, signals: item.evidenceIndicators.map((signal) => ({ label: signal.label, value: String(signal.value ?? "Unknown"), explanation: signal.explanation ?? "No explanation supplied." })) }));
  return { threats, generatedAt: response.generatedAt, source: response.source === "demo" ? "simulated" : "api" };
}
