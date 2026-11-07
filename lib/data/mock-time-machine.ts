import type { HistoricalSnapshot, HistoricalVulnerability, RiskLevel } from "@/lib/types/time-machine";
import { supportedReplayMonths } from "@/lib/config/replay";

const baseVulnerabilities: HistoricalVulnerability[] = [
  { id: "CVE-2024-21412", description: "Internet shortcut file security feature bypass", cvss: 8.1, epss: 0.71, modelRank: 1, predictedRisk: "Critical", outcome: "confirmed-kev", kevAddedDate: "2024-02-13", signals: [{ label: "Exploit chatter", value: "Rising", detail: "Simulated increase in public exploit discussion before the snapshot cutoff." }, { label: "Attack surface", value: "Broad", detail: "Common desktop configuration with user-interaction exposure." }, { label: "Vendor activity", value: "Active", detail: "Recent advisory and patch activity available by the prediction cutoff." }] },
  { id: "CVE-2024-1709", description: "Authentication bypass in remote management software", cvss: 10, epss: 0.84, modelRank: 2, predictedRisk: "Critical", outcome: "confirmed-kev", kevAddedDate: "2024-02-22", signals: [{ label: "Exposure", value: "Internet-facing", detail: "Simulated asset prevalence indicates remotely accessible deployments." }, { label: "Exploitability", value: "Low complexity", detail: "Attack prerequisites were assessed as limited at snapshot time." }, { label: "Momentum", value: "Accelerating", detail: "Simulated security-community attention increased week over week." }] },
  { id: "CVE-2024-23897", description: "Arbitrary file read through command parser", cvss: 9.8, epss: 0.63, modelRank: 3, predictedRisk: "High", outcome: "not-kev-by-cutoff", kevAddedDate: null, signals: [{ label: "Exploit maturity", value: "Proof of concept", detail: "Public technical material was available before the cutoff." }, { label: "Asset relevance", value: "High", detail: "Commonly used in software delivery infrastructure." }, { label: "Uncertainty", value: "Medium", detail: "Observed exploitation was not confirmed by the evaluation cutoff." }] },
  { id: "CVE-2024-21619", description: "Improper input validation in identity component", cvss: 7.5, epss: 0.34, modelRank: 4, predictedRisk: "Elevated", outcome: "not-kev-by-cutoff", kevAddedDate: null, signals: [{ label: "Identity impact", value: "Material", detail: "Potential impact to authentication flows raised the model score." }, { label: "Telemetry", value: "Sparse", detail: "Limited exploitation evidence was available at prediction time." }] },
  { id: "CVE-2024-22024", description: "Server-side request forgery in gateway appliance", cvss: 9.1, epss: null, modelRank: 5, predictedRisk: "High", outcome: "missing", kevAddedDate: null, signals: [{ label: "Perimeter role", value: "High", detail: "The affected component commonly sits at a trust boundary." }, { label: "EPSS", value: "Unavailable", detail: "EPSS was missing in this simulated historical snapshot." }, { label: "Data quality", value: "Partial", detail: "The prediction used available metadata only." }] },
  { id: "CVE-2024-25600", description: "Unauthenticated template injection in web framework", cvss: 9.8, epss: 0.42, modelRank: 6, predictedRisk: "Moderate", outcome: "not-kev-by-cutoff", kevAddedDate: null, signals: [{ label: "Exploitability", value: "Plausible", detail: "Technical conditions suggested practical exploitation." }, { label: "Prevalence", value: "Uncertain", detail: "Deployment prevalence was incomplete at snapshot time." }] },
];

function rotateRisk(risk: RiskLevel, offset: number): RiskLevel {
  const risks: RiskLevel[] = ["Critical", "High", "Elevated", "Moderate"];
  return risks[(risks.indexOf(risk) + offset) % risks.length];
}

// SIMULATED DATA: values are for UI development and are not model-performance claims.
export function createMockSnapshot(month: string): HistoricalSnapshot {
  const monthMeta = supportedReplayMonths.find((item) => item.value === month) ?? supportedReplayMonths[0];
  const monthIndex = supportedReplayMonths.findIndex((item) => item.value === monthMeta.value);
  const predictionDate = new Date(`${monthMeta.value}-01T00:00:00Z`);
  predictionDate.setUTCMonth(predictionDate.getUTCMonth() + 1);
  predictionDate.setUTCDate(0);
  const evaluationDate = new Date(predictionDate);
  evaluationDate.setUTCMonth(evaluationDate.getUTCMonth() + 3);
  const vulnerabilities = baseVulnerabilities.map((item, index) => ({ ...item, modelRank: index + 1, predictedRisk: rotateRisk(item.predictedRisk, (monthIndex + index) % 4 === 0 ? 1 : 0), epss: item.epss === null ? null : Math.min(0.98, Math.max(0.04, item.epss + ((monthIndex % 5) - 2) * 0.025)) }));
  const metricShift = monthIndex % 7;
  return {
    month: monthMeta.value,
    label: monthMeta.label,
    predictionCutoff: predictionDate.toISOString().slice(0, 10),
    evaluationCutoff: evaluationDate.toISOString().slice(0, 10),
    vulnerabilities,
    metrics: [
      { method: "SignalZero", hitsAt500: 318 + metricShift, note: "Simulated demo value — not a measured model result." },
      { method: "CVSS baseline", hitsAt500: 251 + metricShift, note: "Simulated demo baseline." },
      { method: "EPSS baseline", hitsAt500: 276 + metricShift, note: "Simulated demo baseline." },
    ],
    source: "simulated",
  };
}
