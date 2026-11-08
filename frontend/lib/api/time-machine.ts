import { getReplay } from "@/lib/api/service";
import type { HistoricalSnapshot, OutcomeStatus, RiskLevel } from "@/lib/types/time-machine";

function toRisk(value: string): RiskLevel { return value === "Critical" || value === "High" || value === "Elevated" || value === "Moderate" ? value : "Moderate"; }

export async function fetchHistoricalSnapshot(month: string): Promise<HistoricalSnapshot> {
  const replay = await getReplay(month);
  const outcomes = new Map(replay.laterOutcomes.map((item) => [item.cveId, item]));
  return { month: replay.month, label: new Intl.DateTimeFormat("en-US", { month: "long", year: "numeric", timeZone: "UTC" }).format(new Date(`${replay.month}-01T00:00:00Z`)), predictionCutoff: replay.predictionSnapshot.featureCutoff, evaluationCutoff: replay.evaluationCutoff, vulnerabilities: replay.rankings.map((ranking) => { const outcome = outcomes.get(ranking.vulnerability.cveId); const status = outcome?.status === "unknown" || !outcome ? "missing" : outcome.status as OutcomeStatus; return { id: ranking.vulnerability.cveId, description: ranking.vulnerability.description, cvss: ranking.vulnerability.cvss, epss: ranking.vulnerability.epss, modelRank: ranking.rank, predictedRisk: toRisk(ranking.predictedRisk), signals: ranking.vulnerability.evidenceIndicators.map((signal) => ({ label: signal.label, value: String(signal.value ?? "Unknown"), detail: signal.explanation ?? "No detail supplied." })), outcome: status, kevAddedDate: outcome?.kevAddedAt ?? null }; }), metrics: replay.baselines.map((item) => ({ method: item.method === "CVSS baseline" || item.method === "EPSS baseline" ? item.method : "SignalZero", hitsAt500: item.hitsAt500, note: item.note ?? "No note supplied." })), source: replay.source === "demo" ? "simulated" : "api" };
}
