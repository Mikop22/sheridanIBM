export type RiskLevel = "Critical" | "High" | "Elevated" | "Moderate";
export type OutcomeStatus = "confirmed-kev" | "not-kev-by-cutoff" | "missing";

export interface HistoricalVulnerability {
  id: string;
  description: string;
  cvss: number | null;
  epss: number | null;
  modelRank: number;
  predictedRisk: RiskLevel;
  signals: Array<{ label: string; value: string; detail: string }>;
  outcome: OutcomeStatus;
  kevAddedDate: string | null;
}

export interface HistoricalMetric {
  method: "SignalZero" | "CVSS baseline" | "EPSS baseline";
  hitsAt500: number | null;
  note: string;
}

export interface HistoricalSnapshot {
  month: string;
  label: string;
  predictionCutoff: string;
  evaluationCutoff: string;
  vulnerabilities: HistoricalVulnerability[];
  metrics: HistoricalMetric[];
  source: "simulated" | "api";
}
