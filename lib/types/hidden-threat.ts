export type HiddenThreatRisk = "Critical" | "High" | "Elevated";

export interface HiddenThreat {
  id: string;
  description: string;
  cvss: number;
  epss: number;
  modelRank: number;
  traditionalRank: number | null;
  predictedRisk: HiddenThreatRisk;
  affectedProduct: string;
  signals: Array<{ label: string; value: string; explanation: string }>;
}

export interface HiddenThreatResponse {
  threats: HiddenThreat[];
  generatedAt: string;
  source: "simulated" | "api";
}
