export type HiddenThreatRisk = "Critical" | "High" | "Elevated" | "Unknown";

export interface HiddenThreat {
  id: string;
  description: string;
  cvss: number | null;
  epss: number | null;
  modelRank: number | null;
  traditionalRank: number | null;
  predictedRisk: HiddenThreatRisk;
  affectedProduct: string | null;
  signals: Array<{ label: string; value: string; explanation: string }>;
}

export interface HiddenThreatResponse {
  threats: HiddenThreat[];
  generatedAt: string;
  source: "simulated" | "api";
}
