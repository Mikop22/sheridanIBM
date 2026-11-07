export type AssetEnvironment = "Production" | "Development";
export type BusinessCriticality = "Critical" | "High" | "Medium" | "Low";
export type VulnerabilityMatchStatus = "Confirmed" | "Possible" | "Unknown";

export interface AssetVulnerabilityMatch {
  cveId: string;
  status: VulnerabilityMatchStatus;
  reason: string;
  predictedRisk: "Critical" | "High" | "Elevated" | "Moderate";
}

export interface CompanyAsset {
  id: string;
  name: string;
  vendor: string;
  product: string;
  version: string;
  environment: AssetEnvironment;
  internetExposed: boolean;
  criticality: BusinessCriticality;
  ownerTeam: string;
  matches: AssetVulnerabilityMatch[];
}

export interface AssetInventoryResponse {
  assets: CompanyAsset[];
  source: "simulated" | "api";
  organizationLabel: string;
}
