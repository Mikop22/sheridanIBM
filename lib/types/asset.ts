export type AssetEnvironment = "Production" | "Development" | "Unknown";
export type BusinessCriticality = "Critical" | "High" | "Medium" | "Low" | "Unknown";
export type VulnerabilityMatchStatus = "Confirmed" | "Possible" | "Unknown";

export interface AssetVulnerabilityMatch {
  cveId: string;
  assetId?: string;
  status: VulnerabilityMatchStatus;
  /** Compatibility summary for existing demo records. */
  reason: string;
  supportingEvidence?: string[];
  predictedRisk: "Critical" | "High" | "Elevated" | "Moderate" | null;
}

export interface CompanyAsset {
  id: string;
  name: string;
  vendor: string | null;
  product: string | null;
  version: string | null;
  environment: AssetEnvironment;
  internetExposed: boolean | null;
  criticality: BusinessCriticality;
  ownerTeam: string | null;
  matches: AssetVulnerabilityMatch[];
}

export interface AssetInventoryResponse {
  assets: CompanyAsset[];
  source: "simulated" | "api";
  organizationLabel: string | null;
}
