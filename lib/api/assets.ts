import { getAssets } from "@/lib/api/service";
import type { AssetInventoryResponse, BusinessCriticality, CompanyAsset } from "@/lib/types/asset";

export async function fetchAssetInventory(): Promise<AssetInventoryResponse> {
  const response = await getAssets();
  const matchesByAsset = new Map<string, typeof response.matches>();
  response.matches.forEach((match) => matchesByAsset.set(match.assetId, [...(matchesByAsset.get(match.assetId) ?? []), match]));
  const assets: CompanyAsset[] = response.assets.map((asset) => ({ id: asset.assetId, name: asset.name, vendor: asset.vendor ?? "Unknown vendor", product: asset.product ?? "Unknown product", version: asset.version ?? "Unknown", environment: asset.environment === "Development" ? "Development" : "Production", internetExposed: asset.internetExposed ?? false, criticality: (asset.businessCriticality === "Unknown" ? "Low" : asset.businessCriticality) as BusinessCriticality, ownerTeam: asset.owner ?? "Unassigned", matches: (matchesByAsset.get(asset.assetId) ?? []).map((match) => ({ cveId: match.cveId, status: match.matchStatus, reason: match.supportingEvidence.join(" ") || "No supporting evidence supplied.", predictedRisk: match.predictedRisk === "Critical" || match.predictedRisk === "High" || match.predictedRisk === "Elevated" || match.predictedRisk === "Moderate" ? match.predictedRisk : "Moderate" })) }));
  return { assets, source: response.source === "demo" ? "simulated" : "api", organizationLabel: response.organizationLabel ?? "Unknown organization" };
}
