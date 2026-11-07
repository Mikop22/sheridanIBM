import { getAssets } from "@/lib/api/service";
import type { AssetInventoryResponse, CompanyAsset } from "@/lib/types/asset";

export async function fetchAssetInventory(): Promise<AssetInventoryResponse> {
  const response = await getAssets();
  const matchesByAsset = new Map<string, typeof response.matches>();
  response.matches.forEach((match) => matchesByAsset.set(match.assetId, [...(matchesByAsset.get(match.assetId) ?? []), match]));
  const assets: CompanyAsset[] = response.assets.map((asset) => ({ id: asset.assetId, name: asset.name, vendor: asset.vendor, product: asset.product, version: asset.version, environment: asset.environment, internetExposed: asset.internetExposed, criticality: asset.businessCriticality, ownerTeam: asset.owner, matches: (matchesByAsset.get(asset.assetId) ?? []).map((match) => ({ cveId: match.cveId, assetId: match.assetId, status: match.matchStatus, reason: match.supportingEvidence.join(" ") || "No supporting evidence supplied.", supportingEvidence: match.supportingEvidence, predictedRisk: match.predictedRisk === "Critical" || match.predictedRisk === "High" || match.predictedRisk === "Elevated" || match.predictedRisk === "Moderate" ? match.predictedRisk : null })) }));
  return { assets, source: response.source === "demo" ? "simulated" : "api", organizationLabel: response.organizationLabel };
}
