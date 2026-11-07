import { mockAssets } from "@/lib/data/mock-assets";
import type { AssetInventoryResponse } from "@/lib/types/asset";

/** Replace with the teammate-owned asset inventory endpoint when available. */
export async function fetchAssetInventory(): Promise<AssetInventoryResponse> {
  await new Promise((resolve) => setTimeout(resolve, 240));
  return { assets: mockAssets, source: "simulated", organizationLabel: "Demo organization" };
}
