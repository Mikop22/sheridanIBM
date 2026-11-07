import { getOverview, getVulnerability, getVulnerabilities } from "@/lib/api/service";
import type { Priority, Vulnerability } from "@/lib/types/vulnerability";

function toPriority(value: string | null): Priority {
  if (value === "Critical" || value === "High" || value === "Medium" || value === "Low") return value;
  return value === "Elevated" ? "Medium" : "Low";
}

function toViewModel(item: Awaited<ReturnType<typeof getVulnerabilities>>["vulnerabilities"][number]): Vulnerability {
  return { id: item.cveId, title: item.description, asset: item.affectedAsset?.name ?? "Unknown asset", service: item.affectedAsset?.service ?? "Unknown service", cvss: item.cvss ?? 0, epss: item.epss ?? 0, priority: toPriority(item.predictedRisk), detected: item.detectedAt ?? "Unknown" };
}

export async function fetchVulnerabilityOverview(): Promise<Vulnerability[]> {
  const response = await getOverview();
  return response.priorityVulnerabilities.map(toViewModel);
}

export async function fetchVulnerabilities(): Promise<Vulnerability[]> {
  const response = await getVulnerabilities();
  return response.vulnerabilities.map(toViewModel);
}

export { getVulnerability };
