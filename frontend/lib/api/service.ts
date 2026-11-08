import { getApiMode } from "@/lib/api/config";
import { fetchValidated, SignalZeroApiError } from "@/lib/api/http";
import { mockAlerts } from "@/lib/data/mock-alerts";
import { mockAssets } from "@/lib/data/mock-assets";
import { mockHiddenThreats } from "@/lib/data/mock-hidden-threats";
import { mockVulnerabilities } from "@/lib/data/mock-vulnerabilities";
import {
  alertsResponseSchema,
  assetsResponseSchema,
  overviewResponseSchema,
  vulnerabilityDetailResponseSchema,
  vulnerabilityListResponseSchema,
  type AlertContract,
  type AlertsResponse,
  type AssetsResponse,
  type IntegrationDeliveryResultContract,
  type OverviewResponse,
  type VulnerabilityContract,
  type VulnerabilityDetailResponse,
  type VulnerabilityListResponse,
} from "@/lib/types/contracts";

function overviewMockToContract(item: (typeof mockVulnerabilities)[number]): VulnerabilityContract {
  return {
    cveId: item.id,
    description: item.title,
    snapshotMonth: item.snapshotMonth,
    cvss: item.cvss ?? null,
    epss: item.epss ?? null,
    modelRank: item.modelRank,
    rankingScore: item.rankingScore,
    rankingScoreKind: item.rankingScoreKind,
    traditionalRank: null,
    predictedRisk: item.priority === "Unknown" ? null : item.priority,
    evidenceIndicators: [],
    affectedAsset: { id: null, name: item.asset ?? "Unknown asset", service: item.service },
    detectedAt: item.detected ?? null,
  };
}

function hiddenMockToContract(item: (typeof mockHiddenThreats)[number]): VulnerabilityContract {
  return {
    cveId: item.id,
    description: item.description,
    snapshotMonth: null,
    cvss: item.cvss,
    epss: item.epss,
    modelRank: item.modelRank,
    rankingScore: null,
    rankingScoreKind: "relative",
    traditionalRank: item.traditionalRank,
    predictedRisk: item.predictedRisk,
    evidenceIndicators: item.signals.map((signal, index) => ({
      key: `signal-${index + 1}`,
      label: signal.label,
      value: signal.value,
      status: "present",
      observedAt: null,
      source: "simulated",
      explanation: signal.explanation,
    })),
    affectedAsset: { id: null, name: item.affectedProduct ?? "Unknown product", service: null },
    detectedAt: null,
  };
}

function delivery(
  provider: "slack" | "jira",
  status: string,
  timestamp: string,
  externalId: string | null,
  externalUrl: string | null,
): IntegrationDeliveryResultContract {
  const normalized =
    status === "Delivered" || status === "Created" || status === "Updated"
      ? "delivered"
      : status === "Failed"
        ? "failed"
        : status === "Pending"
          ? "pending"
          : "not-attempted";
  const operation =
    provider === "jira" && status === "Created"
      ? "created"
      : provider === "jira" && status === "Updated"
        ? "updated"
        : null;
  return {
    provider,
    status: normalized,
    operation,
    attemptedAt: normalized === "not-attempted" ? null : timestamp,
    deliveredAt: normalized === "delivered" ? timestamp : null,
    externalId,
    externalUrl,
    errorCode: normalized === "failed" ? "simulated_failure" : null,
    errorMessage: normalized === "failed" ? "Simulated historical delivery failure." : null,
  };
}

function alertMockToContract(item: (typeof mockAlerts)[number]): AlertContract {
  return {
    alertId: item.id,
    cveId: item.cveId,
    assetId: item.assetId,
    assetName: item.assetName,
    priority: item.priority,
    triggerReason: item.triggerReason,
    createdAt: item.history[item.history.length - 1]?.timestamp ?? item.timestamp,
    updatedAt: item.timestamp,
    slackDelivery: delivery("slack", item.slackStatus, item.timestamp, null, null),
    jiraDelivery: delivery("jira", item.jiraStatus, item.timestamp, item.jiraKey, item.jiraUrl),
    lifecycle: item.lifecycle,
    occurrenceCount: item.occurrenceCount,
    evidence: item.evidence,
    history: item.history,
    dedupeKey: item.dedupeKey,
    simulated: true,
  };
}

function demoVulnerabilities(): VulnerabilityContract[] {
  const combined = [
    ...mockVulnerabilities.map(overviewMockToContract),
    ...mockHiddenThreats.map(hiddenMockToContract),
  ];
  return Array.from(new Map(combined.map((item) => [item.cveId, item])).values());
}

export async function getOverview(): Promise<OverviewResponse> {
  if (getApiMode() === "live") return fetchValidated("/api/overview", overviewResponseSchema);
  const priorityVulnerabilities = mockVulnerabilities.map(overviewMockToContract);
  return overviewResponseSchema.parse({
    summary: {
      totalVulnerabilities: 1284,
      criticalPriority: 18,
      exposedAssets: 36,
      predictionHorizonDays: 30,
      inventoryMatches: priorityVulnerabilities.filter((item) => item.affectedAsset !== null).length,
      topModelRank: null,
    },
    priorityVulnerabilities,
    generatedAt: new Date().toISOString(),
    source: "demo",
  });
}

export async function getVulnerabilities(): Promise<VulnerabilityListResponse> {
  if (getApiMode() === "live") {
    return fetchValidated("/api/vulnerabilities", vulnerabilityListResponseSchema);
  }
  return vulnerabilityListResponseSchema.parse({
    vulnerabilities: demoVulnerabilities(),
    generatedAt: new Date().toISOString(),
    source: "demo",
  });
}

export async function getVulnerability(cveId: string): Promise<VulnerabilityDetailResponse> {
  if (getApiMode() === "live") {
    return fetchValidated(
      `/api/vulnerabilities/${encodeURIComponent(cveId)}`,
      vulnerabilityDetailResponseSchema,
    );
  }
  const vulnerability = demoVulnerabilities().find(
    (item) => item.cveId.toUpperCase() === cveId.toUpperCase(),
  );
  if (!vulnerability) {
    throw new SignalZeroApiError(`No demo vulnerability found for ${cveId}.`, 404, "not_found");
  }
  return vulnerabilityDetailResponseSchema.parse({ vulnerability, source: "demo" });
}

export async function getAssets(): Promise<AssetsResponse> {
  if (getApiMode() === "live") return fetchValidated("/api/assets", assetsResponseSchema);
  return assetsResponseSchema.parse({
    assets: mockAssets.map((asset) => ({
      assetId: asset.id,
      name: asset.name,
      vendor: asset.vendor,
      product: asset.product,
      version: asset.version,
      environment: asset.environment,
      internetExposed: asset.internetExposed,
      businessCriticality: asset.criticality,
      owner: asset.ownerTeam,
    })),
    matches: mockAssets.flatMap((asset) =>
      asset.matches.map((match) => ({
        cveId: match.cveId,
        assetId: asset.id,
        matchStatus: match.status,
        supportingEvidence: [match.reason],
        predictedRisk: match.predictedRisk,
      })),
    ),
    organizationLabel: "Demo organization",
    source: "demo",
  });
}

export async function getAlerts(): Promise<AlertsResponse> {
  if (getApiMode() === "live") return fetchValidated("/api/alerts", alertsResponseSchema);
  return alertsResponseSchema.parse({
    alerts: mockAlerts.map(alertMockToContract),
    source: "demo",
  });
}
