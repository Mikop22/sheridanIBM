export interface SlackNotificationPayload {
  cveId: string;
  affectedAsset: { id: string; name: string };
  riskReason: string;
  actionPriority: "Critical" | "High" | "Medium";
}

export interface JiraTicketPayload {
  title: string;
  cveId: string;
  evidence: string[];
  affectedAsset: { id: string; name: string };
  ownerTeam: string;
  recommendedInvestigation: string;
  dedupeKey: string;
}

import type { IntegrationDeliveryResultContract } from "@/lib/types/contracts";

export type IntegrationResult = IntegrationDeliveryResultContract & { mode: "simulated"; message: string };

export interface SlackAdapter { sendVulnerabilityAlert(payload: SlackNotificationPayload): Promise<IntegrationResult>; }
export interface JiraAdapter { createOrUpdateInvestigation(payload: JiraTicketPayload): Promise<IntegrationResult>; }
