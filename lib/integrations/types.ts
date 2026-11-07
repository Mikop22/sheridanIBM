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

export interface IntegrationResult {
  mode: "simulated";
  status: "simulated-not-sent";
  message: string;
  externalId: null;
}

export interface SlackAdapter { sendVulnerabilityAlert(payload: SlackNotificationPayload): Promise<IntegrationResult>; }
export interface JiraAdapter { createOrUpdateInvestigation(payload: JiraTicketPayload): Promise<IntegrationResult>; }
