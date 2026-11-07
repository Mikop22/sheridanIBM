import type { JiraAdapter, JiraTicketPayload, SlackAdapter, SlackNotificationPayload } from "@/lib/integrations/types";

/** Client-safe demo adapters. They never contact Slack or Jira and never accept credentials. */
export const mockSlackAdapter: SlackAdapter = {
  async sendVulnerabilityAlert(payload: SlackNotificationPayload) {
    void payload;
    return { mode: "simulated", provider: "slack", status: "simulated-not-sent", message: "Demo mode: Slack delivery was not attempted.", attemptedAt: null, deliveredAt: null, externalId: null, externalUrl: null, errorCode: null, errorMessage: null };
  },
};

const simulatedTicketKeys = new Set<string>();

export const mockJiraAdapter: JiraAdapter = {
  async createOrUpdateInvestigation(payload: JiraTicketPayload) {
    const duplicate = simulatedTicketKeys.has(payload.dedupeKey);
    simulatedTicketKeys.add(payload.dedupeKey);
    return { mode: "simulated", provider: "jira", status: "simulated-not-sent", message: duplicate ? "Demo mode: an existing ticket would be updated using the CVE + asset key." : "Demo mode: ticket creation was not attempted.", attemptedAt: null, deliveredAt: null, externalId: null, externalUrl: null, errorCode: null, errorMessage: null };
  },
};

export function createAlertDedupeKey(cveId: string, assetId: string) {
  return `${cveId.trim().toUpperCase()}::${assetId.trim().toUpperCase()}`;
}
