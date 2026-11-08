import { getAlerts } from "@/lib/api/service";
import type { DeliveryStatus, JiraStatus, VulnerabilityAlert } from "@/lib/types/alert";

function slackStatus(value: string): DeliveryStatus { return value === "delivered" ? "Delivered" : value === "failed" ? "Failed" : value === "pending" ? "Pending" : value === "not-attempted" ? "Not attempted" : value === "simulated-not-sent" ? "Simulated — not sent" : "Unknown"; }
function jiraStatus(status: string, operation: string | null): JiraStatus {
  if (status === "delivered") return operation === "created" ? "Created" : operation === "updated" ? "Updated" : operation === "commented" ? "Commented" : "Delivered";
  return status === "failed" ? "Failed" : status === "pending" ? "Pending" : status === "not-attempted" ? "Not attempted" : status === "simulated-not-sent" ? "Simulated — not sent" : "Unknown";
}

export async function fetchAlertActivity() {
  const response = await getAlerts();
  const alerts: VulnerabilityAlert[] = response.alerts.map((alert) => ({ id: alert.alertId, cveId: alert.cveId, assetId: alert.assetId, assetName: alert.assetName ?? "Unknown asset", priority: alert.priority, triggerReason: alert.triggerReason, timestamp: alert.updatedAt, slackStatus: slackStatus(alert.slackDelivery.status), jiraStatus: jiraStatus(alert.jiraDelivery.status, alert.jiraDelivery.operation), slackDelivery: alert.slackDelivery, jiraDelivery: alert.jiraDelivery, jiraKey: alert.jiraDelivery.externalId, jiraUrl: alert.jiraDelivery.externalUrl, lifecycle: alert.lifecycle, occurrenceCount: alert.occurrenceCount, evidence: alert.evidence, history: alert.history, dedupeKey: alert.dedupeKey, simulated: alert.simulated, repository: alert.repository ?? null, ownerTeam: alert.ownerTeam ?? null, prUrl: alert.prUrl ?? null, prNumber: alert.prNumber ?? null, prTitle: alert.prTitle ?? null, prBranch: alert.prBranch ?? null, checksPassed: alert.checksPassed ?? null, commitSha: alert.commitSha ?? null, commitUrl: alert.commitUrl ?? null, verificationCommand: alert.verificationCommand ?? null }));
  return { alerts, source: response.source === "demo" ? "simulated" as const : "api" as const };
}
