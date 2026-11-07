import { getAlerts } from "@/lib/api/service";
import type { DeliveryStatus, JiraStatus, VulnerabilityAlert } from "@/lib/types/alert";

function slackStatus(value: string): DeliveryStatus { return value === "delivered" ? "Delivered" : value === "failed" ? "Failed" : value === "pending" ? "Pending" : "Not attempted"; }
function jiraStatus(value: string): JiraStatus { return value === "delivered" ? "Created" : value === "failed" ? "Failed" : "Not attempted"; }

export async function fetchAlertActivity() {
  const response = await getAlerts();
  const alerts: VulnerabilityAlert[] = response.alerts.map((alert) => ({ id: alert.alertId, cveId: alert.cveId, assetId: alert.assetId, assetName: alert.assetName ?? "Unknown asset", priority: alert.priority, triggerReason: alert.triggerReason, timestamp: alert.updatedAt, slackStatus: slackStatus(alert.slackDelivery.status), jiraStatus: jiraStatus(alert.jiraDelivery.status), jiraKey: alert.jiraDelivery.externalId, jiraUrl: alert.jiraDelivery.externalUrl, lifecycle: alert.lifecycle, occurrenceCount: alert.occurrenceCount, evidence: alert.evidence, history: alert.history, dedupeKey: alert.dedupeKey, simulated: alert.simulated }));
  return { alerts, source: response.source === "demo" ? "simulated" as const : "api" as const };
}
