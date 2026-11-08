import type { IntegrationDeliveryResultContract } from "@/lib/types/contracts";

export type AlertPriority = "Critical" | "High" | "Medium";
export type AlertLifecycle = "Open" | "Investigating" | "Resolved" | "Suppressed";
export type DeliveryStatus = "Delivered" | "Failed" | "Pending" | "Not attempted" | "Simulated — not sent" | "Unknown";
export type JiraStatus = "Created" | "Updated" | "Commented" | "Delivered" | "Failed" | "Pending" | "Not attempted" | "Simulated — not sent" | "Unknown";

export interface AlertActivityEvent {
  timestamp: string;
  label: string;
  detail: string;
  kind: "detection" | "delivery" | "ticket" | "status";
}

export interface VulnerabilityAlert {
  id: string;
  cveId: string;
  assetId: string;
  assetName: string;
  priority: AlertPriority;
  triggerReason: string;
  timestamp: string;
  slackStatus: DeliveryStatus;
  jiraStatus: JiraStatus;
  slackDelivery?: IntegrationDeliveryResultContract;
  jiraDelivery?: IntegrationDeliveryResultContract;
  jiraKey: string | null;
  jiraUrl: string | null;
  lifecycle: AlertLifecycle;
  occurrenceCount: number;
  evidence: string[];
  history: AlertActivityEvent[];
  dedupeKey: string;
  simulated: boolean;
}

export interface AlertActivityResponse {
  alerts: VulnerabilityAlert[];
  source: "simulated" | "api";
}
