import { z } from "zod";

export const dataSourceSchema = z.enum(["demo", "live"]);
export const riskLevelSchema = z.enum(["Critical", "High", "Elevated", "Medium", "Moderate", "Low"]);

export const evidenceIndicatorSchema = z.object({
  key: z.string().min(1),
  label: z.string().min(1),
  value: z.union([z.string(), z.number(), z.boolean()]).nullable(),
  status: z.enum(["present", "absent", "unknown"]),
  observedAt: z.string().nullable(),
  source: z.string().nullable(),
  explanation: z.string().nullable(),
});

export const vulnerabilitySchema = z.object({
  cveId: z.string().min(1),
  description: z.string().min(1).nullable(),
  snapshotMonth: z.string().regex(/^\d{4}-\d{2}$/).nullable(),
  cvss: z.number().min(0).max(10).nullable(),
  epss: z.number().min(0).max(1).nullable(),
  modelRank: z.number().int().positive().nullable(),
  /** Relative ordering score only. It is not a calibrated exploitation probability. */
  rankingScore: z.number().nullable(),
  rankingScoreKind: z.enum(["relative", "unknown"]),
  traditionalRank: z.number().int().positive().nullable(),
  predictedRisk: riskLevelSchema.nullable(),
  evidenceIndicators: z.array(evidenceIndicatorSchema),
  affectedAsset: z.object({ id: z.string().nullable(), name: z.string(), service: z.string().nullable(), owner: z.string().nullable().optional() }).nullable(),
  detectedAt: z.string().nullable(),
  modelVersion: z.string().min(1).optional(),
  scoreScale: z.object({ minimum: z.number(), maximum: z.number(), higher_is_riskier: z.boolean() }).optional(),
  scoreInterpretation: z.string().min(1).optional(),
  componentScores: z.record(z.string(), z.number()).optional(),
  artifact: z.object({ artifactId: z.string().min(1), sourceKind: z.enum(["summary_json", "full_csv"]), recordCount: z.number().int().positive() }).optional(),
  missingInformation: z.array(z.string()).optional(),
  assetMatchStatus: z.enum(["confirmed_affected", "potentially_affected", "unknown", "confirmed_unaffected"]).optional(),
  investigationState: z.enum(["unreviewed", "monitoring", "investigating", "action_pending"]).optional(),
  operationalDecision: z.enum(["MONITOR", "INVESTIGATE", "ACTION_REQUIRED", "URGENT"]).optional(),
  decisionReasons: z.array(z.object({ code: z.string(), message: z.string(), sourceRefs: z.array(z.string()) })).optional(),
  assetDecisions: z.array(z.unknown()).optional(),
  remediationEligibility: z.enum(["CODE_REMEDIABLE", "OPERATIONAL_REMEDIATION", "NEEDS_INVESTIGATION", "NOT_ELIGIBLE"]).optional(),
  agentEligible: z.boolean().optional(),
  suggestedAction: z.string().nullable().optional(),
  groundedExplanation: z.unknown().optional(),
});

export const assetSchema = z.object({
  assetId: z.string().min(1),
  name: z.string().min(1),
  vendor: z.string().nullable(),
  product: z.string().nullable(),
  version: z.string().nullable(),
  environment: z.enum(["Production", "Development", "Unknown"]),
  internetExposed: z.boolean().nullable(),
  businessCriticality: z.enum(["Critical", "High", "Medium", "Low", "Unknown"]),
  owner: z.string().nullable(),
  repositoryIdentifier: z.string().nullable().optional(),
  componentPackage: z.string().nullable().optional(),
  synthetic: z.boolean().optional(),
});

export const assetVulnerabilityMatchSchema = z.object({
  cveId: z.string().min(1),
  assetId: z.string().min(1),
  matchStatus: z.enum(["Confirmed", "Possible", "Unknown", "Unaffected"]),
  canonicalMatchStatus: z.enum(["confirmed_affected", "potentially_affected", "unknown", "confirmed_unaffected"]).optional(),
  supportingEvidence: z.array(z.string()),
  predictedRisk: riskLevelSchema.nullable(),
  provenance: z.string().optional(),
});

export const integrationDeliveryResultSchema = z.object({
  provider: z.enum(["slack", "jira"]),
  status: z.enum(["not-attempted", "pending", "delivered", "failed", "simulated-not-sent"]),
  operation: z.enum(["created", "updated", "commented"]).nullable(),
  attemptedAt: z.string().nullable(),
  deliveredAt: z.string().nullable(),
  externalId: z.string().nullable(),
  externalUrl: z.string().nullable(),
  errorCode: z.string().nullable(),
  errorMessage: z.string().nullable(),
});

export const alertHistoryEventSchema = z.object({ timestamp: z.string(), label: z.string(), detail: z.string(), kind: z.enum(["detection", "delivery", "ticket", "status"]) });
export const alertSchema = z.object({
  alertId: z.string().min(1),
  cveId: z.string().min(1),
  assetId: z.string().min(1),
  assetName: z.string().nullable(),
  priority: z.enum(["Critical", "High", "Medium"]),
  triggerReason: z.string().min(1),
  createdAt: z.string(),
  updatedAt: z.string(),
  slackDelivery: integrationDeliveryResultSchema,
  jiraDelivery: integrationDeliveryResultSchema,
  lifecycle: z.enum(["Open", "Investigating", "Resolved", "Suppressed"]),
  occurrenceCount: z.number().int().positive(),
  evidence: z.array(z.string()),
  history: z.array(alertHistoryEventSchema),
  dedupeKey: z.string().min(1),
  simulated: z.boolean(),
  repository: z.string().nullable().optional(),
  ownerTeam: z.string().nullable().optional(),
  prUrl: z.string().nullable().optional(),
  prNumber: z.number().int().positive().nullable().optional(),
  prTitle: z.string().nullable().optional(),
  prBranch: z.string().nullable().optional(),
  checksPassed: z.boolean().nullable().optional(),
});

export const persistentDecisionSchema = z.object({
  recommendationId: z.string().min(1),
  findingId: z.string().min(1),
  cveId: z.string().min(1),
  assetId: z.string().min(1),
  operationalDecision: z.enum(["MONITOR", "INVESTIGATE", "ACTION_REQUIRED", "URGENT"]),
  workflowStatus: z.string().min(1),
  reasonCodes: z.array(z.string()),
  evidenceRefs: z.array(z.string()),
  remediationEligibility: z.enum(["CODE_REMEDIABLE", "OPERATIONAL_REMEDIATION", "NEEDS_INVESTIGATION", "NOT_ELIGIBLE"]),
  agentEligible: z.boolean(),
  executionAuthorized: z.literal(false),
  proposedNextAction: z.string().min(1),
  createdAt: z.string(),
  decidedAt: z.string().nullable(),
  decidedBy: z.string().nullable(),
  decisionReason: z.string().nullable(),
  activityHistory: z.array(z.object({ eventId: z.string(), processedAt: z.string(), reasonCode: z.string(), reusedRecommendation: z.boolean() })),
});

export const overviewResponseSchema = z.object({
  summary: z.object({
    totalVulnerabilities: z.number().int().nonnegative().nullable(),
    criticalPriority: z.number().int().nonnegative().nullable(),
    exposedAssets: z.number().int().nonnegative().nullable(),
    predictionHorizonDays: z.number().int().positive().nullable(),
    inventoryMatches: z.number().int().nonnegative().nullable(),
    topModelRank: z.number().int().positive().nullable(),
    draftPullRequests: z.number().int().nonnegative().nullable().optional(),
  }),
  priorityVulnerabilities: z.array(vulnerabilitySchema),
  generatedAt: z.string(),
  source: dataSourceSchema,
});
export const vulnerabilityListResponseSchema = z.object({ vulnerabilities: z.array(vulnerabilitySchema), generatedAt: z.string().nullable(), source: dataSourceSchema });
export const vulnerabilityDetailResponseSchema = z.object({ vulnerability: vulnerabilitySchema, source: dataSourceSchema });
export const assetsResponseSchema = z.object({ assets: z.array(assetSchema), matches: z.array(assetVulnerabilityMatchSchema), organizationLabel: z.string().nullable(), synthetic: z.boolean().optional(), provenance: z.string().optional(), source: dataSourceSchema });
export const alertsResponseSchema = z.object({ alerts: z.array(alertSchema), decisions: z.array(persistentDecisionSchema).optional().default([]), source: dataSourceSchema });
export const apiErrorResponseSchema = z.object({ error: z.object({ code: z.string(), message: z.string(), details: z.unknown().nullable().optional(), requestId: z.string().nullable().optional() }) });

export type DataSource = z.infer<typeof dataSourceSchema>;
export type EvidenceIndicator = z.infer<typeof evidenceIndicatorSchema>;
export type VulnerabilityContract = z.infer<typeof vulnerabilitySchema>;
export type AssetContract = z.infer<typeof assetSchema>;
export type AssetVulnerabilityMatchContract = z.infer<typeof assetVulnerabilityMatchSchema>;
export type AlertContract = z.infer<typeof alertSchema>;
export type IntegrationDeliveryResultContract = z.infer<typeof integrationDeliveryResultSchema>;
export type OverviewResponse = z.infer<typeof overviewResponseSchema>;
export type VulnerabilityListResponse = z.infer<typeof vulnerabilityListResponseSchema>;
export type VulnerabilityDetailResponse = z.infer<typeof vulnerabilityDetailResponseSchema>;
export type AssetsResponse = z.infer<typeof assetsResponseSchema>;
export type AlertsResponse = z.infer<typeof alertsResponseSchema>;
