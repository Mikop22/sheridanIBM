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
  affectedAsset: z.object({ id: z.string().nullable(), name: z.string(), service: z.string().nullable() }).nullable(),
  detectedAt: z.string().nullable(),
  modelVersion: z.string().min(1).optional(),
  scoreScale: z.object({ minimum: z.number(), maximum: z.number(), higher_is_riskier: z.boolean() }).optional(),
  scoreInterpretation: z.string().min(1).optional(),
  componentScores: z.record(z.string(), z.number()).optional(),
  artifact: z.object({ artifactId: z.string().min(1), sourceKind: z.enum(["summary_json", "full_csv"]), recordCount: z.number().int().positive() }).optional(),
  missingInformation: z.array(z.string()).optional(),
  assetMatchStatus: z.literal("unknown").optional(),
  investigationState: z.literal("unreviewed").optional(),
  suggestedAction: z.null().optional(),
  groundedExplanation: z.unknown().optional(),
});

export const baselineSchema = z.object({
  method: z.string().min(1),
  hitsAt500: z.number().int().nonnegative().nullable(),
  note: z.string().nullable(),
});

export const historicalOutcomeSchema = z.object({
  cveId: z.string().min(1),
  status: z.enum(["confirmed-kev", "not-kev-by-cutoff", "unknown"]),
  kevAddedAt: z.string().nullable(),
  observedByCutoff: z.boolean(),
});

export const historicalReplaySchema = z.object({
  month: z.string().regex(/^\d{4}-\d{2}$/),
  predictionSnapshot: z.object({ capturedAt: z.string(), featureCutoff: z.string() }),
  rankings: z.array(z.object({ rank: z.number().int().positive(), predictedRisk: riskLevelSchema, vulnerability: vulnerabilitySchema })),
  baselines: z.array(baselineSchema),
  evaluationCutoff: z.string(),
  laterOutcomes: z.array(historicalOutcomeSchema),
  source: dataSourceSchema,
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
});

export const assetVulnerabilityMatchSchema = z.object({
  cveId: z.string().min(1),
  assetId: z.string().min(1),
  matchStatus: z.enum(["Confirmed", "Possible", "Unknown"]),
  supportingEvidence: z.array(z.string()),
  predictedRisk: riskLevelSchema.nullable(),
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
});

export const overviewResponseSchema = z.object({
  summary: z.object({ totalVulnerabilities: z.number().int().nonnegative().nullable(), criticalPriority: z.number().int().nonnegative().nullable(), exposedAssets: z.number().int().nonnegative().nullable(), predictionHorizonDays: z.number().int().positive().nullable() }),
  priorityVulnerabilities: z.array(vulnerabilitySchema),
  generatedAt: z.string(),
  source: dataSourceSchema,
});
export const vulnerabilityListResponseSchema = z.object({ vulnerabilities: z.array(vulnerabilitySchema), generatedAt: z.string().nullable(), source: dataSourceSchema });
export const vulnerabilityDetailResponseSchema = z.object({ vulnerability: vulnerabilitySchema, source: dataSourceSchema });
export const assetsResponseSchema = z.object({ assets: z.array(assetSchema), matches: z.array(assetVulnerabilityMatchSchema), organizationLabel: z.string().nullable(), source: dataSourceSchema });
export const alertsResponseSchema = z.object({ alerts: z.array(alertSchema), source: dataSourceSchema });
export const apiErrorResponseSchema = z.object({ error: z.object({ code: z.string(), message: z.string(), details: z.unknown().nullable().optional(), requestId: z.string().nullable().optional() }) });

export type DataSource = z.infer<typeof dataSourceSchema>;
export type EvidenceIndicator = z.infer<typeof evidenceIndicatorSchema>;
export type VulnerabilityContract = z.infer<typeof vulnerabilitySchema>;
export type HistoricalReplay = z.infer<typeof historicalReplaySchema>;
export type AssetContract = z.infer<typeof assetSchema>;
export type AssetVulnerabilityMatchContract = z.infer<typeof assetVulnerabilityMatchSchema>;
export type AlertContract = z.infer<typeof alertSchema>;
export type IntegrationDeliveryResultContract = z.infer<typeof integrationDeliveryResultSchema>;
export type OverviewResponse = z.infer<typeof overviewResponseSchema>;
export type VulnerabilityListResponse = z.infer<typeof vulnerabilityListResponseSchema>;
export type VulnerabilityDetailResponse = z.infer<typeof vulnerabilityDetailResponseSchema>;
export type AssetsResponse = z.infer<typeof assetsResponseSchema>;
export type AlertsResponse = z.infer<typeof alertsResponseSchema>;
