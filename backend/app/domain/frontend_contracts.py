from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from app.domain.contracts import AssetDecision, ContractModel, Explanation, ScoreScale


class FrontendArtifactProvenance(ContractModel):
    artifactId: str
    sourceKind: Literal["summary_json", "full_csv"]
    recordCount: int = Field(ge=1)


class FrontendEvidenceIndicator(ContractModel):
    key: str
    label: str
    value: str | float | bool | None
    status: Literal["present", "absent", "unknown"]
    observedAt: datetime | None
    source: str | None
    explanation: str | None


class FrontendAffectedAsset(ContractModel):
    id: str | None
    name: str
    service: str | None
    owner: str | None


class FrontendDecisionReason(ContractModel):
    code: str
    message: str
    sourceRefs: list[str]


class FrontendVulnerability(ContractModel):
    cveId: str
    description: str | None = None
    snapshotMonth: str
    cvss: float | None = None
    epss: float | None = None
    modelRank: int = Field(ge=1)
    rankingScore: float
    rankingScoreKind: Literal["relative"] = "relative"
    traditionalRank: int | None = None
    predictedRisk: None = None
    evidenceIndicators: list[FrontendEvidenceIndicator]
    affectedAsset: FrontendAffectedAsset | None = None
    detectedAt: datetime | None = None
    modelVersion: str
    scoreScale: ScoreScale
    scoreInterpretation: str
    componentScores: dict[str, float]
    artifact: FrontendArtifactProvenance
    missingInformation: list[str]
    assetMatchStatus: Literal[
        "confirmed_affected", "potentially_affected", "unknown", "confirmed_unaffected"
    ] = "unknown"
    investigationState: Literal["unreviewed", "monitoring", "investigating", "action_pending"]
    operationalDecision: Literal["MONITOR", "INVESTIGATE", "ACTION_REQUIRED", "URGENT"]
    decisionReasons: list[FrontendDecisionReason]
    assetDecisions: list[AssetDecision] = Field(default_factory=list)
    remediationEligibility: Literal[
        "CODE_REMEDIABLE",
        "OPERATIONAL_REMEDIATION",
        "NEEDS_INVESTIGATION",
        "NOT_ELIGIBLE",
    ]
    agentEligible: bool
    suggestedAction: str
    groundedExplanation: Explanation


class FrontendVulnerabilityList(ContractModel):
    vulnerabilities: list[FrontendVulnerability] = Field(default_factory=list)
    generatedAt: datetime | None = None
    source: Literal["live"] = "live"


class FrontendOverviewSummary(ContractModel):
    totalVulnerabilities: int | None = Field(default=None, ge=0)
    criticalPriority: int | None = Field(default=None, ge=0)
    exposedAssets: int | None = Field(default=None, ge=0)
    predictionHorizonDays: int | None = Field(default=None, ge=1)


class FrontendOverview(ContractModel):
    summary: FrontendOverviewSummary = Field(default_factory=FrontendOverviewSummary)
    priorityVulnerabilities: list[dict] = Field(default_factory=list)
    generatedAt: datetime
    source: Literal["live"] = "live"


class FrontendVulnerabilityDetail(ContractModel):
    vulnerability: FrontendVulnerability
    source: Literal["live"] = "live"


class FrontendAsset(ContractModel):
    assetId: str
    name: str
    vendor: str | None = None
    product: str | None = None
    version: str | None = None
    environment: Literal["Production", "Development", "Unknown"]
    internetExposed: bool | None
    businessCriticality: Literal["Critical", "High", "Medium", "Low", "Unknown"]
    owner: str | None
    repositoryIdentifier: str | None
    componentPackage: str | None
    synthetic: Literal[True] = True


class FrontendAssetMatch(ContractModel):
    cveId: str
    assetId: str
    matchStatus: Literal["Confirmed", "Possible", "Unknown", "Unaffected"]
    canonicalMatchStatus: Literal[
        "confirmed_affected", "potentially_affected", "unknown", "confirmed_unaffected"
    ]
    supportingEvidence: list[str]
    predictedRisk: None = None
    provenance: Literal[
        "internally_consistent_synthetic_scenario_not_external_product_intelligence"
    ]


class FrontendAssets(ContractModel):
    assets: list[FrontendAsset] = Field(default_factory=list)
    matches: list[FrontendAssetMatch] = Field(default_factory=list)
    organizationLabel: str | None = None
    synthetic: bool = True
    provenance: str
    source: Literal["live"] = "live"


class FrontendDecisionActivity(ContractModel):
    eventId: str
    processedAt: datetime
    reasonCode: str
    reusedRecommendation: bool


class FrontendPersistentDecision(ContractModel):
    recommendationId: str
    findingId: str
    cveId: str
    assetId: str
    operationalDecision: Literal["MONITOR", "INVESTIGATE", "ACTION_REQUIRED", "URGENT"]
    workflowStatus: str
    reasonCodes: list[str]
    evidenceRefs: list[str]
    remediationEligibility: str
    agentEligible: bool
    executionAuthorized: Literal[False] = False
    proposedNextAction: str
    createdAt: datetime
    decidedAt: datetime | None
    decidedBy: str | None
    decisionReason: str | None
    activityHistory: list[FrontendDecisionActivity]


class FrontendAlerts(ContractModel):
    alerts: list[dict] = Field(default_factory=list)
    decisions: list[FrontendPersistentDecision] = Field(default_factory=list)
    source: Literal["live"] = "live"
