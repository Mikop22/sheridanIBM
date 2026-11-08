from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from app.domain.contracts import ContractModel, Explanation, ScoreScale


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
    assetMatchStatus: Literal["unknown"] = "unknown"
    investigationState: Literal["unreviewed"] = "unreviewed"
    suggestedAction: None = None
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
    priorityVulnerabilities: list[FrontendVulnerability] = Field(default_factory=list)
    generatedAt: datetime
    source: Literal["live"] = "live"


class FrontendVulnerabilityDetail(ContractModel):
    vulnerability: FrontendVulnerability
    source: Literal["live"] = "live"


class FrontendAsset(ContractModel):
    assetId: str
    name: str
    vendor: str | None
    product: str | None
    version: str | None
    environment: Literal["Production", "Development", "Unknown"]
    internetExposed: bool | None
    businessCriticality: Literal["Critical", "High", "Medium", "Low", "Unknown"]
    owner: str | None


class FrontendAssetVulnerabilityMatch(ContractModel):
    cveId: str
    assetId: str
    matchStatus: Literal["Confirmed", "Possible", "Unknown"]
    supportingEvidence: list[str]
    predictedRisk: None = None


class FrontendAssets(ContractModel):
    assets: list[FrontendAsset] = Field(default_factory=list)
    matches: list[FrontendAssetVulnerabilityMatch] = Field(default_factory=list)
    organizationLabel: str | None = None
    source: Literal["live"] = "live"


class FrontendIntegrationDelivery(ContractModel):
    provider: Literal["slack", "jira"]
    status: Literal["not-attempted", "pending", "delivered", "failed", "simulated-not-sent"]
    operation: Literal["created", "updated", "commented"] | None
    attemptedAt: str | None
    deliveredAt: str | None
    externalId: str | None
    externalUrl: str | None
    errorCode: str | None
    errorMessage: str | None


class FrontendAlertHistoryEvent(ContractModel):
    timestamp: str
    label: str
    detail: str
    kind: Literal["detection", "delivery", "ticket", "status"]


class FrontendAlert(ContractModel):
    alertId: str
    cveId: str
    assetId: str
    assetName: str | None
    priority: Literal["Critical", "High", "Medium"]
    triggerReason: str
    createdAt: str
    updatedAt: str
    slackDelivery: FrontendIntegrationDelivery
    jiraDelivery: FrontendIntegrationDelivery
    lifecycle: Literal["Open", "Investigating", "Resolved", "Suppressed"]
    occurrenceCount: int = Field(ge=1)
    evidence: list[str]
    history: list[FrontendAlertHistoryEvent]
    dedupeKey: str
    simulated: bool


class FrontendAlerts(ContractModel):
    alerts: list[FrontendAlert] = Field(default_factory=list)
    source: Literal["live"] = "live"
