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
    affectedAsset: None = None
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
    priorityVulnerabilities: list[dict] = Field(default_factory=list)
    generatedAt: datetime
    source: Literal["live"] = "live"


class FrontendVulnerabilityDetail(ContractModel):
    vulnerability: FrontendVulnerability
    source: Literal["live"] = "live"


class FrontendAssets(ContractModel):
    assets: list[dict] = Field(default_factory=list)
    matches: list[dict] = Field(default_factory=list)
    organizationLabel: str | None = None
    source: Literal["live"] = "live"


class FrontendAlerts(ContractModel):
    alerts: list[dict] = Field(default_factory=list)
    source: Literal["live"] = "live"
