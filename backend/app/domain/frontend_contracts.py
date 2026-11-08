from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from app.domain.contracts import ContractModel


class FrontendVulnerabilityList(ContractModel):
    vulnerabilities: list[dict] = Field(default_factory=list)
    generatedAt: datetime
    source: Literal["live"] = "live"


class FrontendAssets(ContractModel):
    assets: list[dict] = Field(default_factory=list)
    matches: list[dict] = Field(default_factory=list)
    organizationLabel: str | None = None
    source: Literal["live"] = "live"


class FrontendAlerts(ContractModel):
    alerts: list[dict] = Field(default_factory=list)
    source: Literal["live"] = "live"


class FrontendReplay(ContractModel):
    month: str
    predictionSnapshot: dict
    rankings: list[dict]
    baselines: list[dict]
    evaluationCutoff: str
    laterOutcomes: list[dict]
    source: Literal["live"] = "live"
