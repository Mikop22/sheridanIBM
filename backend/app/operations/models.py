from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RankingView(ApiModel):
    cve_id: str
    published: str
    snapshot_month: str
    ranking_score: float
    score_kind: Literal["ranking_score"] = "ranking_score"
    score_minimum: float = 0
    score_maximum: float = 1
    higher_is_riskier: bool = True
    rank: int
    scoreboard_rows: int
    population_percentile: float
    asset_id: str | None
    match_status: Literal["confirmed", "unmatched"]
    inventory_synthetic: bool


class RankingsResponse(ApiModel):
    source: str
    rankings: list[RankingView]


class ReadinessResponse(ApiModel):
    delivery_mode: Literal["recording", "live"]
    live_calls_enabled: bool
    missing: list[str]
    github_push_verified: bool
    note: str


class DeliveryView(ApiModel):
    kind: str
    finding_key: str
    team: str
    delivered: bool
    mode: str
    external_id: str | None
    body: str
    detail: str


class JobView(ApiModel):
    finding_key: str
    status: str
    branch: str
    repository: str
    task: str
    pr_url: str | None
    checks_passed: bool | None


class FindingView(ApiModel):
    finding_key: str
    cve_id: str
    asset_id: str
    level: str
    jira_issue_key: str | None
    urgent_notified: bool
    review_notified: bool
    team: str
    route: str
    inventory_synthetic: bool = True


class StepView(ApiModel):
    step: str
    finding_key: str
    level: str
    actions: list[str]
    suppressed: bool
    reason: str


class PreviewView(ApiModel):
    cve_id: str
    asset_id: str
    level: str
    reason: str
    dispatch: bool
    note: str
    source: str


class JudgeScriptReport(ApiModel):
    steps: list[StepView]
    findings: list[FindingView]
    deliveries: list[DeliveryView]
    jobs: list[JobView]
    undispatched: list[PreviewView]


class JudgeScriptRequest(ApiModel):
    through: Literal["july", "kev", "portal", "codefix", "replay"] = "replay"


class PullRequestRecord(ApiModel):
    pr_url: str = Field(min_length=1)
    checks_passed: bool
