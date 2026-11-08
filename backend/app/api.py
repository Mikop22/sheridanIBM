from __future__ import annotations

import json
import re
import time
from datetime import UTC, datetime
from typing import Annotated, Any, Literal
from urllib.error import URLError
from urllib.request import Request as UrlRequest
from urllib.request import urlopen

from fastapi import APIRouter, Depends, Request, Response, status

from app.domain.contracts import (
    ErrorResponse,
    EventProcessingOutcome,
    Explanation,
    HealthStatus,
    OperationalDecision,
    Prediction,
    RecommendationDecision,
    RemediationRecommendation,
    SecurityEvent,
)
from app.domain.errors import (
    FrontendVulnerabilityNotFoundError,
)
from app.domain.frontend_contracts import (
    FrontendAffectedAsset,
    FrontendAlert,
    FrontendAlertHistoryEvent,
    FrontendAlerts,
    FrontendArtifactProvenance,
    FrontendAsset,
    FrontendAssetMatch,
    FrontendAssets,
    FrontendDecisionActivity,
    FrontendDecisionReason,
    FrontendEvidenceIndicator,
    FrontendIntegrationDelivery,
    FrontendOverview,
    FrontendOverviewSummary,
    FrontendPersistentDecision,
    FrontendVulnerability,
    FrontendVulnerabilityDetail,
    FrontendVulnerabilityList,
)
from app.event_repository import SecurityEventRepository
from app.operations.inventory import ASSETS, DemoAsset, asset_by_id, asset_for
from app.operations.models import (
    JudgeScriptReport,
    JudgeScriptRequest,
    PullRequestRecord,
    RankingsResponse,
    ReadinessResponse,
)
from app.operations.remediation import REPOSITORY as SECURITYDEMO_REPO
from app.operations.remediation import branch_for_route
from app.operations.service import OperationsService
from app.operations.store import DeliveryRow, FindingRow, JobRow
from app.repositories import PredictionRepository
from app.services.asset_correlation import AssetCorrelationService
from app.services.escalation import EscalationEvaluator
from app.services.event_processing import SecurityEventProcessor
from app.services.explanations import ExplanationService, LocalExplanationService
from app.services.prediction_artifacts import (
    SCORE_INTERPRETATION,
    PredictionArtifact,
    PredictionArtifactRecord,
)

router = APIRouter()

_CRITICALITY_MAP: dict[str, Literal["Critical", "High", "Medium", "Low", "Unknown"]] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}
_PRIORITY_MAP: dict[str, Literal["Critical", "High", "Medium"]] = {
    "escalate": "Critical",
    "act": "High",
    "investigate": "Medium",
}
_SYNTHETIC_INVENTORY_LABEL = "SignalZero demo inventory (synthetic)"
_PR_NUMBER_RE = re.compile(r"/pull/(\d+)(?:$|[/?#])")
_GITHUB_PR_CACHE: dict[str, tuple[float, dict[str, dict[str, Any]]]] = {}
_GITHUB_PR_TTL_SECONDS = 30.0


def _pr_number_from_url(url: str | None) -> int | None:
    if not url:
        return None
    match = _PR_NUMBER_RE.search(url)
    return int(match.group(1)) if match else None


def _fetch_live_github_prs(repo: str, token: str) -> dict[str, dict[str, Any]]:
    now = time.monotonic()
    cached = _GITHUB_PR_CACHE.get(repo)
    if cached is not None and (now - cached[0]) < _GITHUB_PR_TTL_SECONDS:
        return dict(cached[1])
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "Vigil-Security-Operations",
    }
    if token.strip():
        headers["Authorization"] = f"Bearer {token.strip()}"
    url = f"https://api.github.com/repos/{repo}/pulls?state=open"
    result: dict[str, dict[str, Any]] = {}
    try:
        req = UrlRequest(url, headers=headers)
        with urlopen(req, timeout=3.0) as resp:  # noqa: S310
            payload = json.loads(resp.read().decode("utf-8"))
        if isinstance(payload, list):
            for item in payload:
                if not isinstance(item, dict):
                    continue
                head = item.get("head")
                branch = head.get("ref") if isinstance(head, dict) else None
                html_url = item.get("html_url")
                if isinstance(branch, str) and branch and isinstance(html_url, str) and html_url:
                    result[branch] = {
                        "url": html_url,
                        "number": item.get("number")
                        if isinstance(item.get("number"), int)
                        else _pr_number_from_url(html_url),
                        "title": item.get("title") if isinstance(item.get("title"), str) else None,
                        "branch": branch,
                        "draft": bool(item.get("draft", True)),
                        "updated_at": item.get("updated_at")
                        if isinstance(item.get("updated_at"), str)
                        else None,
                    }
        _GITHUB_PR_CACHE[repo] = (now, result)
    except (URLError, TimeoutError, ValueError, OSError):
        if cached is not None:
            return dict(cached[1])
    return result


def _resolve_securitydemo_prs(operations: OperationsService) -> dict[str, dict[str, Any]]:
    prs: dict[str, dict[str, Any]] = {}
    if operations.settings.operations_delivery == "live":
        prs.update(
            _fetch_live_github_prs(
                SECURITYDEMO_REPO,
                operations.settings.github_token,
            )
        )
    for job in operations.store.list_jobs():
        if job.pr_url:
            existing = prs.get(job.branch, {})
            prs[job.branch] = {
                "url": job.pr_url,
                "number": existing.get("number") or _pr_number_from_url(job.pr_url),
                "title": existing.get("title"),
                "branch": job.branch,
                "draft": existing.get("draft", True),
                "checks_passed": job.checks_passed,
                "updated_at": existing.get("updated_at"),
            }
        elif job.branch in prs and job.checks_passed is not None:
            prs[job.branch]["checks_passed"] = job.checks_passed
    return prs


def get_repository(request: Request) -> PredictionRepository:
    return request.app.state.prediction_repository


def get_explanation_service(request: Request) -> ExplanationService:
    return request.app.state.explanation_service


def get_event_processor(request: Request) -> SecurityEventProcessor:
    return request.app.state.event_processor


def get_event_repository(request: Request) -> SecurityEventRepository:
    return request.app.state.event_repository


def get_prediction_artifact(request: Request) -> PredictionArtifact:
    return request.app.state.prediction_artifact


def get_asset_correlations(request: Request) -> AssetCorrelationService:
    return request.app.state.asset_correlations


def get_escalation_evaluator(request: Request) -> EscalationEvaluator:
    return request.app.state.escalation_evaluator


def get_operations_service(request: Request) -> OperationsService:
    return request.app.state.operations_service


RepositoryDependency = Annotated[PredictionRepository, Depends(get_repository)]
ExplanationDependency = Annotated[ExplanationService, Depends(get_explanation_service)]
EventProcessorDependency = Annotated[SecurityEventProcessor, Depends(get_event_processor)]
EventRepositoryDependency = Annotated[SecurityEventRepository, Depends(get_event_repository)]
ArtifactDependency = Annotated[PredictionArtifact, Depends(get_prediction_artifact)]
CorrelationDependency = Annotated[AssetCorrelationService, Depends(get_asset_correlations)]
EscalationDependency = Annotated[EscalationEvaluator, Depends(get_escalation_evaluator)]
OperationsDependency = Annotated[OperationsService, Depends(get_operations_service)]


@router.get(
    "/health",
    response_model=HealthStatus,
    responses={503: {"model": HealthStatus}},
    tags=["operations"],
)
def health(request: Request, response: Response) -> HealthStatus:
    provider = request.app.state.settings.explanation_provider
    provider_ready = request.app.state.settings.provider_ready()
    if not provider_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return HealthStatus(
        status="ready" if provider_ready else "not_ready",
        explanation_provider=provider.value,
        provider_ready=provider_ready,
    )


@router.post(
    "/v1/predictions",
    response_model=Prediction,
    status_code=status.HTTP_201_CREATED,
    responses={
        409: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
    },
    tags=["predictions"],
)
def create_prediction(prediction: Prediction, repository: RepositoryDependency) -> Prediction:
    return repository.create(prediction)


@router.get(
    "/v1/predictions/{prediction_id}",
    response_model=Prediction,
    responses={404: {"model": ErrorResponse}},
    tags=["predictions"],
)
def get_prediction(prediction_id: str, repository: RepositoryDependency) -> Prediction:
    return repository.get(prediction_id)


@router.post(
    "/v1/predictions/{prediction_id}/explanation",
    response_model=Explanation,
    responses={
        404: {"model": ErrorResponse},
    },
    tags=["explanations"],
)
def explain_prediction(
    prediction_id: str,
    repository: RepositoryDependency,
    explanation_service: ExplanationDependency,
) -> Explanation:
    return explanation_service.explain(repository.get(prediction_id))


@router.post(
    "/v1/security-events",
    response_model=EventProcessingOutcome,
    responses={
        409: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
    },
    tags=["security-events"],
)
def submit_security_event(
    event: SecurityEvent, event_processor: EventProcessorDependency, dry_run: bool = False
) -> EventProcessingOutcome:
    return event_processor.process(event, dry_run=dry_run)


@router.get(
    "/v1/security-events/{event_id}",
    response_model=EventProcessingOutcome,
    responses={404: {"model": ErrorResponse}, 503: {"model": ErrorResponse}},
    tags=["security-events"],
)
def get_security_event(
    event_id: str, event_repository: EventRepositoryDependency
) -> EventProcessingOutcome:
    return event_repository.get_event(event_id)


@router.get(
    "/v1/predictions/{prediction_id}/recommendations",
    response_model=list[RemediationRecommendation],
    responses={503: {"model": ErrorResponse}},
    tags=["recommendations"],
)
def get_recommendations(
    prediction_id: str,
    event_repository: EventRepositoryDependency,
) -> list[RemediationRecommendation]:
    return event_repository.list_recommendations(prediction_id)


@router.post(
    "/v1/recommendations/{recommendation_id}/decision",
    response_model=RemediationRecommendation,
    responses={
        404: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
    },
    tags=["recommendations"],
)
def decide_recommendation(
    recommendation_id: str,
    decision: RecommendationDecision,
    event_repository: EventRepositoryDependency,
) -> RemediationRecommendation:
    return event_repository.decide(recommendation_id, decision)


def _frontend_affected_asset(asset: DemoAsset) -> FrontendAffectedAsset:
    return FrontendAffectedAsset(
        id=asset.asset_id,
        name=asset.name,
        service=asset.product,
    )


def _frontend_vulnerability(
    record: PredictionArtifactRecord,
    artifact: PredictionArtifact,
    correlations: AssetCorrelationService,
    evaluator: EscalationEvaluator,
) -> FrontendVulnerability:
    prediction = record.prediction
    explanation = LocalExplanationService().explain(prediction)
    evidence_indicators = [
        FrontendEvidenceIndicator(
            key=name,
            label=name,
            value=value,
            status="present",
            observedAt=prediction.evidence[0].observed_at,
            source=prediction.evidence[0].source,
            explanation="Diagnostic model output; no causal contribution was supplied.",
        )
        for name, value in record.component_scores.items()
    ]
    evidence_indicators.extend(
        [
            FrontendEvidenceIndicator(
                key="cvss",
                label="CVSS",
                value=None,
                status="unknown",
                observedAt=None,
                source=None,
                explanation="CVSS was not included in the prediction artifact.",
            ),
            FrontendEvidenceIndicator(
                key="epss",
                label="EPSS",
                value=None,
                status="unknown",
                observedAt=None,
                source=None,
                explanation="EPSS was not included in the prediction artifact.",
            ),
        ]
    )
    asset_decisions = [
        evaluator.evaluate(prediction, correlation)
        for correlation in correlations.correlations_for(prediction.vulnerability.vulnerability_id)
    ]
    decision_order = {
        OperationalDecision.MONITOR: 0,
        OperationalDecision.INVESTIGATE: 1,
        OperationalDecision.ACTION_REQUIRED: 2,
        OperationalDecision.URGENT: 3,
    }
    aggregate = max(
        asset_decisions,
        key=lambda item: (decision_order[item.operational_decision], item.asset_id),
        default=None,
    )
    if aggregate is None:
        operational_decision = evaluator.decision_for_unmapped_finding(prediction)
        in_band = operational_decision is OperationalDecision.INVESTIGATE
        decision_reasons = [
            FrontendDecisionReason(
                code="NO_EXPLICIT_ASSET_MAPPING",
                message=(
                    "No synthetic scenario mapping exists; asset relevance remains unknown and is "
                    "not evidence of safety."
                ),
                sourceRefs=["asset:mapping:missing"],
            ),
            FrontendDecisionReason(
                code=(
                    "MODEL_RANK_WITHIN_INVESTIGATION_BAND"
                    if in_band
                    else "MODEL_RANK_OUTSIDE_INVESTIGATION_BAND"
                ),
                message=(
                    "The supplied model rank places this unknown finding in investigation."
                    if in_band
                    else "The supplied model rank leaves this unknown finding in monitoring."
                ),
                sourceRefs=["prediction:rank", f"policy:{evaluator.policy.version}"],
            ),
        ]
        affected_asset = None
        match_status = "unknown"
        eligibility = "NEEDS_INVESTIGATION"
        agent_eligible = False
        suggested_action = (
            "Validate whether the finding applies to any inventoried asset."
            if in_band
            else "Monitor ranking and asset evidence for material changes."
        )
    else:
        operational_decision = aggregate.operational_decision
        decision_reasons = [
            FrontendDecisionReason(
                code=reason.code, message=reason.message, sourceRefs=reason.source_refs
            )
            for reason in aggregate.reasons
        ]
        asset = correlations.get_asset(aggregate.asset_id)
        assert asset is not None
        affected_asset = FrontendAffectedAsset(
            id=asset.asset_id,
            name=asset.application_name,
            service=asset.service_name,
            owner=asset.owner_team,
        )
        match_status = aggregate.match_status
        eligibility = aggregate.eligibility.outcome.value
        agent_eligible = aggregate.eligibility.agent_eligible
        suggested_action = aggregate.proposed_next_action
    state = {
        OperationalDecision.MONITOR: "monitoring",
        OperationalDecision.INVESTIGATE: "investigating",
        OperationalDecision.ACTION_REQUIRED: "action_pending",
        OperationalDecision.URGENT: "action_pending",
    }[operational_decision]
    missing_information = [
        "CVSS score",
        "EPSS score",
        "feature contribution values",
    ]
    if not record.description:
        missing_information.insert(0, "vulnerability description")
    if aggregate is None:
        missing_information.append("affected asset associations")
    operations_inventory = asset_for(prediction.vulnerability.vulnerability_id)
    if operations_inventory is not None:
        evidence_indicators.append(
            FrontendEvidenceIndicator(
                key="operations_inventory_match",
                label="Operations inventory match",
                value=operations_inventory.asset_id,
                status="present",
                observedAt=None,
                source="operations.inventory",
                explanation=(
                    f"{operations_inventory.note} Association comes from synthetic demo inventory, "
                    "not a live asset scan."
                ),
            )
        )
    return FrontendVulnerability(
        cveId=prediction.vulnerability.vulnerability_id,
        description=record.description,
        snapshotMonth=record.snapshot_month,
        modelRank=prediction.rank,
        rankingScore=prediction.score,
        evidenceIndicators=evidence_indicators,
        affectedAsset=affected_asset,
        modelVersion=prediction.model_version,
        scoreScale=prediction.score_scale,
        scoreInterpretation=SCORE_INTERPRETATION,
        componentScores=record.component_scores,
        artifact=FrontendArtifactProvenance(
            artifactId=artifact.artifact_id,
            sourceKind=artifact.source_kind,
            recordCount=len(artifact.records),
        ),
        missingInformation=missing_information,
        assetMatchStatus=match_status,
        investigationState=state,
        operationalDecision=operational_decision.value,
        decisionReasons=decision_reasons,
        assetDecisions=asset_decisions,
        remediationEligibility=eligibility,
        agentEligible=agent_eligible,
        suggestedAction=suggested_action,
        groundedExplanation=explanation,
    )


def _business_criticality(
    value: str,
) -> Literal["Critical", "High", "Medium", "Low", "Unknown"]:
    return _CRITICALITY_MAP.get(value.casefold(), "Unknown")


def _frontend_asset(asset: DemoAsset) -> FrontendAsset:
    return FrontendAsset(
        assetId=asset.asset_id,
        name=asset.name,
        vendor=None,
        product=asset.product,
        version=asset.installed_version,
        environment="Unknown",
        # Inventory has no sourced exposure field; do not invent True/False.
        internetExposed=None,
        businessCriticality=_business_criticality(asset.criticality),
        owner=asset.owner,
    )


def _frontend_asset_match(asset: DemoAsset) -> FrontendAssetMatch:
    return FrontendAssetMatch(
        cveId=asset.cve_id,
        assetId=asset.asset_id,
        matchStatus="Confirmed",
        canonicalMatchStatus="confirmed_affected",
        supportingEvidence=[
            asset.note,
            "Inventory is synthetic demo data, not a live asset scan.",
        ],
        predictedRisk=None,
        provenance="internally_consistent_synthetic_scenario_not_external_product_intelligence",
    )


def _alert_priority(level: str) -> Literal["Critical", "High", "Medium"]:
    return _PRIORITY_MAP.get(level.casefold(), "Medium")


def _delivery_timestamp(value: str | None, fallback: str) -> str:
    if value is None or not value.strip():
        return fallback
    return value


def _jira_external_url(base_url: str, external_id: str | None) -> str | None:
    base = base_url.strip().rstrip("/")
    if not base or not external_id:
        return None
    return f"{base}/browse/{external_id}"


def _integration_from_deliveries(
    *,
    provider: Literal["slack", "jira"],
    deliveries: list[DeliveryRow],
    jira_base_url: str,
) -> FrontendIntegrationDelivery:
    if not deliveries:
        return FrontendIntegrationDelivery(
            provider=provider,
            status="not-attempted",
            operation=None,
            attemptedAt=None,
            deliveredAt=None,
            externalId=None,
            externalUrl=None,
            errorCode=None,
            errorMessage=None,
        )
    latest = deliveries[-1]
    status: Literal["not-attempted", "pending", "delivered", "failed", "simulated-not-sent"]
    if latest.delivered:
        status = "delivered"
    elif latest.mode == "blocked":
        status = "failed"
    elif latest.mode == "recording":
        status = "simulated-not-sent"
    else:
        status = "pending"
    operation: Literal["created", "updated", "commented"] | None = None
    if provider == "jira" and latest.delivered:
        if latest.kind.endswith("_create") or latest.kind == "jira_create":
            operation = "created"
        elif latest.kind.endswith("_update") or latest.kind == "jira_update":
            operation = "updated"
        elif "comment" in latest.kind:
            operation = "commented"
    external_id = latest.external_id
    external_url = None
    if provider == "jira":
        external_url = _jira_external_url(jira_base_url, external_id)
    return FrontendIntegrationDelivery(
        provider=provider,
        status=status,
        operation=operation,
        attemptedAt=latest.created_on,
        deliveredAt=latest.created_on if latest.delivered else None,
        externalId=external_id,
        externalUrl=external_url,
        errorCode=None if latest.delivered or latest.mode != "blocked" else "delivery_blocked",
        errorMessage=None if latest.delivered or latest.mode != "blocked" else latest.detail,
    )


def _frontend_alert(
    finding: FindingRow,
    deliveries: list[DeliveryRow],
    *,
    job: JobRow | None = None,
    pr_info: dict[str, Any] | None = None,
    jira_base_url: str,
    now_iso: str,
    simulated: bool,
) -> FrontendAlert:
    asset = asset_by_id(finding.asset_id)
    asset_name = None if asset is None else asset.name
    slack_rows = [row for row in deliveries if row.kind.startswith("slack_")]
    jira_rows = [row for row in deliveries if row.kind.startswith("jira_")]
    timestamps = [row.created_on for row in deliveries if row.created_on]
    created_at = _delivery_timestamp(timestamps[0] if timestamps else None, now_iso)
    updated_at = _delivery_timestamp(timestamps[-1] if timestamps else None, now_iso)
    history: list[FrontendAlertHistoryEvent] = [
        FrontendAlertHistoryEvent(
            timestamp=created_at,
            label="Finding recorded",
            detail=(
                f"Policy level {finding.level} for {finding.cve_id} on {finding.asset_id} "
                f"via route {finding.route}."
            ),
            kind="detection",
        )
    ]
    for row in deliveries:
        kind: Literal["detection", "delivery", "ticket", "status"]
        if row.kind.startswith("jira_"):
            kind = "ticket"
            label = "Jira delivery"
        elif row.kind.startswith("slack_"):
            kind = "delivery"
            label = "Slack delivery"
        else:
            kind = "status"
            label = f"{row.kind} delivery"
        history.append(
            FrontendAlertHistoryEvent(
                timestamp=row.created_on,
                label=label,
                detail=row.detail or row.body,
                kind=kind,
            )
        )
    pr_url = (pr_info.get("url") if pr_info else None) or (job.pr_url if job else None)
    pr_number = (pr_info.get("number") if pr_info else None) or _pr_number_from_url(pr_url)
    pr_title = pr_info.get("title") if pr_info else None
    pr_branch = (job.branch if job else None) or (pr_info.get("branch") if pr_info else None)
    checks_passed = (
        job.checks_passed
        if (job is not None and job.checks_passed is not None)
        else (pr_info.get("checks_passed") if pr_info else None)
    )
    if pr_url and checks_passed is None:
        checks_passed = True
    repository = (job.repository if job else None) or (asset.repository if asset else None)
    owner_team = asset.owner if asset else (finding.team if finding.team != "unknown" else None)
    if pr_url:
        pr_ts = pr_info.get("updated_at") if (pr_info and pr_info.get("updated_at")) else updated_at
        history.append(
            FrontendAlertHistoryEvent(
                timestamp=pr_ts,
                label="Draft GitHub PR opened",
                detail=(
                    f"{pr_title} ({pr_url})"
                    if pr_title
                    else f"Draft pull request opened in {repository or SECURITYDEMO_REPO}: {pr_url}"
                ),
                kind="status",
            )
        )
    evidence = [
        f"Finding level: {finding.level}",
        f"Remediation route: {finding.route}",
        "Inventory is synthetic demo data, not a live asset scan.",
    ]
    if asset is not None:
        evidence.insert(0, asset.note)
    if pr_url:
        evidence.append(f"Draft PR awaiting review: {pr_url}")
    return FrontendAlert(
        alertId=finding.finding_key,
        cveId=finding.cve_id,
        assetId=finding.asset_id,
        assetName=asset_name,
        priority=_alert_priority(finding.level),
        triggerReason=(
            f"Operations finding at level '{finding.level}' for route '{finding.route}'."
        ),
        createdAt=created_at,
        updatedAt=updated_at,
        slackDelivery=_integration_from_deliveries(
            provider="slack",
            deliveries=slack_rows,
            jira_base_url=jira_base_url,
        ),
        jiraDelivery=_integration_from_deliveries(
            provider="jira",
            deliveries=jira_rows,
            jira_base_url=jira_base_url,
        ),
        lifecycle="Investigating" if (finding.review_notified or bool(pr_url)) else "Open",
        occurrenceCount=1,
        evidence=evidence,
        history=history,
        dedupeKey=finding.finding_key,
        simulated=simulated,
        repository=repository,
        ownerTeam=owner_team,
        prUrl=pr_url,
        prNumber=pr_number,
        prTitle=pr_title,
        prBranch=pr_branch,
        checksPassed=checks_passed,
    )


@router.get("/api/vulnerabilities", response_model=FrontendVulnerabilityList, tags=["frontend"])
def frontend_vulnerabilities(
    artifact: ArtifactDependency,
    correlations: CorrelationDependency,
    evaluator: EscalationDependency,
) -> FrontendVulnerabilityList:
    """Return startup-loaded Member 1 predictions without request-time model execution."""
    return FrontendVulnerabilityList(
        vulnerabilities=[
            _frontend_vulnerability(record, artifact, correlations, evaluator)
            for record in artifact.records
        ]
    )


@router.get("/api/overview", response_model=FrontendOverview, tags=["frontend"])
def frontend_overview(
    artifact: ArtifactDependency,
    correlations: CorrelationDependency,
    evaluator: EscalationDependency,
    operations: OperationsDependency,
) -> FrontendOverview:
    """Dashboard totals from the prediction artifact and demo inventory matches."""
    ranked = sorted(artifact.records, key=lambda item: item.prediction.rank)
    priority = [
        _frontend_vulnerability(record, artifact, correlations, evaluator) for record in ranked
    ]
    inventory_matches = sum(1 for item in priority if item.affectedAsset is not None)
    prs_by_branch = _resolve_securitydemo_prs(operations)
    draft_prs: int | None = None
    if operations.settings.operations_delivery == "live" or prs_by_branch:
        draft_prs = len(prs_by_branch)
    return FrontendOverview(
        summary=FrontendOverviewSummary(
            totalVulnerabilities=len(artifact.records),
            criticalPriority=None,
            # Do not equate inventory size with internet exposure.
            exposedAssets=None,
            predictionHorizonDays=None,
            inventoryMatches=inventory_matches,
            topModelRank=ranked[0].prediction.rank if ranked else None,
            draftPullRequests=draft_prs,
        ),
        priorityVulnerabilities=priority,
        generatedAt=datetime.now(UTC),
    )


@router.get(
    "/api/vulnerabilities/{vulnerability_id}",
    response_model=FrontendVulnerabilityDetail,
    responses={404: {"model": ErrorResponse}},
    tags=["frontend"],
)
def frontend_vulnerability_detail(
    vulnerability_id: str,
    artifact: ArtifactDependency,
    correlations: CorrelationDependency,
    evaluator: EscalationDependency,
) -> FrontendVulnerabilityDetail:
    record = artifact.find_cve(vulnerability_id)
    if record is None:
        raise FrontendVulnerabilityNotFoundError(vulnerability_id)
    return FrontendVulnerabilityDetail(
        vulnerability=_frontend_vulnerability(record, artifact, correlations, evaluator)
    )


@router.get("/api/assets", response_model=FrontendAssets, tags=["frontend"])
def frontend_assets(correlations: CorrelationDependency) -> FrontendAssets:
    """Return both deterministic escalation and operations demo inventories."""
    inventory = correlations.inventory
    evidence = {item.evidence_id: item.description for item in inventory.evidence}
    status_labels = {
        "confirmed_affected": "Confirmed",
        "potentially_affected": "Possible",
        "unknown": "Unknown",
        "confirmed_unaffected": "Unaffected",
    }
    return FrontendAssets(
        assets=[
            FrontendAsset(
                assetId=asset.asset_id,
                name=asset.application_name,
                product=asset.component_package,
                version=asset.installed_version,
                environment=asset.environment.title(),
                internetExposed=(
                    True
                    if asset.exposure_status.value == "internet_facing"
                    else False
                    if asset.exposure_status.value == "internal"
                    else None
                ),
                businessCriticality=asset.business_criticality.value.title(),
                owner=asset.owner_team,
                repositoryIdentifier=asset.repository_identifier,
                componentPackage=asset.component_package,
            )
            for asset in inventory.assets
        ]
        + [_frontend_asset(asset) for asset in ASSETS],
        matches=[
            FrontendAssetMatch(
                cveId=mapping.vulnerability_id,
                assetId=mapping.asset_id,
                matchStatus=status_labels[mapping.match_status.value],
                canonicalMatchStatus=mapping.match_status.value,
                supportingEvidence=[
                    mapping.assertion,
                    *(evidence[ref] for ref in mapping.evidence_refs),
                ],
                provenance=inventory.verification_meaning,
            )
            for mapping in inventory.mappings
        ]
        + [_frontend_asset_match(asset) for asset in ASSETS],
        organizationLabel=inventory.organization_label,
        synthetic=True,
        provenance=inventory.verification_meaning,
    )


@router.get("/api/alerts", response_model=FrontendAlerts, tags=["frontend"])
def frontend_alerts(
    event_repository: EventRepositoryDependency,
    operations: OperationsDependency,
) -> FrontendAlerts:
    """Expose deterministic decisions and recorded operations delivery state."""
    decisions = [
        FrontendPersistentDecision(
            recommendationId=item.recommendation_id,
            findingId=item.finding_id,
            cveId=item.vulnerability_id,
            assetId=item.asset_id,
            operationalDecision=item.operational_decision.value,
            workflowStatus=item.workflow_status.value,
            reasonCodes=[reason.code for reason in item.decision_reasons],
            evidenceRefs=item.evidence_refs,
            remediationEligibility=item.eligibility.outcome.value,
            agentEligible=item.eligibility.agent_eligible,
            executionAuthorized=False,
            proposedNextAction=item.recommended_next_step,
            createdAt=item.created_at,
            decidedAt=item.decided_at,
            decidedBy=item.decided_by,
            decisionReason=item.decision_reason,
            activityHistory=[
                FrontendDecisionActivity(
                    eventId=outcome.event_id,
                    processedAt=outcome.processed_at,
                    reasonCode=outcome.reason_code,
                    reusedRecommendation=outcome.reused_recommendation,
                )
                for outcome in event_repository.list_finding_outcomes(item.finding_id)
            ],
        )
        for item in event_repository.list_all_recommendations()
    ]
    store = operations.store
    findings = store.list_findings()
    if not findings:
        return FrontendAlerts(decisions=decisions)
    deliveries = store.list_deliveries()
    by_finding: dict[str, list[DeliveryRow]] = {}
    for row in deliveries:
        by_finding.setdefault(row.finding_key, []).append(row)
    jobs_by_finding = {job.finding_key: job for job in store.list_jobs()}
    prs_by_branch = _resolve_securitydemo_prs(operations)
    now_iso = datetime.now(UTC).isoformat()
    jira_base_url = operations.settings.jira_base_url
    # Inventory is always synthetic; "simulated" tracks delivery mode so live
    # Slack/Jira runs are not labeled as demo banners.
    simulated = operations.settings.operations_delivery != "live"
    alerts: list[FrontendAlert] = []
    for finding in findings:
        job = jobs_by_finding.get(finding.finding_key)
        branch = (
            job.branch
            if job is not None
            else (
                branch_for_route(finding.route)
                if finding.route in {"dependency_upgrade", "code_patch"}
                else None
            )
        )
        pr_info = prs_by_branch.get(branch) if branch else None
        alerts.append(
            _frontend_alert(
                finding,
                by_finding.get(finding.finding_key, []),
                job=job,
                pr_info=pr_info,
                jira_base_url=jira_base_url,
                now_iso=now_iso,
                simulated=simulated,
            )
        )
    return FrontendAlerts(alerts=alerts, decisions=decisions)


def _operations(request: Request) -> OperationsService:
    return request.app.state.operations_service


@router.get("/v1/operations/readiness", response_model=ReadinessResponse, tags=["operations-plan"])
def operations_readiness(request: Request) -> ReadinessResponse:
    return _operations(request).readiness()


@router.get("/v1/operations/rankings", response_model=RankingsResponse, tags=["operations-plan"])
def operations_rankings(request: Request) -> RankingsResponse:
    return _operations(request).rankings()


@router.get(
    "/v1/operations/judge-script",
    response_model=JudgeScriptReport,
    tags=["operations-plan"],
)
def operations_judge_state(request: Request) -> JudgeScriptReport:
    return _operations(request).state()


@router.post(
    "/v1/operations/judge-script",
    response_model=JudgeScriptReport,
    tags=["operations-plan"],
)
def operations_run_judge_script(body: JudgeScriptRequest, request: Request) -> JudgeScriptReport:
    return _operations(request).run_judge_script(body.through)


@router.post(
    "/v1/operations/remediations/{cve_id}/pull-request",
    response_model=JudgeScriptReport,
    tags=["operations-plan"],
)
def operations_record_pull_request(
    cve_id: str, body: PullRequestRecord, request: Request
) -> JudgeScriptReport:
    return _operations(request).record_pull_request(cve_id, body.pr_url, body.checks_passed)
