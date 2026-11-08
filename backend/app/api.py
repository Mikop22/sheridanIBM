from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Request, Response, status

from app.domain.contracts import (
    ErrorResponse,
    EventProcessingOutcome,
    Explanation,
    HealthStatus,
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
    FrontendAssets,
    FrontendAssetVulnerabilityMatch,
    FrontendEvidenceIndicator,
    FrontendIntegrationDelivery,
    FrontendOverview,
    FrontendOverviewSummary,
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
from app.operations.service import OperationsService
from app.operations.store import DeliveryRow, FindingRow
from app.repositories import PredictionRepository
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
_INTERNET_EXPOSED_ASSET_IDS = frozenset({"edge-load-balancer", "file-gateway"})
_SYNTHETIC_INVENTORY_LABEL = "SignalZero demo inventory (synthetic)"


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


def get_operations_service(request: Request) -> OperationsService:
    return request.app.state.operations_service


RepositoryDependency = Annotated[PredictionRepository, Depends(get_repository)]
ExplanationDependency = Annotated[ExplanationService, Depends(get_explanation_service)]
EventProcessorDependency = Annotated[SecurityEventProcessor, Depends(get_event_processor)]
EventRepositoryDependency = Annotated[SecurityEventRepository, Depends(get_event_repository)]
ArtifactDependency = Annotated[PredictionArtifact, Depends(get_prediction_artifact)]
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
    event: SecurityEvent, event_processor: EventProcessorDependency
) -> EventProcessingOutcome:
    return event_processor.process(event)


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
    record: PredictionArtifactRecord, artifact: PredictionArtifact
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
    inventory = asset_for(prediction.vulnerability.vulnerability_id)
    missing = [
        "vulnerability description",
        "CVSS score",
        "EPSS score",
        "feature contribution values",
    ]
    affected: FrontendAffectedAsset | None = None
    if inventory is None:
        missing.append("affected asset associations")
    else:
        affected = _frontend_affected_asset(inventory)
        missing.append("asset association is from synthetic demo inventory")
        evidence_indicators.append(
            FrontendEvidenceIndicator(
                key="inventory_match",
                label="Inventory match",
                value=inventory.asset_id,
                status="present",
                observedAt=None,
                source="operations.inventory",
                explanation=(
                    f"{inventory.note} Association comes from synthetic demo inventory, "
                    "not a live asset scan."
                ),
            )
        )
    return FrontendVulnerability(
        cveId=prediction.vulnerability.vulnerability_id,
        snapshotMonth=record.snapshot_month,
        modelRank=prediction.rank,
        rankingScore=prediction.score,
        evidenceIndicators=evidence_indicators,
        affectedAsset=affected,
        modelVersion=prediction.model_version,
        scoreScale=prediction.score_scale,
        scoreInterpretation=SCORE_INTERPRETATION,
        componentScores=record.component_scores,
        artifact=FrontendArtifactProvenance(
            artifactId=artifact.artifact_id,
            sourceKind=artifact.source_kind,
            recordCount=len(artifact.records),
        ),
        missingInformation=missing,
        groundedExplanation=explanation,
    )


def _business_criticality(
    value: str,
) -> Literal["Critical", "High", "Medium", "Low", "Unknown"]:
    return _CRITICALITY_MAP.get(value.casefold(), "Unknown")


def _frontend_asset(asset: DemoAsset) -> FrontendAsset:
    exposed: bool | None
    if asset.asset_id in _INTERNET_EXPOSED_ASSET_IDS:
        exposed = True
    else:
        exposed = None
    return FrontendAsset(
        assetId=asset.asset_id,
        name=asset.name,
        vendor=None,
        product=asset.product,
        version=asset.installed_version,
        environment="Unknown",
        internetExposed=exposed,
        businessCriticality=_business_criticality(asset.criticality),
        owner=asset.owner,
    )


def _frontend_asset_match(asset: DemoAsset) -> FrontendAssetVulnerabilityMatch:
    return FrontendAssetVulnerabilityMatch(
        cveId=asset.cve_id,
        assetId=asset.asset_id,
        matchStatus="Confirmed",
        supportingEvidence=[
            asset.note,
            "Inventory is synthetic demo data, not a live asset scan.",
        ],
        predictedRisk=None,
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
        operation=operation if provider == "jira" else None,
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
    evidence = [
        f"Finding level: {finding.level}",
        f"Remediation route: {finding.route}",
        "Inventory is synthetic demo data, not a live asset scan.",
    ]
    if asset is not None:
        evidence.insert(0, asset.note)
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
        lifecycle="Investigating" if finding.review_notified else "Open",
        occurrenceCount=1,
        evidence=evidence,
        history=history,
        dedupeKey=finding.finding_key,
        simulated=simulated,
    )


@router.get("/api/vulnerabilities", response_model=FrontendVulnerabilityList, tags=["frontend"])
def frontend_vulnerabilities(artifact: ArtifactDependency) -> FrontendVulnerabilityList:
    """Return startup-loaded Member 1 predictions without request-time model execution."""
    return FrontendVulnerabilityList(
        vulnerabilities=[_frontend_vulnerability(record, artifact) for record in artifact.records]
    )


@router.get("/api/overview", response_model=FrontendOverview, tags=["frontend"])
def frontend_overview(artifact: ArtifactDependency) -> FrontendOverview:
    """Dashboard totals from the prediction artifact and demo inventory counts."""
    priority = [
        _frontend_vulnerability(record, artifact)
        for record in sorted(artifact.records, key=lambda item: item.prediction.rank)[:10]
    ]
    return FrontendOverview(
        summary=FrontendOverviewSummary(
            totalVulnerabilities=len(artifact.records),
            criticalPriority=None,
            # Do not equate inventory size with internet exposure.
            exposedAssets=None,
            predictionHorizonDays=None,
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
    vulnerability_id: str, artifact: ArtifactDependency
) -> FrontendVulnerabilityDetail:
    record = artifact.find_cve(vulnerability_id)
    if record is None:
        raise FrontendVulnerabilityNotFoundError(vulnerability_id)
    return FrontendVulnerabilityDetail(vulnerability=_frontend_vulnerability(record, artifact))


@router.get("/api/assets", response_model=FrontendAssets, tags=["frontend"])
def frontend_assets() -> FrontendAssets:
    """Map the synthetic demo inventory into the frontend asset contract."""
    return FrontendAssets(
        assets=[_frontend_asset(asset) for asset in ASSETS],
        matches=[_frontend_asset_match(asset) for asset in ASSETS],
        organizationLabel=_SYNTHETIC_INVENTORY_LABEL,
    )


@router.get("/api/alerts", response_model=FrontendAlerts, tags=["frontend"])
def frontend_alerts(operations: OperationsDependency) -> FrontendAlerts:
    """Build alerts from recorded operations findings and deliveries."""
    store = operations.store
    findings = store.list_findings()
    if not findings:
        return FrontendAlerts()
    deliveries = store.list_deliveries()
    by_finding: dict[str, list[DeliveryRow]] = {}
    for row in deliveries:
        by_finding.setdefault(row.finding_key, []).append(row)
    now_iso = datetime.now(UTC).isoformat()
    jira_base_url = operations.settings.jira_base_url
    # Inventory is always synthetic; "simulated" tracks delivery mode so live
    # Slack/Jira runs are not labeled as demo banners.
    simulated = operations.settings.operations_delivery != "live"
    return FrontendAlerts(
        alerts=[
            _frontend_alert(
                finding,
                by_finding.get(finding.finding_key, []),
                jira_base_url=jira_base_url,
                now_iso=now_iso,
                simulated=simulated,
            )
            for finding in findings
        ]
    )


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

