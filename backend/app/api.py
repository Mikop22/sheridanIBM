from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

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
    FrontendAlerts,
    FrontendArtifactProvenance,
    FrontendAssets,
    FrontendEvidenceIndicator,
    FrontendOverview,
    FrontendVulnerability,
    FrontendVulnerabilityDetail,
    FrontendVulnerabilityList,
)
from app.event_repository import SecurityEventRepository
from app.operations.models import (
    JudgeScriptReport,
    JudgeScriptRequest,
    PullRequestRecord,
    RankingsResponse,
    ReadinessResponse,
)
from app.repositories import PredictionRepository
from app.services.event_processing import SecurityEventProcessor
from app.services.explanations import ExplanationService, LocalExplanationService
from app.services.prediction_artifacts import (
    SCORE_INTERPRETATION,
    PredictionArtifact,
    PredictionArtifactRecord,
)

router = APIRouter()


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


RepositoryDependency = Annotated[PredictionRepository, Depends(get_repository)]
ExplanationDependency = Annotated[ExplanationService, Depends(get_explanation_service)]
EventProcessorDependency = Annotated[SecurityEventProcessor, Depends(get_event_processor)]
EventRepositoryDependency = Annotated[SecurityEventRepository, Depends(get_event_repository)]
ArtifactDependency = Annotated[PredictionArtifact, Depends(get_prediction_artifact)]


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
    return FrontendVulnerability(
        cveId=prediction.vulnerability.vulnerability_id,
        snapshotMonth=record.snapshot_month,
        modelRank=prediction.rank,
        rankingScore=prediction.score,
        evidenceIndicators=evidence_indicators,
        modelVersion=prediction.model_version,
        scoreScale=prediction.score_scale,
        scoreInterpretation=SCORE_INTERPRETATION,
        componentScores=record.component_scores,
        artifact=FrontendArtifactProvenance(
            artifactId=artifact.artifact_id,
            sourceKind=artifact.source_kind,
            recordCount=len(artifact.records),
        ),
        missingInformation=[
            "vulnerability description",
            "CVSS score",
            "EPSS score",
            "feature contribution values",
            "affected asset associations",
        ],
        groundedExplanation=explanation,
    )


@router.get("/api/vulnerabilities", response_model=FrontendVulnerabilityList, tags=["frontend"])
def frontend_vulnerabilities(artifact: ArtifactDependency) -> FrontendVulnerabilityList:
    """Return startup-loaded Member 1 predictions without request-time model execution."""
    return FrontendVulnerabilityList(
        vulnerabilities=[_frontend_vulnerability(record, artifact) for record in artifact.records]
    )


@router.get("/api/overview", response_model=FrontendOverview, tags=["frontend"])
def frontend_overview() -> FrontendOverview:
    """Return nullable totals instead of inventing dashboard statistics."""
    return FrontendOverview(generatedAt=datetime.now(UTC))


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
    """Do not invent simulated assets when no validated inventory is configured."""
    return FrontendAssets()


@router.get("/api/alerts", response_model=FrontendAlerts, tags=["frontend"])
def frontend_alerts() -> FrontendAlerts:
    """Frontend alerts remain empty until an explicit adapter is configured."""
    return FrontendAlerts()


def _operations(request: Request):  # type: ignore[no-untyped-def]
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

