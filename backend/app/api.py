from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response, status

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
from app.domain.errors import HistoricalDataUnavailableError, UnsupportedHistoricalMonthError
from app.domain.frontend_contracts import (
    FrontendAlerts,
    FrontendAssets,
    FrontendReplay,
    FrontendVulnerabilityList,
)
from app.event_repository import SecurityEventRepository
from app.repositories import PredictionRepository
from app.services.event_processing import SecurityEventProcessor
from app.services.explanations import ExplanationService

router = APIRouter()

SUPPORTED_REPLAY_MONTHS = {f"{year}-{month:02d}" for year in (2024, 2025) for month in range(1, 13)}


def get_repository(request: Request) -> PredictionRepository:
    return request.app.state.prediction_repository


def get_explanation_service(request: Request) -> ExplanationService:
    return request.app.state.explanation_service


def get_event_processor(request: Request) -> SecurityEventProcessor:
    return request.app.state.event_processor


def get_event_repository(request: Request) -> SecurityEventRepository:
    return request.app.state.event_repository


RepositoryDependency = Annotated[PredictionRepository, Depends(get_repository)]
ExplanationDependency = Annotated[ExplanationService, Depends(get_explanation_service)]
EventProcessorDependency = Annotated[SecurityEventProcessor, Depends(get_event_processor)]
EventRepositoryDependency = Annotated[SecurityEventRepository, Depends(get_event_repository)]


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


@router.get("/api/vulnerabilities", response_model=FrontendVulnerabilityList, tags=["frontend"])
def frontend_vulnerabilities() -> FrontendVulnerabilityList:
    """Return an honest empty live collection until real predictions are loaded."""
    return FrontendVulnerabilityList(generatedAt=datetime.now(UTC))


@router.get("/api/assets", response_model=FrontendAssets, tags=["frontend"])
def frontend_assets() -> FrontendAssets:
    """Do not invent simulated assets when no validated inventory is configured."""
    return FrontendAssets()


@router.get("/api/alerts", response_model=FrontendAlerts, tags=["frontend"])
def frontend_alerts() -> FrontendAlerts:
    """Frontend alerts remain empty until an explicit adapter is configured."""
    return FrontendAlerts()


@router.get(
    "/api/replay",
    response_model=FrontendReplay,
    responses={404: {"model": ErrorResponse}, 503: {"model": ErrorResponse}},
    tags=["frontend"],
)
def frontend_replay(
    month: Annotated[str, Query(pattern=r"^\d{4}-(0[1-9]|1[0-2])$")],
) -> FrontendReplay:
    """Refuse to publish replay results until a month passes real-data validation."""
    if month not in SUPPORTED_REPLAY_MONTHS:
        raise UnsupportedHistoricalMonthError(month)
    raise HistoricalDataUnavailableError(month)
