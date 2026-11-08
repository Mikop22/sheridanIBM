from __future__ import annotations

from uuid import uuid4

import httpx
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api import router
from app.config import ExplanationProvider as ConfigExplanationProvider
from app.config import Settings, get_settings
from app.domain.contracts import ErrorBody, ErrorDetail, ErrorResponse, ExplanationProvider
from app.domain.errors import (
    EventAlreadyExistsError,
    EventNotFoundError,
    EventStoreUnavailableError,
    HistoricalDataUnavailableError,
    InvalidRecommendationTransitionError,
    PredictionAlreadyExistsError,
    PredictionNotFoundError,
    RecommendationNotFoundError,
    UnsupportedHistoricalMonthError,
)
from app.event_repository import SecurityEventRepository
from app.repositories import InMemoryPredictionRepository, PredictionRepository
from app.services.event_processing import RiskThreshold, SecurityEventProcessor
from app.services.explanations import (
    ExplanationService,
    ExternalExplanationService,
    LocalExplanationService,
)
from app.services.providers import HuggingFaceClient, OllamaGraniteClient, WatsonxGraniteClient


def _error_response(
    request: Request,
    status_code: int,
    code: str,
    message: str,
    details: list[ErrorDetail] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    trace_id = getattr(request.state, "trace_id", f"request-{uuid4().hex}")
    payload = ErrorResponse(
        error=ErrorBody(code=code, message=message, details=details or []),
        trace_id=trace_id,
    )
    response_headers = dict(headers or {})
    response_headers["X-Trace-ID"] = trace_id
    return JSONResponse(
        status_code=status_code,
        content=payload.model_dump(mode="json"),
        headers=response_headers,
    )


def create_app(
    settings: Settings | None = None,
    repository: PredictionRepository | None = None,
    explanation_service: ExplanationService | None = None,
    event_repository: SecurityEventRepository | None = None,
) -> FastAPI:
    resolved_settings = settings or get_settings()
    app = FastAPI(
        title="Before the Breach — Member 3 API",
        version="1.0.0",
        description=(
            "Versioned prediction ingestion, evidence-grounded explanations, and deterministic "
            "security event recommendations. All bundled examples are synthetic."
        ),
    )
    app.state.settings = resolved_settings
    app.state.prediction_repository = repository or InMemoryPredictionRepository()
    app.state.event_repository = event_repository or SecurityEventRepository(
        resolved_settings.event_database_path
    )
    app.state.event_processor = SecurityEventProcessor(
        app.state.prediction_repository,
        app.state.event_repository,
        RiskThreshold(
            value=resolved_settings.event_risk_threshold,
            scale_minimum=resolved_settings.event_threshold_scale_minimum,
            scale_maximum=resolved_settings.event_threshold_scale_maximum,
            higher_is_riskier=resolved_settings.event_threshold_higher_is_riskier,
        ),
    )

    allowed_origins = resolved_settings.allowed_cors_origins()
    if allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=allowed_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Content-Type", "Authorization"],
        )

    if explanation_service is not None:
        app.state.explanation_service = explanation_service
    else:
        app.state.explanation_service = _build_explanation_service(resolved_settings)

    @app.middleware("http")
    async def add_trace_id(request: Request, call_next):  # type: ignore[no-untyped-def]
        request.state.trace_id = f"request-{uuid4().hex}"
        response = await call_next(request)
        response.headers["X-Trace-ID"] = request.state.trace_id
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        details = [
            ErrorDetail(
                location=list(error["loc"]),
                message=error["msg"],
                error_type=error["type"],
            )
            for error in exc.errors()
        ]
        return _error_response(
            request,
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "validation_error",
            "Request validation failed.",
            details,
        )

    @app.exception_handler(PredictionAlreadyExistsError)
    async def duplicate_handler(
        request: Request, exc: PredictionAlreadyExistsError
    ) -> JSONResponse:
        return _error_response(
            request,
            status.HTTP_409_CONFLICT,
            "prediction_already_exists",
            f"Prediction {exc.prediction_id!r} already exists.",
        )

    @app.exception_handler(PredictionNotFoundError)
    async def not_found_handler(request: Request, exc: PredictionNotFoundError) -> JSONResponse:
        return _error_response(
            request,
            status.HTTP_404_NOT_FOUND,
            "prediction_not_found",
            f"Prediction {exc.prediction_id!r} was not found.",
        )

    @app.exception_handler(EventAlreadyExistsError)
    async def event_conflict_handler(
        request: Request, exc: EventAlreadyExistsError
    ) -> JSONResponse:
        return _error_response(
            request,
            status.HTTP_409_CONFLICT,
            "event_already_exists",
            f"Event {exc.event_id!r} already exists with different content.",
        )

    @app.exception_handler(EventNotFoundError)
    async def event_not_found_handler(request: Request, exc: EventNotFoundError) -> JSONResponse:
        return _error_response(
            request,
            status.HTTP_404_NOT_FOUND,
            "event_not_found",
            f"Event {exc.event_id!r} was not found.",
        )

    @app.exception_handler(RecommendationNotFoundError)
    async def recommendation_not_found_handler(
        request: Request, exc: RecommendationNotFoundError
    ) -> JSONResponse:
        return _error_response(
            request,
            status.HTTP_404_NOT_FOUND,
            "recommendation_not_found",
            f"Recommendation {exc.recommendation_id!r} was not found.",
        )

    @app.exception_handler(InvalidRecommendationTransitionError)
    async def invalid_transition_handler(
        request: Request, exc: InvalidRecommendationTransitionError
    ) -> JSONResponse:
        return _error_response(
            request,
            status.HTTP_409_CONFLICT,
            "invalid_recommendation_transition",
            (
                f"Recommendation {exc.recommendation_id!r} cannot be changed from "
                f"{exc.current_status!r}."
            ),
        )

    @app.exception_handler(EventStoreUnavailableError)
    async def event_store_unavailable_handler(
        request: Request, exc: EventStoreUnavailableError
    ) -> JSONResponse:
        return _error_response(
            request,
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "event_store_unavailable",
            "The event workflow store is temporarily unavailable.",
            headers={"Retry-After": "1"},
        )

    @app.exception_handler(HistoricalDataUnavailableError)
    async def historical_unavailable_handler(
        request: Request, exc: HistoricalDataUnavailableError
    ) -> JSONResponse:
        return _error_response(
            request,
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "historical_data_unavailable",
            f"No validated historical prediction data is available for {exc.month}.",
        )

    @app.exception_handler(UnsupportedHistoricalMonthError)
    async def unsupported_month_handler(
        request: Request, exc: UnsupportedHistoricalMonthError
    ) -> JSONResponse:
        return _error_response(
            request,
            status.HTTP_404_NOT_FOUND,
            "unsupported_month",
            f"Historical month {exc.month} is not supported.",
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        if exc.status_code == status.HTTP_404_NOT_FOUND:
            code, message = "route_not_found", "The requested route was not found."
        elif exc.status_code == status.HTTP_405_METHOD_NOT_ALLOWED:
            code, message = "method_not_allowed", "The request method is not allowed."
        else:
            code, message = "http_error", "The request could not be completed."
        return _error_response(
            request,
            exc.status_code,
            code,
            message,
            headers=dict(exc.headers or {}),
        )

    @app.exception_handler(Exception)
    async def internal_error_handler(request: Request, exc: Exception) -> JSONResponse:
        return _error_response(
            request,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "internal_server_error",
            "The server could not complete the request.",
        )

    app.include_router(router)
    return app


def _build_explanation_service(settings: Settings) -> ExplanationService:
    if settings.explanation_provider is ConfigExplanationProvider.LOCAL:
        return LocalExplanationService()

    timeout = httpx.Timeout(
        connect=settings.provider_connect_timeout,
        read=settings.provider_read_timeout,
        write=settings.provider_read_timeout,
        pool=settings.provider_connect_timeout,
    )
    if settings.explanation_provider is ConfigExplanationProvider.OLLAMA:
        client = OllamaGraniteClient(
            settings.ollama_base_url,
            settings.ollama_model,
            timeout=timeout,
            max_output_tokens=settings.provider_max_output_tokens,
        )
    elif settings.explanation_provider is ConfigExplanationProvider.HUGGINGFACE:
        client = HuggingFaceClient(
            settings.hf_token,
            settings.hf_model_id,
            response_model_id=settings.hf_response_model_id,
            timeout=timeout,
            max_output_tokens=settings.provider_max_output_tokens,
        )
    else:
        client = WatsonxGraniteClient(
            settings.watsonx_api_key,
            settings.watsonx_project_id,
            settings.watsonx_url,
            settings.watsonx_model_id,
            timeout=timeout,
            max_output_tokens=settings.provider_max_output_tokens,
        )
    return ExternalExplanationService(
        requested_provider=ExplanationProvider(settings.explanation_provider.value),
        client=client,
    )


app = create_app()
