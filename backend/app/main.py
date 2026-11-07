from __future__ import annotations

from uuid import uuid4

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api import router
from app.config import ExplanationProvider, Settings, get_settings
from app.domain.contracts import ErrorBody, ErrorDetail, ErrorResponse
from app.domain.errors import (
    PredictionAlreadyExistsError,
    PredictionNotFoundError,
    ProviderUnavailableError,
)
from app.repositories import InMemoryPredictionRepository, PredictionRepository
from app.services.explanations import ExplanationService, LocalExplanationService


def _error_response(
    request: Request,
    status_code: int,
    code: str,
    message: str,
    details: list[ErrorDetail] | None = None,
) -> JSONResponse:
    trace_id = getattr(request.state, "trace_id", f"request-{uuid4().hex}")
    payload = ErrorResponse(
        error=ErrorBody(code=code, message=message, details=details or []),
        trace_id=trace_id,
    )
    return JSONResponse(status_code=status_code, content=payload.model_dump(mode="json"))


def create_app(
    settings: Settings | None = None,
    repository: PredictionRepository | None = None,
    explanation_service: ExplanationService | None = None,
) -> FastAPI:
    resolved_settings = settings or get_settings()
    app = FastAPI(
        title="Before the Breach — Member 3 API",
        version="1.0.0",
        description=(
            "Versioned prediction ingestion and deterministic, evidence-grounded explanations. "
            "All bundled examples are synthetic."
        ),
    )
    app.state.settings = resolved_settings
    app.state.prediction_repository = repository or InMemoryPredictionRepository()

    if explanation_service is not None:
        app.state.explanation_service = explanation_service
    elif resolved_settings.explanation_provider is ExplanationProvider.LOCAL:
        app.state.explanation_service = LocalExplanationService()
    else:
        app.state.explanation_service = _UnavailableExplanationService()

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

    @app.exception_handler(ProviderUnavailableError)
    async def provider_unavailable_handler(
        request: Request, exc: ProviderUnavailableError
    ) -> JSONResponse:
        return _error_response(
            request,
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "explanation_provider_unavailable",
            str(exc),
        )

    app.include_router(router)
    return app


class _UnavailableExplanationService:
    def explain(self, prediction):  # type: ignore[no-untyped-def]
        raise ProviderUnavailableError(
            "The configured explanation provider is not available in this milestone. "
            "Use EXPLANATION_PROVIDER=local."
        )


app = create_app()
