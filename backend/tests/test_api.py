from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import ExplanationProvider as ConfigExplanationProvider
from app.config import Settings
from app.domain.contracts import ExplanationProvider, GroundedStatement
from app.main import create_app
from app.repositories import InMemoryPredictionRepository
from app.services.explanations import ExternalExplanationService
from app.services.providers import ProviderOutput, ProviderResult


def test_health_reports_local_provider_ready(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "explanation_provider": "local",
        "provider_ready": True,
    }
    assert response.headers["X-Trace-ID"].startswith("request-")


def test_health_returns_503_when_configured_provider_is_not_ready(tmp_path: Path) -> None:
    settings = Settings(
        explanation_provider=ConfigExplanationProvider.HUGGINGFACE,
        hf_token="",
        hf_model_id="",
        event_database_path=tmp_path / "events.db",
    )
    with TestClient(create_app(settings)) as external_client:
        response = external_client.get("/health")

    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"
    assert response.headers["X-Trace-ID"].startswith("request-")


def test_ollama_configuration_is_ready_without_hosted_credentials(tmp_path: Path) -> None:
    settings = Settings(
        explanation_provider=ConfigExplanationProvider.OLLAMA,
        event_database_path=tmp_path / "events.db",
    )
    with TestClient(create_app(settings)) as ollama_client:
        response = ollama_client.get("/health")

    assert response.status_code == 200
    assert response.json()["explanation_provider"] == "ollama"
    assert response.json()["provider_ready"] is True


def test_ollama_configuration_rejects_remote_hosts() -> None:
    with pytest.raises(ValidationError, match="loopback HTTP origin"):
        Settings(ollama_base_url="https://hosted-ollama.example")


def test_prediction_artifact_freshness_month_validation() -> None:
    assert (
        Settings(prediction_artifact_min_snapshot_month="").prediction_artifact_min_snapshot_month
        is None
    )
    assert (
        Settings(
            prediction_artifact_min_snapshot_month="2026-09"
        ).prediction_artifact_min_snapshot_month
        == "2026-09"
    )
    with pytest.raises(ValidationError, match="must use YYYY-MM"):
        Settings(prediction_artifact_min_snapshot_month="September 2026")


def test_prediction_ingestion_and_retrieval(client: TestClient, prediction_payload: dict) -> None:
    created = client.post("/v1/predictions", json=prediction_payload)
    retrieved = client.get(f"/v1/predictions/{prediction_payload['prediction_id']}")

    assert created.status_code == 201
    assert created.json() == prediction_payload
    assert retrieved.status_code == 200
    assert retrieved.json() == prediction_payload


def test_duplicate_prediction_returns_stable_error(
    client: TestClient, prediction_payload: dict
) -> None:
    assert client.post("/v1/predictions", json=prediction_payload).status_code == 201

    response = client.post("/v1/predictions", json=prediction_payload)

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "prediction_already_exists"
    assert response.json()["trace_id"].startswith("request-")


def test_missing_prediction_returns_stable_error(client: TestClient) -> None:
    response = client.get("/v1/predictions/does-not-exist")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "prediction_not_found"


def test_invalid_score_returns_validation_error(
    client: TestClient, prediction_payload: dict
) -> None:
    invalid = deepcopy(prediction_payload)
    invalid["score"] = 2.0

    response = client.post("/v1/predictions", json=invalid)

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert "declared score scale" in response.json()["error"]["details"][0]["message"]


def test_contract_numeric_and_boolean_fields_reject_string_coercion(
    client: TestClient, prediction_payload: dict
) -> None:
    for path, value in [
        (("score",), "0.82"),
        (("rank",), "4"),
        (("score_scale", "higher_is_riskier"), "false"),
    ]:
        invalid = deepcopy(prediction_payload)
        target = invalid
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value

        response = client.post("/v1/predictions", json=invalid)

        assert response.status_code == 422
        assert response.json()["error"]["code"] == "validation_error"


def test_unmatched_routes_and_unhandled_errors_use_traced_error_envelope(
    tmp_path: Path,
) -> None:
    class FailingRepository(InMemoryPredictionRepository):
        def get(self, prediction_id: str):  # type: ignore[no-untyped-def]
            raise RuntimeError("synthetic internal failure")

    app = create_app(
        Settings(event_database_path=tmp_path / "events.db"),
        repository=FailingRepository(),
    )
    with TestClient(app, raise_server_exceptions=False) as test_client:
        missing_route = test_client.get("/does-not-exist")
        wrong_method = test_client.put("/health")
        server_error = test_client.get("/v1/predictions/synthetic-id")

    assert missing_route.status_code == 404
    assert missing_route.json()["error"]["code"] == "route_not_found"
    assert wrong_method.status_code == 405
    assert wrong_method.json()["error"]["code"] == "method_not_allowed"
    assert wrong_method.headers["Allow"] == "GET"
    assert server_error.status_code == 500
    assert server_error.json()["error"]["code"] == "internal_server_error"
    assert "synthetic internal failure" not in server_error.text
    for response in (missing_route, wrong_method, server_error):
        assert response.json()["schema_version"] == "1.0"
        assert response.headers["X-Trace-ID"] == response.json()["trace_id"]


def test_cors_uses_explicit_origin_allowlist(tmp_path: Path) -> None:
    app = create_app(
        Settings(
            event_database_path=tmp_path / "events.db",
            cors_allowed_origins="http://localhost:3000",
        )
    )
    preflight_headers = {
        "Origin": "http://localhost:3000",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type",
    }
    with TestClient(app) as cors_client:
        allowed = cors_client.options("/v1/predictions", headers=preflight_headers)
        denied = cors_client.options(
            "/v1/predictions",
            headers={**preflight_headers, "Origin": "https://untrusted.example"},
        )

    assert allowed.status_code == 200
    assert allowed.headers["Access-Control-Allow-Origin"] == "http://localhost:3000"
    assert "Access-Control-Allow-Origin" not in denied.headers


def test_explanation_is_deterministic_and_grounded(
    client: TestClient, prediction_payload: dict
) -> None:
    client.post("/v1/predictions", json=prediction_payload)

    first = client.post(f"/v1/predictions/{prediction_payload['prediction_id']}/explanation")
    second = client.post(f"/v1/predictions/{prediction_payload['prediction_id']}/explanation")

    assert first.status_code == 200
    assert first.json() == second.json()
    explanation = first.json()
    assert explanation["provider"] == "local"
    assert explanation["generation_status"] == "complete"
    assert explanation["context"]["model_score"] == prediction_payload["score"]
    assert explanation["context"]["evidence"][0]["source"] == "synthetic-test-fixture"
    assert explanation["provider_metadata"]["fallback_status"] == "not_used"
    assert explanation["trace_id"].startswith("local-")
    assert all(item["source_refs"] for item in explanation["observed_facts"])
    assert all(item["source_refs"] for item in explanation["interpretations"])
    assert not any("remediat" in item["text"].lower() for item in explanation["observed_facts"])


def test_local_mode_never_constructs_an_external_http_client(
    client: TestClient, prediction_payload: dict, monkeypatch
) -> None:
    def reject_http_client(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("local explanation attempted external HTTP")

    monkeypatch.setattr("app.services.providers.httpx.Client", reject_http_client)
    assert client.post("/v1/predictions", json=prediction_payload).status_code == 201

    response = client.post(f"/v1/predictions/{prediction_payload['prediction_id']}/explanation")

    assert response.status_code == 200
    assert response.json()["provider"] == "local"


def test_explanation_endpoint_reports_external_provider_metadata(prediction_payload: dict) -> None:
    class SuccessfulClient:
        def generate(self, prediction):  # type: ignore[no-untyped-def]
            return ProviderResult(
                output=ProviderOutput(
                    interpretations=[
                        GroundedStatement(
                            text="The submitted score is the model's supplied risk estimate.",
                            source_refs=["prediction:score"],
                        )
                    ],
                    limitations=["Only submitted prediction data was considered."],
                ),
                model_id="configured/model",
            )

    service = ExternalExplanationService(ExplanationProvider.HUGGINGFACE, SuccessfulClient())
    app = create_app(
        Settings(explanation_provider=ConfigExplanationProvider.HUGGINGFACE),
        explanation_service=service,
    )
    with TestClient(app) as external_client:
        external_client.post("/v1/predictions", json=prediction_payload)
        response = external_client.post(
            f"/v1/predictions/{prediction_payload['prediction_id']}/explanation"
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["provider"] == "huggingface"
    assert payload["generation_status"] == "complete"
    assert payload["provider_metadata"] == {
        "requested_provider": "huggingface",
        "actual_provider": "huggingface",
        "model_id": "configured/model",
        "requested_generation_status": "complete",
        "fallback_status": "not_used",
    }


def test_openapi_lists_public_endpoints(client: TestClient) -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200
    paths = response.json()["paths"]
    assert "/health" in paths
    assert "/v1/predictions" in paths
    assert "/v1/predictions/{prediction_id}" in paths
    assert "/v1/predictions/{prediction_id}/explanation" in paths
    assert "/v1/security-events" in paths
    assert "/v1/security-events/{event_id}" in paths
    assert "/v1/predictions/{prediction_id}/recommendations" in paths
    assert "/v1/recommendations/{recommendation_id}/decision" in paths
    decision_422 = paths["/v1/recommendations/{recommendation_id}/decision"]["post"]["responses"][
        "422"
    ]
    assert decision_422["content"]["application/json"]["schema"]["$ref"].endswith("/ErrorResponse")
