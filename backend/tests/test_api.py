from __future__ import annotations

from copy import deepcopy

from fastapi.testclient import TestClient

from app.config import ExplanationProvider as ConfigExplanationProvider
from app.config import Settings
from app.domain.contracts import ExplanationProvider, GroundedStatement
from app.main import create_app
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
