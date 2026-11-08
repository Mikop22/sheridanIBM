from __future__ import annotations

from fastapi.testclient import TestClient


def test_frontend_collections_are_truthful_empty_live_states(client: TestClient) -> None:
    overview = client.get("/api/overview")
    vulnerabilities = client.get("/api/vulnerabilities")
    assets = client.get("/api/assets")
    alerts = client.get("/api/alerts")

    assert overview.status_code == 200
    assert overview.json() == {
        "summary": {
            "totalVulnerabilities": None,
            "criticalPriority": None,
            "exposedAssets": None,
            "predictionHorizonDays": None,
        },
        "priorityVulnerabilities": [],
        "generatedAt": overview.json()["generatedAt"],
        "source": "live",
    }
    assert vulnerabilities.status_code == 200
    assert vulnerabilities.json()["vulnerabilities"] == []
    assert vulnerabilities.json()["source"] == "live"
    assert vulnerabilities.json()["generatedAt"]
    assert assets.json() == {
        "assets": [],
        "matches": [],
        "organizationLabel": None,
        "source": "live",
    }
    assert alerts.json() == {"alerts": [], "source": "live"}


def test_frontend_detail_is_truthful_not_found_without_predictions(client: TestClient) -> None:
    response = client.get("/api/vulnerabilities/CVE-2025-0001")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "vulnerability_not_found"


def test_replay_distinguishes_missing_data_unsupported_and_invalid_month(
    client: TestClient,
) -> None:
    unavailable = client.get("/api/replay", params={"month": "2025-01"})
    unsupported = client.get("/api/replay", params={"month": "2026-01"})
    invalid = client.get("/api/replay", params={"month": "January"})

    assert unavailable.status_code == 503
    assert unavailable.json()["error"]["code"] == "historical_data_unavailable"
    assert unsupported.status_code == 404
    assert unsupported.json()["error"]["code"] == "unsupported_month"
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "validation_error"


def test_openapi_exposes_frontend_contract_routes(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]

    assert "/api/replay" in paths
    assert "/api/overview" in paths
    assert "/api/vulnerabilities" in paths
    assert "/api/vulnerabilities/{vulnerability_id}" in paths
    assert "/api/assets" in paths
    assert "/api/alerts" in paths
