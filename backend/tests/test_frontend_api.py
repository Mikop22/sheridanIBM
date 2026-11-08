from __future__ import annotations

from fastapi.testclient import TestClient


def test_frontend_threats_use_real_artifact_and_other_collections_remain_empty(
    client: TestClient,
) -> None:
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
    payload = vulnerabilities.json()
    assert len(payload["vulnerabilities"]) == 25
    first = payload["vulnerabilities"][0]
    assert first["cveId"] == "CVE-2026-2699"
    assert first["modelRank"] == 1
    assert first["rankingScore"] == 0.317252
    assert first["rankingScoreKind"] == "relative"
    assert first["description"] is None
    assert first["cvss"] is None
    assert first["epss"] is None
    assert first["predictedRisk"] is None
    assert first["affectedAsset"] is None
    assert first["assetMatchStatus"] == "unknown"
    assert first["artifact"]["sourceKind"] == "summary_json"
    assert first["artifact"]["recordCount"] == 25
    assert first["artifact"]["artifactId"].startswith("sha256:")
    assert first["componentScores"]["score_v1_ensemble"] == 0.317252
    assert "calibrated exploitation probability" in first["scoreInterpretation"]
    assert first["groundedExplanation"]["provider"] == "local"
    assert "CVSS score" in first["missingInformation"]
    assert payload["source"] == "live"
    assert payload["generatedAt"] is None
    assert assets.json() == {
        "assets": [],
        "matches": [],
        "organizationLabel": None,
        "source": "live",
    }
    assert alerts.json() == {"alerts": [], "source": "live"}


def test_frontend_detail_finds_real_prediction_case_insensitively(client: TestClient) -> None:
    response = client.get("/api/vulnerabilities/cve-2026-2699")

    assert response.status_code == 200
    assert response.json()["vulnerability"]["cveId"] == "CVE-2026-2699"
    assert response.json()["vulnerability"]["description"] is None


def test_frontend_detail_returns_not_found_for_unknown_cve(client: TestClient) -> None:
    response = client.get("/api/vulnerabilities/CVE-2025-0001")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "vulnerability_not_found"


def test_replay_route_is_removed(client: TestClient) -> None:
    response = client.get("/api/replay", params={"month": "2025-01"})

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "route_not_found"


def test_openapi_exposes_frontend_contract_routes(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]

    assert "/api/replay" not in paths
    assert "/api/overview" in paths
    assert "/api/vulnerabilities" in paths
    assert "/api/vulnerabilities/{vulnerability_id}" in paths
    assert "/api/assets" in paths
    assert "/api/alerts" in paths
