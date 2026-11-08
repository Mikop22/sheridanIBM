from __future__ import annotations

from fastapi.testclient import TestClient


def test_frontend_threats_include_synthetic_asset_decisions_and_inventory(
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
    assert first["affectedAsset"]["id"] == "demo-asset-identity"
    assert first["assetMatchStatus"] == "confirmed_affected"
    assert first["operationalDecision"] == "URGENT"
    assert first["remediationEligibility"] == "CODE_REMEDIABLE"
    assert first["agentEligible"] is True
    assert len(first["assetDecisions"]) == 2
    assert {item["asset_id"] for item in first["assetDecisions"]} == {
        "demo-asset-analytics",
        "demo-asset-identity",
    }
    assert first["artifact"]["sourceKind"] == "summary_json"
    assert first["artifact"]["recordCount"] == 25
    assert first["artifact"]["artifactId"].startswith("sha256:")
    assert first["componentScores"]["score_v1_ensemble"] == 0.317252
    assert "calibrated exploitation probability" in first["scoreInterpretation"]
    assert first["groundedExplanation"]["provider"] == "local"
    assert "CVSS score" in first["missingInformation"]
    assert payload["source"] == "live"
    assert payload["generatedAt"] is None
    asset_payload = assets.json()
    assert len(asset_payload["assets"]) == 7
    assert asset_payload["synthetic"] is True
    assert asset_payload["organizationLabel"] == "SignalZero Synthetic Demo Organization"
    assert asset_payload["provenance"].endswith("not_external_product_intelligence")
    assert any(item["matchStatus"] == "Unaffected" for item in asset_payload["matches"])
    assert alerts.json() == {"alerts": [], "decisions": [], "source": "live"}


def test_unmapped_lower_ranked_threat_remains_unknown_and_monitored(
    client: TestClient,
) -> None:
    response = client.get("/api/vulnerabilities/CVE-2026-93643")

    vulnerability = response.json()["vulnerability"]
    assert vulnerability["modelRank"] == 25
    assert vulnerability["assetMatchStatus"] == "unknown"
    assert vulnerability["affectedAsset"] is None
    assert vulnerability["operationalDecision"] == "MONITOR"
    assert vulnerability["remediationEligibility"] == "NEEDS_INVESTIGATION"
    assert vulnerability["agentEligible"] is False


def test_frontend_remediation_contract_lists_persistent_decision_without_delivery_claims(
    client: TestClient, prediction_payload: dict, event_payload: dict
) -> None:
    client.post("/v1/predictions", json=prediction_payload)
    created = client.post("/v1/security-events", json=event_payload)

    response = client.get("/api/alerts")

    assert created.status_code == 200
    assert response.status_code == 200
    payload = response.json()
    assert payload["alerts"] == []
    assert len(payload["decisions"]) == 1
    decision = payload["decisions"][0]
    assert decision["operationalDecision"] == "URGENT"
    assert decision["remediationEligibility"] == "CODE_REMEDIABLE"
    assert decision["agentEligible"] is True
    assert decision["executionAuthorized"] is False
    assert decision["decidedBy"] is None
    assert decision["decisionReason"] is None
    assert len(decision["activityHistory"]) == 1
    assert decision["activityHistory"][0]["eventId"] == event_payload["event_id"]


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
