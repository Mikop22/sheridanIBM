from __future__ import annotations

from fastapi.testclient import TestClient

from app.operations.inventory import ASSETS


def test_frontend_threats_include_synthetic_asset_decisions_and_inventory(
    client: TestClient,
) -> None:
    overview = client.get("/api/overview")
    vulnerabilities = client.get("/api/vulnerabilities")
    assets = client.get("/api/assets")
    alerts = client.get("/api/alerts")

    assert overview.status_code == 200
    overview_body = overview.json()
    assert overview_body["summary"] == {
        "totalVulnerabilities": 25,
        "criticalPriority": None,
        "exposedAssets": None,
        "predictionHorizonDays": None,
        "inventoryMatches": 5,
        "topModelRank": 1,
        "draftPullRequests": None,
    }
    assert overview_body["source"] == "live"
    assert overview_body["generatedAt"]
    priority = overview_body["priorityVulnerabilities"]
    assert len(priority) == 25
    assert priority[0]["cveId"] == "CVE-2026-2699"
    assert priority[0]["modelRank"] == 1
    assert priority[0]["rankingScore"] == 0.317252
    assert priority[0]["predictedRisk"] is None
    assert "ShareFile" in (priority[0]["description"] or "")
    assert priority[0]["affectedAsset"] == {
        "id": "demo-asset-identity",
        "name": "Demo Identity Gateway",
        "service": "Synthetic authentication edge",
        "owner": "Demo Identity Team",
    }
    assert any(
        item["key"] == "operations_inventory_match"
        for item in priority[0]["evidenceIndicators"]
    )
    assert "vulnerability description" not in priority[0]["missingInformation"]

    assert vulnerabilities.status_code == 200
    payload = vulnerabilities.json()
    assert len(payload["vulnerabilities"]) == 25
    first = payload["vulnerabilities"][0]
    assert first["cveId"] == "CVE-2026-2699"
    assert first["modelRank"] == 1
    assert first["rankingScore"] == 0.317252
    assert first["rankingScoreKind"] == "relative"
    assert first["description"]
    assert "ShareFile" in first["description"]
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
    assert len(asset_payload["assets"]) == 7 + len(ASSETS)
    assert len(asset_payload["matches"]) == 7 + len(ASSETS)
    assert asset_payload["synthetic"] is True
    assert asset_payload["organizationLabel"] == "SignalZero Synthetic Demo Organization"
    assert asset_payload["provenance"].endswith("not_external_product_intelligence")
    assert any(item["matchStatus"] == "Unaffected" for item in asset_payload["matches"])
    assert alerts.json() == {"alerts": [], "decisions": [], "source": "live"}

    edge = next(
        item for item in asset_payload["assets"] if item["assetId"] == "edge-load-balancer"
    )
    assert edge["vendor"] is None
    assert edge["version"] == "7.2.60.0"
    assert edge["environment"] == "Unknown"
    assert edge["internetExposed"] is None
    assert edge["businessCriticality"] == "Critical"


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


def test_frontend_alerts_populate_after_judge_script(client: TestClient) -> None:
    empty = client.get("/api/alerts")
    assert empty.json() == {"alerts": [], "decisions": [], "source": "live"}

    scripted = client.post("/v1/operations/judge-script", json={"through": "portal"})
    assert scripted.status_code == 200
    assert scripted.json()["findings"]

    alerts = client.get("/api/alerts")
    assert alerts.status_code == 200
    body = alerts.json()
    assert body["source"] == "live"
    assert len(body["alerts"]) >= 1
    first = body["alerts"][0]
    assert first["alertId"]
    assert first["dedupeKey"] == first["alertId"]
    assert first["cveId"]
    assert first["assetId"]
    assert first["priority"] in {"Critical", "High", "Medium"}
    assert first["simulated"] is True  # default OPERATIONS_DELIVERY=recording
    assert first["occurrenceCount"] == 1
    assert first["lifecycle"] in {"Open", "Investigating"}
    assert first["evidence"]
    assert any("synthetic" in item.lower() for item in first["evidence"])
    assert first["history"]
    assert first["history"][0]["kind"] == "detection"
    assert first["slackDelivery"]["provider"] == "slack"
    assert first["jiraDelivery"]["provider"] == "jira"
    assert first["jiraDelivery"]["status"] in {
        "not-attempted",
        "pending",
        "delivered",
        "failed",
        "simulated-not-sent",
    }
    if first["jiraDelivery"]["status"] != "not-attempted":
        assert first["jiraDelivery"]["status"] == "simulated-not-sent"
    if first["slackDelivery"]["status"] != "not-attempted":
        assert first["slackDelivery"]["status"] == "simulated-not-sent"

    recorded = client.post(
        "/v1/operations/remediations/CVE-2026-22739/pull-request",
        json={"pr_url": "https://github.com/Mikop22/securitydemo/pull/1", "checks_passed": True},
    )
    assert recorded.status_code == 200
    overview_after = client.get("/api/overview").json()
    assert overview_after["summary"]["draftPullRequests"] == 1
    alerts_after = client.get("/api/alerts").json()["alerts"]
    portal_alert = next(item for item in alerts_after if item["assetId"] == "customer-portal")
    assert portal_alert["prUrl"] == "https://github.com/Mikop22/securitydemo/pull/1"
    assert portal_alert["prNumber"] == 1
    assert portal_alert["repository"] == "Mikop22/securitydemo"


def test_frontend_alerts_populate_after_kev_step(client: TestClient) -> None:
    response = client.post("/v1/operations/judge-script", json={"through": "kev"})
    assert response.status_code == 200

    alerts = client.get("/api/alerts").json()["alerts"]
    assert alerts
    edge = next(item for item in alerts if item["assetId"] == "edge-load-balancer")
    assert edge["cveId"] == "CVE-2026-8037"
    assert edge["priority"] == "Critical"
    assert edge["simulated"] is True


def test_frontend_detail_finds_real_prediction_case_insensitively(client: TestClient) -> None:
    response = client.get("/api/vulnerabilities/cve-2026-2699")

    assert response.status_code == 200
    assert response.json()["vulnerability"]["cveId"] == "CVE-2026-2699"
    assert "ShareFile" in (response.json()["vulnerability"]["description"] or "")


def test_frontend_detail_returns_not_found_for_unknown_cve(client: TestClient) -> None:
    response = client.get("/api/vulnerabilities/CVE-2025-0001")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "vulnerability_not_found"


def test_openapi_exposes_frontend_contract_routes(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]

    assert "/api/overview" in paths
    assert "/api/vulnerabilities" in paths
    assert "/api/vulnerabilities/{vulnerability_id}" in paths
    assert "/api/assets" in paths
    assert "/api/alerts" in paths
    assert "/api/replay" not in paths
