from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import ExplanationProvider, Settings
from app.main import create_app
from app.operations.policy import decide, notification_allowed

REPO_ROOT = Path(__file__).resolve().parents[2]


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "explanation_provider": ExplanationProvider.LOCAL,
        "event_database_path": tmp_path / "events.db",
        "operations_database_path": tmp_path / "operations.db",
        "operations_delivery": "recording",
        "slack_webhook_url": "",
        "slack_channel_id": "",
        "slack_app_id": "",
        "slack_team_id": "",
        "jira_base_url": "",
        "jira_email": "",
        "jira_api_token": "",
        "jira_project_key": "",
        "entire_token": "",
        "github_token": "",
        "event_risk_threshold": 0.75,
        "event_threshold_scale_minimum": 0.0,
        "event_threshold_scale_maximum": 1.0,
        "event_threshold_higher_is_riskier": True,
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def _client(tmp_path: Path, **overrides: object) -> TestClient:
    return TestClient(create_app(_settings(tmp_path, **overrides)))


def test_saved_ranking_is_labeled_as_a_ranking_score(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        body = client.get("/v1/operations/rankings").json()

    assert body["source"].endswith("submission_v1_summary.json")
    first = body["rankings"][0]
    portal = next(row for row in body["rankings"] if row["cve_id"] == "CVE-2026-22739")
    assert first["cve_id"] == "CVE-2026-2699"
    assert first["rank"] == 1
    assert first["ranking_score"] == pytest.approx(0.317252)
    assert first["score_kind"] == "ranking_score"
    assert first["scoreboard_rows"] == 72670
    assert portal["rank"] == 6
    assert portal["asset_id"] == "customer-portal"
    assert portal["inventory_synthetic"] is True
    unmatched = next(row for row in body["rankings"] if row["cve_id"] == "CVE-2026-1603")
    assert unmatched["match_status"] == "unmatched"


def test_judge_script_records_side_effects_without_calling_the_network(
    tmp_path: Path, monkeypatch
) -> None:
    def explode(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("external call")

    monkeypatch.setattr("app.operations.delivery.httpx.Client", explode)
    monkeypatch.setattr("app.operations.delivery.httpx.post", explode)
    monkeypatch.setattr(subprocess, "run", explode)

    with _client(tmp_path) as client:
        first = client.post("/v1/operations/judge-script", json={})
        second = client.post("/v1/operations/judge-script", json={})
        readiness = client.get("/v1/operations/readiness")

    assert first.status_code == 200
    report = first.json()
    kinds = [item["kind"] for item in report["deliveries"]]
    assert kinds == [
        "jira_create",
        "jira_update",
        "slack_urgent",
        "jira_create",
        "jira_create",
    ]
    assert all(
        item["mode"] == "recording" and item["delivered"] is False for item in report["deliveries"]
    )
    assert report["deliveries"][2]["body"].startswith("Urgent: CVE-2026-8037")
    assert "not an exploitation probability" in report["deliveries"][2]["body"]
    assert "2026-08-07" in report["deliveries"][2]["body"]
    july = next(step for step in report["steps"] if step["step"] == "july")
    assert july["actions"] == ["UPSERT_JIRA"]
    assert "NOTIFY_SLACK_URGENT" not in july["actions"]
    findings = {item["finding_key"]: item for item in report["findings"]}
    assert findings["CVE-2026-8037::edge-load-balancer"]["level"] == "escalate"
    assert findings["CVE-2026-8037::edge-load-balancer"]["jira_issue_key"] == (
        "REC-CVE-2026-8037-edge-load-balancer"
    )
    assert findings["CVE-2026-22739::customer-portal"]["level"] == "act"
    assert findings["CVE-2026-22739::customer-portal-config-loader"]["level"] == "act"
    assert report["undispatched"][0]["cve_id"] == "CVE-2026-2699"
    assert report["undispatched"][0]["dispatch"] is False
    assert not any("CVE-2026-2699" in item["finding_key"] for item in report["deliveries"])
    jobs = {item["finding_key"]: item for item in report["jobs"]}
    dependency_job = jobs["CVE-2026-22739::customer-portal"]
    assert dependency_job["status"] == "blocked_pending_credentials"
    assert dependency_job["branch"] == "signalzero/cve-2026-22739"
    assert "Do not upgrade to 5.0.2" in dependency_job["task"]
    assert "Do not merge" in dependency_job["task"]
    assert "does not prove the path traversal is closed" in dependency_job["task"]
    code_job = jobs["CVE-2026-22739::customer-portal-config-loader"]
    assert code_job["branch"] == "signalzero/cve-2026-22739-code"
    assert "Rewrite resolve_config_path" in code_job["task"]
    assert "Do not change pom.xml" in code_job["task"]
    assert "check_code_fix.py" in code_job["task"]

    replay = second.json()
    assert replay["deliveries"] == report["deliveries"]
    assert all(step["suppressed"] for step in replay["steps"])
    assert len(replay["jobs"]) == 2
    assert readiness.json()["live_calls_enabled"] is False
    missing = readiness.json()["missing"]
    assert "GH_TOKEN" in missing
    assert any(item.startswith("SLACK_") for item in missing)
    assert readiness.json()["github_push_verified"] is False


def test_review_notice_waits_for_a_recorded_pull_request(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        client.post("/v1/operations/judge-script", json={"through": "portal"})
        recorded = client.post(
            "/v1/operations/remediations/CVE-2026-22739/pull-request",
            json={
                "pr_url": "https://github.com/Mikop22/securitydemo/pull/1",
                "checks_passed": True,
            },
        )
        repeated = client.post(
            "/v1/operations/remediations/CVE-2026-22739/pull-request",
            json={
                "pr_url": "https://github.com/Mikop22/securitydemo/pull/1",
                "checks_passed": True,
            },
        )
        rejected = client.post(
            "/v1/operations/remediations/CVE-2026-22739/pull-request",
            json={"pr_url": "https://example.com/pull/1", "checks_passed": True},
        )

    assert recorded.status_code == 200
    reviews = [item for item in recorded.json()["deliveries"] if item["kind"] == "slack_review"]
    assert len(reviews) == 1
    assert "does not prove the vulnerability is closed" in reviews[0]["body"]
    assert recorded.json()["jobs"][0]["pr_url"].endswith("/pull/1")
    assert repeated.status_code == 200
    assert sum(item["kind"] == "slack_review" for item in repeated.json()["deliveries"]) == 1
    assert rejected.status_code == 422


def test_review_budget_blocks_the_sixth_notice(tmp_path: Path) -> None:
    from app.operations.store import DeliveryRow, OperationsStore

    with _client(tmp_path) as client:
        client.post("/v1/operations/judge-script", json={"through": "portal"})
        store = OperationsStore(tmp_path / "operations.db")
        for _ in range(5):
            store.add_delivery(
                DeliveryRow(
                    kind="slack_review",
                    finding_key="other::asset",
                    team="portal",
                    delivered=False,
                    mode="recording",
                    external_id=None,
                    body="prior",
                    detail="seed",
                    created_on=store.list_deliveries()[0].created_on,
                )
            )
        recorded = client.post(
            "/v1/operations/remediations/CVE-2026-22739/pull-request",
            json={
                "pr_url": "https://github.com/Mikop22/securitydemo/pull/2",
                "checks_passed": False,
            },
        )

    assert recorded.status_code == 200
    assert recorded.json()["steps"][0]["reason"] == (
        "Pull request recorded. The review-notice budget is exhausted."
    )
    review_for_second = [
        item
        for item in recorded.json()["deliveries"]
        if item["kind"] == "slack_review" and "pull/2" in item["body"]
    ]
    assert review_for_second == []
    assert recorded.json()["jobs"][0]["pr_url"].endswith("/pull/2")


def test_policy_hysteresis_and_urgent_budget() -> None:
    base = dict(
        population_percentile=0.96,
        match_status="confirmed",
        owner_known=True,
        criticality="high",
        urgent=False,
        route="dependency_upgrade",
        fix_verified=True,
        human_resolved=False,
    )
    assert decide(**base, prior_level=None).level == "investigate"
    assert decide(**base, prior_level="act").level == "act"
    dropped = decide(**{**base, "population_percentile": 0.94}, prior_level="act")
    assert dropped.level == "observe"
    held = decide(
        population_percentile=0.1,
        match_status="confirmed",
        owner_known=True,
        criticality="critical",
        urgent=False,
        route="appliance",
        fix_verified=False,
        prior_level="escalate",
        human_resolved=False,
    )
    assert held.level == "escalate"
    cleared = decide(
        population_percentile=0.1,
        match_status="confirmed",
        owner_known=True,
        criticality="critical",
        urgent=False,
        route="appliance",
        fix_verified=False,
        prior_level="escalate",
        human_resolved=True,
    )
    assert cleared.level == "observe"
    assert notification_allowed("slack_urgent", 100) is True
    assert notification_allowed("slack_routine", 3) is False
    assert notification_allowed("slack_review", 4) is True
    assert notification_allowed("slack_review", 5) is False


def test_seed_repository_check_fails_on_the_vulnerable_pin() -> None:
    script = REPO_ROOT / "demo" / "securitydemo" / "check_version.py"
    completed = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 1
    assert "4.3.2" in completed.stderr
    pom = (REPO_ROOT / "demo" / "securitydemo" / "pom.xml").read_text(encoding="utf-8")
    assert "<version>4.3.1</version>" in pom


def test_seed_repository_code_fix_fails_before_the_loader_is_rewritten() -> None:
    script = REPO_ROOT / "demo" / "securitydemo" / "check_code_fix.py"
    completed = subprocess.run(
        [sys.executable, str(script)],
        cwd=script.parent,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode != 0
    assert "portal/configs" in completed.stderr
    loader = (
        REPO_ROOT / "demo" / "securitydemo" / "portal" / "config_loader.py"
    ).read_text(encoding="utf-8")
    assert "Intentionally unsafe join" in loader


def test_live_jira_client_posts_the_v3_payload(monkeypatch) -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["body"] = request.read()
        return httpx.Response(201, json={"key": "SEC-9"})

    settings = Settings(
        explanation_provider=ExplanationProvider.LOCAL,
        operations_delivery="live",
        jira_base_url="https://example.atlassian.net",
        jira_email="demo@example.com",
        jira_api_token="token",
        jira_project_key="SEC",
    )
    from app.operations.delivery import LiveDelivery

    delivery = LiveDelivery(settings, transport=httpx.MockTransport(handler))
    outbound = delivery.create_jira("CVE-2026-22739::customer-portal", "portal", "Summary", "Body")
    monkeypatch.delenv("JIRA_API_TOKEN", raising=False)

    assert outbound.delivered is True
    assert outbound.external_id == "SEC-9"
    assert seen["path"] == "/rest/api/3/issue"
    assert b"spring" not in seen["body"] or b"Summary" in seen["body"]
    assert b'"key": "SEC"' in seen["body"] or b'"key":"SEC"' in seen["body"]
