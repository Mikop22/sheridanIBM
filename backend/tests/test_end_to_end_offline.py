from __future__ import annotations

from fastapi.testclient import TestClient


def test_complete_synthetic_workflow_is_offline(
    client: TestClient, prediction_payload: dict, event_payload: dict, monkeypatch
) -> None:
    def reject_http_client(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("offline workflow attempted external HTTP")

    monkeypatch.setattr("app.services.providers.httpx.Client", reject_http_client)

    created = client.post("/v1/predictions", json=prediction_payload)
    retrieved = client.get(f"/v1/predictions/{prediction_payload['prediction_id']}")
    explanation = client.post(f"/v1/predictions/{prediction_payload['prediction_id']}/explanation")
    event = client.post("/v1/security-events", json=event_payload)
    recommendations = client.get(
        f"/v1/predictions/{prediction_payload['prediction_id']}/recommendations"
    )
    recommendation_id = event.json()["recommendation_id"]
    decision = client.post(
        f"/v1/recommendations/{recommendation_id}/decision",
        json={
            "schema_version": "1.0",
            "action": "approve",
            "actor": "synthetic-reviewer",
            "reason": "Synthetic end-to-end verification only.",
        },
    )

    assert created.status_code == 201
    assert retrieved.json() == created.json()
    assert explanation.status_code == 200
    assert explanation.json()["provider"] == "local"
    assert explanation.json()["generation_status"] == "complete"
    assert event.status_code == 200
    assert event.json()["processing_status"] == "recommendation_created"
    assert len(recommendations.json()) == 1
    assert recommendations.json()[0]["workflow_status"] == "pending_approval"
    assert decision.status_code == 200
    assert decision.json()["workflow_status"] == "approved"
    assert decision.json()["approval_required"] is True
