from __future__ import annotations

import sqlite3
from copy import deepcopy
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import ExplanationProvider, Settings
from app.domain.contracts import (
    DecisionAction,
    EventProcessingStatus,
    Prediction,
    RecommendationDecision,
    RecommendationStatus,
    SecurityEvent,
)
from app.domain.errors import EventAlreadyExistsError, InvalidRecommendationTransitionError
from app.event_repository import SecurityEventRepository
from app.main import create_app
from app.repositories import InMemoryPredictionRepository
from app.services.event_processing import RiskThreshold, SecurityEventProcessor


def _processor(
    database_path: Path,
    prediction_payload: dict,
    *,
    threshold: RiskThreshold | None = None,
) -> tuple[SecurityEventProcessor, SecurityEventRepository]:
    predictions = InMemoryPredictionRepository()
    predictions.create(Prediction.model_validate(prediction_payload))
    events = SecurityEventRepository(database_path)
    processor = SecurityEventProcessor(
        predictions,
        events,
        threshold or RiskThreshold(0.75, 0.0, 1.0, True),
    )
    return processor, events


def test_above_threshold_event_creates_grounded_recommendation(
    tmp_path: Path, prediction_payload: dict, event_payload: dict
) -> None:
    processor, events = _processor(tmp_path / "events.db", prediction_payload)

    outcome = processor.process(SecurityEvent.model_validate(event_payload))
    recommendations = events.list_recommendations(event_payload["prediction_id"])

    assert outcome.processing_status is EventProcessingStatus.RECOMMENDATION_CREATED
    assert outcome.reason_code == "configured_threshold_met"
    assert len(recommendations) == 1
    recommendation = recommendations[0]
    assert (
        recommendation.vulnerability_id == prediction_payload["vulnerability"]["vulnerability_id"]
    )
    assert recommendation.asset_id == event_payload["asset_id"]
    assert recommendation.risk_score == prediction_payload["score"]
    assert recommendation.score_scale.model_dump() == prediction_payload["score_scale"]
    assert recommendation.evidence_refs == event_payload["evidence_refs"]
    assert recommendation.approval_required is True
    assert recommendation.workflow_status is RecommendationStatus.PENDING_APPROVAL
    assert "command" not in recommendation.recommended_next_step.lower()


@pytest.mark.parametrize(
    ("field", "value", "reason_code"),
    [
        ("vulnerability_id", "SYNTH-UNKNOWN", "vulnerability_not_matched"),
        ("asset_id", "synthetic-missing-asset", "asset_not_matched"),
        ("evidence_refs", ["synthetic-missing-evidence"], "unsupported_evidence"),
    ],
)
def test_unmatched_event_data_is_insufficient(
    tmp_path: Path,
    prediction_payload: dict,
    event_payload: dict,
    field: str,
    value: object,
    reason_code: str,
) -> None:
    event_payload[field] = value
    processor, events = _processor(tmp_path / "events.db", prediction_payload)

    outcome = processor.process(SecurityEvent.model_validate(event_payload))

    assert outcome.processing_status is EventProcessingStatus.INSUFFICIENT_INFORMATION
    assert outcome.reason_code == reason_code
    assert events.list_recommendations(event_payload["prediction_id"]) == []


def test_missing_prediction_is_recorded_as_insufficient(
    tmp_path: Path, event_payload: dict
) -> None:
    events = SecurityEventRepository(tmp_path / "events.db")
    processor = SecurityEventProcessor(
        InMemoryPredictionRepository(), events, RiskThreshold(0.75, 0.0, 1.0, True)
    )

    outcome = processor.process(SecurityEvent.model_validate(event_payload))

    assert outcome.reason_code == "prediction_not_found"
    assert events.get_event(event_payload["event_id"]) == outcome


def test_below_threshold_event_records_no_action(
    tmp_path: Path, prediction_payload: dict, event_payload: dict
) -> None:
    prediction_payload["score"] = 0.5
    processor, events = _processor(tmp_path / "events.db", prediction_payload)

    outcome = processor.process(SecurityEvent.model_validate(event_payload))

    assert outcome.processing_status is EventProcessingStatus.NO_ACTION
    assert outcome.reason_code == "below_configured_threshold"
    assert events.list_recommendations(event_payload["prediction_id"]) == []


@pytest.mark.parametrize(
    "threshold",
    [
        RiskThreshold(None, None, None, None),
        RiskThreshold(75.0, 0.0, 100.0, True),
        RiskThreshold(2.0, 0.0, 1.0, True),
        RiskThreshold(0.75, 0.0, 1.0, False),
    ],
)
def test_missing_or_incompatible_score_semantics_do_not_trigger(
    tmp_path: Path,
    prediction_payload: dict,
    event_payload: dict,
    threshold: RiskThreshold,
) -> None:
    processor, events = _processor(
        tmp_path / f"{hash(threshold)}.db", prediction_payload, threshold=threshold
    )

    outcome = processor.process(SecurityEvent.model_validate(event_payload))

    assert outcome.processing_status is EventProcessingStatus.INSUFFICIENT_INFORMATION
    assert outcome.reason_code == "incompatible_score_semantics"
    assert events.list_recommendations(event_payload["prediction_id"]) == []


def test_nearly_equal_score_scale_is_still_incompatible(
    tmp_path: Path, prediction_payload: dict, event_payload: dict
) -> None:
    prediction_payload["score_scale"]["maximum"] = 1.0000000001
    processor, events = _processor(tmp_path / "near-scale.db", prediction_payload)

    outcome = processor.process(SecurityEvent.model_validate(event_payload))

    assert outcome.processing_status is EventProcessingStatus.INSUFFICIENT_INFORMATION
    assert outcome.reason_code == "incompatible_score_semantics"
    assert events.list_recommendations(event_payload["prediction_id"]) == []


def test_lower_score_can_be_riskier_when_declared(
    tmp_path: Path, prediction_payload: dict, event_payload: dict
) -> None:
    prediction_payload["score"] = 2.0
    prediction_payload["score_scale"] = {
        "minimum": 0.0,
        "maximum": 10.0,
        "higher_is_riskier": False,
    }
    processor, _ = _processor(
        tmp_path / "lower.db",
        prediction_payload,
        threshold=RiskThreshold(3.0, 0.0, 10.0, False),
    )

    outcome = processor.process(SecurityEvent.model_validate(event_payload))

    assert outcome.processing_status is EventProcessingStatus.RECOMMENDATION_CREATED


def test_duplicate_event_is_idempotent_but_changed_content_conflicts(
    tmp_path: Path, prediction_payload: dict, event_payload: dict
) -> None:
    processor, events = _processor(tmp_path / "events.db", prediction_payload)
    event = SecurityEvent.model_validate(event_payload)

    first = processor.process(event)
    second = processor.process(event)

    assert second == first
    assert len(events.list_recommendations(event.prediction_id)) == 1
    changed = event.model_copy(update={"asset_id": "different-asset"})
    with pytest.raises(EventAlreadyExistsError):
        processor.process(changed)


@pytest.mark.parametrize(
    ("action", "expected_status"),
    [
        (DecisionAction.APPROVE, RecommendationStatus.APPROVED),
        (DecisionAction.REJECT, RecommendationStatus.REJECTED),
    ],
)
def test_recommendation_approval_and_rejection_are_auditable(
    tmp_path: Path,
    prediction_payload: dict,
    event_payload: dict,
    action: DecisionAction,
    expected_status: RecommendationStatus,
) -> None:
    processor, events = _processor(tmp_path / f"{action.value}.db", prediction_payload)
    outcome = processor.process(SecurityEvent.model_validate(event_payload))
    decision = RecommendationDecision(
        action=action, actor="synthetic-reviewer", reason="Synthetic workflow test decision."
    )

    updated = events.decide(outcome.recommendation_id, decision)  # type: ignore[arg-type]

    assert updated.workflow_status is expected_status
    assert updated.decided_by == "synthetic-reviewer"
    assert updated.decided_at is not None
    with sqlite3.connect(tmp_path / f"{action.value}.db") as connection:
        audit_count = connection.execute(
            "SELECT COUNT(*) FROM recommendation_audit WHERE recommendation_id = ?",
            (updated.recommendation_id,),
        ).fetchone()[0]
    assert audit_count == 1
    with pytest.raises(InvalidRecommendationTransitionError):
        events.decide(updated.recommendation_id, decision)


def test_sqlite_state_survives_repository_restart(
    tmp_path: Path, prediction_payload: dict, event_payload: dict
) -> None:
    database_path = tmp_path / "persistent.db"
    processor, events = _processor(database_path, prediction_payload)
    outcome = processor.process(SecurityEvent.model_validate(event_payload))
    events.decide(
        outcome.recommendation_id,  # type: ignore[arg-type]
        RecommendationDecision(
            action=DecisionAction.APPROVE,
            actor="synthetic-reviewer",
            reason="Persist this synthetic approval.",
        ),
    )

    restarted = SecurityEventRepository(database_path)

    assert restarted.get_event(event_payload["event_id"]) == outcome
    recommendations = restarted.list_recommendations(event_payload["prediction_id"])
    assert len(recommendations) == 1
    assert recommendations[0].workflow_status is RecommendationStatus.APPROVED


def test_sqlite_connections_are_closed_after_repository_operations(
    tmp_path: Path, prediction_payload: dict, event_payload: dict
) -> None:
    database_path = tmp_path / "closed.db"
    processor, events = _processor(database_path, prediction_payload)
    processor.process(SecurityEvent.model_validate(event_payload))
    events.get_event(event_payload["event_id"])

    renamed_path = tmp_path / "renamed.db"
    database_path.rename(renamed_path)

    assert renamed_path.exists()


def test_sqlite_lock_returns_retryable_error_envelope(
    tmp_path: Path,
    prediction_payload: dict,
    event_payload: dict,
    monkeypatch,
) -> None:
    database_path = tmp_path / "locked.db"
    event_repository = SecurityEventRepository(database_path)
    settings = Settings(
        event_database_path=database_path,
        event_risk_threshold=0.75,
        event_threshold_scale_minimum=0.0,
        event_threshold_scale_maximum=1.0,
        event_threshold_higher_is_riskier=True,
    )
    real_connect = sqlite3.connect
    lock_connection = real_connect(database_path)
    lock_connection.execute("BEGIN EXCLUSIVE")

    def connect_without_wait(database, *args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs["timeout"] = 0
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr("app.event_repository.sqlite3.connect", connect_without_wait)
    try:
        with TestClient(create_app(settings, event_repository=event_repository)) as locked_client:
            assert locked_client.post("/v1/predictions", json=prediction_payload).status_code == 201
            response = locked_client.post("/v1/security-events", json=event_payload)
    finally:
        lock_connection.rollback()
        lock_connection.close()

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "event_store_unavailable"
    assert response.headers["Retry-After"] == "1"
    assert response.headers["X-Trace-ID"] == response.json()["trace_id"]


def test_workflow_never_executes_remediation(
    tmp_path: Path, prediction_payload: dict, event_payload: dict, monkeypatch
) -> None:
    calls: list[str] = []
    monkeypatch.setattr("os.system", lambda command: calls.append(command))
    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: calls.append(str(args)))
    processor, events = _processor(tmp_path / "events.db", prediction_payload)
    outcome = processor.process(SecurityEvent.model_validate(event_payload))
    events.decide(
        outcome.recommendation_id,  # type: ignore[arg-type]
        RecommendationDecision(
            action=DecisionAction.APPROVE,
            actor="synthetic-reviewer",
            reason="Approval records intent only.",
        ),
    )

    assert calls == []


def test_event_api_is_offline_even_when_explanation_provider_is_unavailable(
    tmp_path: Path, prediction_payload: dict, event_payload: dict
) -> None:
    settings = Settings(
        explanation_provider=ExplanationProvider.HUGGINGFACE,
        hf_token="",
        hf_model_id="",
        event_database_path=tmp_path / "api.db",
        event_risk_threshold=0.75,
        event_threshold_scale_minimum=0.0,
        event_threshold_scale_maximum=1.0,
        event_threshold_higher_is_riskier=True,
    )
    with TestClient(create_app(settings)) as client:
        client.post("/v1/predictions", json=prediction_payload)
        submitted = client.post("/v1/security-events", json=event_payload)
        retrieved = client.get(f"/v1/security-events/{event_payload['event_id']}")
        recommendations = client.get(
            f"/v1/predictions/{prediction_payload['prediction_id']}/recommendations"
        )

    assert submitted.status_code == 200
    assert submitted.json()["processing_status"] == "recommendation_created"
    assert retrieved.json() == submitted.json()
    assert len(recommendations.json()) == 1


def test_malformed_event_and_invalid_transition_return_stable_errors(
    client: TestClient, prediction_payload: dict, event_payload: dict
) -> None:
    client.post("/v1/predictions", json=prediction_payload)
    malformed = deepcopy(event_payload)
    malformed["evidence_refs"] = []
    invalid = client.post("/v1/security-events", json=malformed)
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "validation_error"

    created = client.post("/v1/security-events", json=event_payload).json()
    recommendation_id = created["recommendation_id"]
    decision = {
        "action": "approve",
        "actor": "synthetic-reviewer",
        "reason": "Synthetic approval.",
    }
    first = client.post(f"/v1/recommendations/{recommendation_id}/decision", json=decision)
    second = client.post(f"/v1/recommendations/{recommendation_id}/decision", json=decision)

    assert first.status_code == 200
    assert first.json()["workflow_status"] == "approved"
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "invalid_recommendation_transition"
