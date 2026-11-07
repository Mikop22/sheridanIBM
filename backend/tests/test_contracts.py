from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.domain.contracts import (
    ErrorResponse,
    EventProcessingOutcome,
    Explanation,
    HealthStatus,
    Prediction,
    RecommendationDecision,
    RemediationRecommendation,
    SecurityEvent,
)
from app.services.explanations import LocalExplanationService

BACKEND_ROOT = Path(__file__).resolve().parents[1]


def test_fixture_is_valid_and_explicitly_synthetic(prediction_payload: dict) -> None:
    prediction = Prediction.model_validate(prediction_payload)

    serialized = json.dumps(prediction.model_dump(mode="json")).lower()
    assert "synthetic" in serialized
    assert prediction.prediction_id.startswith("synthetic-")


def test_security_event_fixture_is_valid_and_explicitly_synthetic(event_payload: dict) -> None:
    event = SecurityEvent.model_validate(event_payload)

    assert event.event_id.startswith("synthetic-")
    assert "synthetic" in json.dumps(event.model_dump(mode="json")).lower()


def test_response_examples_match_contracts_and_local_output(prediction_payload: dict) -> None:
    prediction = Prediction.model_validate(prediction_payload)
    prediction_response = json.loads(
        (BACKEND_ROOT / "contracts/v1/examples/prediction-response.synthetic.json").read_text(
            encoding="utf-8"
        )
    )
    explanation_response = json.loads(
        (BACKEND_ROOT / "contracts/v1/examples/explanation-response.synthetic.json").read_text(
            encoding="utf-8"
        )
    )

    assert Prediction.model_validate(prediction_response) == prediction
    explanation = Explanation.model_validate(explanation_response)
    explanation.validate_source_refs(prediction)
    assert explanation == LocalExplanationService().explain(prediction)


def test_dangling_signal_evidence_reference_is_rejected(prediction_payload: dict) -> None:
    invalid = deepcopy(prediction_payload)
    invalid["signals"][0]["evidence_refs"] = ["missing-evidence"]

    with pytest.raises(ValidationError, match="unknown evidence_refs"):
        Prediction.model_validate(invalid)


@pytest.mark.parametrize(
    ("filename", "model"),
    [
        ("error-response.schema.json", ErrorResponse),
        ("explanation.schema.json", Explanation),
        ("health-status.schema.json", HealthStatus),
        ("prediction.schema.json", Prediction),
        ("security-event.schema.json", SecurityEvent),
        ("event-processing-outcome.schema.json", EventProcessingOutcome),
        ("remediation-recommendation.schema.json", RemediationRecommendation),
        ("recommendation-decision.schema.json", RecommendationDecision),
    ],
)
def test_exported_schema_matches_model(filename: str, model: type) -> None:
    path = BACKEND_ROOT / "contracts/v1/schemas" / filename
    exported = json.loads(path.read_text(encoding="utf-8"))

    assert exported == model.model_json_schema()
