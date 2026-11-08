from __future__ import annotations

from app.domain.contracts import Prediction
from app.services.explanations import LocalExplanationService


def test_all_explanation_references_are_backed_by_prediction(
    prediction_payload: dict,
) -> None:
    prediction = Prediction.model_validate(prediction_payload)

    explanation = LocalExplanationService().explain(prediction)

    used_refs = {
        ref
        for statement in [*explanation.observed_facts, *explanation.interpretations]
        for ref in statement.source_refs
    }
    assert used_refs <= prediction.valid_source_refs()
    assert explanation.context.prediction_snapshot == prediction.snapshot_date
    assert explanation.context.model_score == prediction.score
    assert explanation.context.model_version == prediction.model_version
    assert explanation.context.evidence[0].source == prediction.evidence[0].source
    assert "not treated as an exploitation probability" in explanation.context.score_meaning
    assert explanation.provider_metadata["actual_provider"] == "local"
    assert explanation.provider_metadata["fallback_status"] == "not_used"


def test_missing_signals_and_evidence_are_disclosed(prediction_payload: dict) -> None:
    prediction_payload["signals"] = []
    prediction_payload["evidence"] = []
    prediction_payload["affected_assets"] = []
    prediction = Prediction.model_validate(prediction_payload)

    explanation = LocalExplanationService().explain(prediction)

    assert "No supporting evidence records were supplied." in explanation.limitations
    assert "No explanatory model signals were supplied." in explanation.limitations
    assert explanation.interpretations == []
    assert explanation.context.missing_information == [
        "supporting evidence",
        "explanatory model signals",
        "affected asset associations",
    ]
