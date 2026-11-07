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


def test_missing_signals_and_evidence_are_disclosed(prediction_payload: dict) -> None:
    prediction_payload["signals"] = []
    prediction_payload["evidence"] = []
    prediction_payload["affected_assets"] = []
    prediction = Prediction.model_validate(prediction_payload)

    explanation = LocalExplanationService().explain(prediction)

    assert "No supporting evidence records were supplied." in explanation.limitations
    assert "No explanatory model signals were supplied." in explanation.limitations
    assert explanation.interpretations == []
