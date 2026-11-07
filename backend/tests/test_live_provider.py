from __future__ import annotations

import os
from datetime import date

import pytest

from app.config import ExplanationProvider, Settings
from app.domain.contracts import Prediction
from app.main import create_app


@pytest.mark.live
@pytest.mark.skipif(
    os.getenv("LIVE_PROVIDER_SMOKE") != "1",
    reason="set LIVE_PROVIDER_SMOKE=1 to permit a paid external inference request",
)
def test_configured_external_provider_live() -> None:
    settings = Settings(provider_max_output_tokens=220)
    if settings.explanation_provider is ExplanationProvider.LOCAL:
        pytest.fail("select huggingface or watsonx before running the live smoke test")

    prediction = Prediction(
        prediction_id="synthetic-live-smoke",
        snapshot_date=date(2026, 1, 15),
        vulnerability={
            "vulnerability_id": "SYNTH-LIVE-001",
            "source": "synthetic-live-smoke",
        },
        score=0.8,
        score_scale={"minimum": 0.0, "maximum": 1.0, "higher_is_riskier": True},
        model_version="synthetic-live-smoke-v1",
    )
    explanation = create_app(settings).state.explanation_service.explain(prediction)

    assert explanation.provider.value == settings.explanation_provider.value, (
        f"provider fell back to local: {explanation.provider_metadata}"
    )
    assert explanation.provider_metadata["fallback_status"] == "not_used"
    assert explanation.provider_metadata["requested_model_id"] == settings.hf_model_id
    accepted_response_models = {settings.hf_model_id.split(":", 1)[0]}
    if settings.hf_response_model_id:
        accepted_response_models.add(settings.hf_response_model_id)
    assert explanation.provider_metadata["model_id"] in accepted_response_models
    assert explanation.interpretations
    assert all(
        "No additional model-authored factual claim was accepted." in item.text
        for item in explanation.interpretations
    )
    assert any("free text is not exposed" in item for item in explanation.limitations)
    print(
        "LIVE_PROVIDER_METADATA "
        f"model={explanation.provider_metadata['model_id']} "
        f"provider={explanation.provider_metadata.get('inference_provider', 'unverified')}"
    )
