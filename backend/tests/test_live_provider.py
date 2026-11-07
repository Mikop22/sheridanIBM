from __future__ import annotations

import json
import os
from pathlib import Path

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
    settings = Settings()
    if settings.explanation_provider is ExplanationProvider.LOCAL:
        pytest.fail("select huggingface or watsonx before running the live smoke test")

    fixture = Path(__file__).parents[1] / "contracts/v1/examples/prediction-create.synthetic.json"
    prediction = Prediction.model_validate(json.loads(fixture.read_text(encoding="utf-8")))
    explanation = create_app(settings).state.explanation_service.explain(prediction)

    assert explanation.provider.value == settings.explanation_provider.value, (
        f"provider fell back to local: {explanation.provider_metadata}"
    )
    assert explanation.provider_metadata["fallback_status"] == "not_used"
