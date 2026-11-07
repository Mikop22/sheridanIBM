"""Export the public v1 contracts as deterministic JSON Schema files."""

from __future__ import annotations

import json
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_ROOT))

from app.domain.contracts import (  # noqa: E402
    ErrorResponse,
    EventProcessingOutcome,
    Explanation,
    HealthStatus,
    Prediction,
    RecommendationDecision,
    RemediationRecommendation,
    SecurityEvent,
)

SCHEMAS = {
    "error-response.schema.json": ErrorResponse,
    "explanation.schema.json": Explanation,
    "health-status.schema.json": HealthStatus,
    "prediction.schema.json": Prediction,
    "security-event.schema.json": SecurityEvent,
    "event-processing-outcome.schema.json": EventProcessingOutcome,
    "remediation-recommendation.schema.json": RemediationRecommendation,
    "recommendation-decision.schema.json": RecommendationDecision,
}


def main() -> None:
    output_dir = BACKEND_ROOT / "contracts" / "v1" / "schemas"
    output_dir.mkdir(parents=True, exist_ok=True)
    for filename, model in SCHEMAS.items():
        content = json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n"
        (output_dir / filename).write_text(content, encoding="utf-8")


if __name__ == "__main__":
    main()
