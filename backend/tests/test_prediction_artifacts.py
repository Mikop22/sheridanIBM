from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from app.services.prediction_artifacts import (
    MODEL_VERSION,
    PredictionArtifactError,
    load_prediction_artifact,
)

FIXTURES = Path(__file__).parent / "fixtures"
SYNTHETIC_CSV = FIXTURES / "member1-submission.synthetic.csv"


def test_loads_full_csv_with_deterministic_rank_and_exact_scores() -> None:
    artifact = load_prediction_artifact(SYNTHETIC_CSV)

    assert artifact.source_kind == "full_csv"
    assert artifact.artifact_id.startswith("sha256:")
    assert [item.prediction.vulnerability.vulnerability_id for item in artifact.records] == [
        "CVE-2099-1002",
        "CVE-2099-1001",
    ]
    first = artifact.records[0]
    assert first.prediction.rank == 1
    assert first.prediction.prediction_id == "member1-v1-2099-01-CVE-2099-1002"
    assert first.prediction.model_version == MODEL_VERSION
    assert first.prediction.score == 0.9
    assert first.component_scores["base_xgb_lambdamart"] == 0.86
    assert first.prediction.affected_assets == []
    assert first.prediction.evidence[0].value["score_tier_a_strict"] == 0.87


def test_loads_tracked_summary_top_25() -> None:
    path = Path(__file__).parents[2] / "model" / "results" / "submission_v1_summary.json"

    artifact = load_prediction_artifact(path)

    assert artifact.source_kind == "summary_json"
    assert len(artifact.records) == 25
    assert artifact.records[0].prediction.vulnerability.vulnerability_id == "CVE-2026-2699"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("score_v1_ensemble", "NaN", "out-of-range"),
        ("base_rf", "not-a-number", "invalid"),
        ("score_tier_a_strict", "1.1", "out-of-range"),
    ],
)
def test_rejects_invalid_scores(tmp_path: Path, field: str, value: str, message: str) -> None:
    rows = _fixture_rows()
    rows[0][field] = value
    path = _write_csv(tmp_path, rows)

    with pytest.raises(PredictionArtifactError, match=message):
        load_prediction_artifact(path)


def test_rejects_missing_column(tmp_path: Path) -> None:
    rows = _fixture_rows()
    for row in rows:
        row.pop("base_rf")
    path = _write_csv(tmp_path, rows)

    with pytest.raises(PredictionArtifactError, match="missing required columns: base_rf"):
        load_prediction_artifact(path)


def test_rejects_duplicate_cves(tmp_path: Path) -> None:
    rows = _fixture_rows()
    rows[1]["cve_id"] = rows[0]["cve_id"]
    path = _write_csv(tmp_path, rows)

    with pytest.raises(PredictionArtifactError, match="duplicate CVE rows"):
        load_prediction_artifact(path)


def test_rejects_publication_after_snapshot(tmp_path: Path) -> None:
    rows = _fixture_rows()
    rows[0]["published"] = "2099-02-01"
    path = _write_csv(tmp_path, rows)

    with pytest.raises(PredictionArtifactError, match="published after its snapshot"):
        load_prediction_artifact(path)


def test_rejects_missing_artifact(tmp_path: Path) -> None:
    with pytest.raises(PredictionArtifactError, match="unavailable"):
        load_prediction_artifact(tmp_path / "missing.csv")


def test_rejects_stale_artifact() -> None:
    with pytest.raises(PredictionArtifactError, match="older than required 2100-01"):
        load_prediction_artifact(SYNTHETIC_CSV, minimum_snapshot_month="2100-01")


def test_rejects_summary_without_expected_rows(tmp_path: Path) -> None:
    path = tmp_path / "summary.json"
    path.write_text(json.dumps({"architecture": "synthetic"}), encoding="utf-8")

    with pytest.raises(PredictionArtifactError, match="top_25_predictions_2026"):
        load_prediction_artifact(path)


def _fixture_rows() -> list[dict[str, str]]:
    with SYNTHETIC_CSV.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _write_csv(tmp_path: Path, rows: list[dict[str, str]]) -> Path:
    path = tmp_path / "predictions.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return path
