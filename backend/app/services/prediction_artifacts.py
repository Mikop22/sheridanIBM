from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import re
from calendar import monthrange
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Literal

from app.domain.contracts import (
    Evidence,
    ExplanatorySignal,
    Prediction,
    ScoreScale,
    SignalDirection,
    VulnerabilityRef,
)

MODEL_VERSION = "member1-v1-locked-ensemble"
SCORE_INTERPRETATION = (
    "Relative ensemble ranking score on a 0 to 1 scale; higher values are declared riskier. "
    "It is not treated as a calibrated exploitation probability."
)
SCORE_COLUMNS = (
    "score_v1_ensemble",
    "score_tier_b_expanded",
    "score_tier_a_strict",
    "base_lr_stack",
    "base_lr_joint_tfidf",
    "base_rf",
    "base_lgbm_full",
    "base_lgbm_undersampled",
    "base_xgb_lambdamart",
)
REQUIRED_COLUMNS = ("cve_id", "published", "snapshot_month", *SCORE_COLUMNS)
SNAPSHOT_PATTERN = re.compile(r"^\d{4}-(0[1-9]|1[0-2])$")
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class PredictionArtifactError(ValueError):
    """Raised when a prediction export cannot be trusted as an integration input."""


@dataclass(frozen=True)
class PredictionArtifactRecord:
    prediction: Prediction
    published: date
    snapshot_month: str
    component_scores: dict[str, float]


@dataclass(frozen=True)
class PredictionArtifact:
    artifact_id: str
    source_kind: Literal["summary_json", "full_csv"]
    records: tuple[PredictionArtifactRecord, ...]

    def find_cve(self, cve_id: str) -> PredictionArtifactRecord | None:
        normalized = cve_id.strip().upper()
        return next(
            (
                item
                for item in self.records
                if item.prediction.vulnerability.vulnerability_id == normalized
            ),
            None,
        )


def load_prediction_artifact(
    path: Path, *, minimum_snapshot_month: str | None = None
) -> PredictionArtifact:
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise PredictionArtifactError(f"prediction artifact is unavailable: {path}") from exc

    artifact_id = f"sha256:{hashlib.sha256(content).hexdigest()}"
    suffix = path.suffix.casefold()
    if suffix == ".json":
        source_kind: Literal["summary_json", "full_csv"] = "summary_json"
        rows = _json_rows(content)
    elif suffix == ".csv":
        source_kind = "full_csv"
        rows = _csv_rows(content)
    else:
        raise PredictionArtifactError("prediction artifact must be a .json or .csv file")

    parsed = [_parse_row(row, index) for index, row in enumerate(rows, start=1)]
    if not parsed:
        raise PredictionArtifactError("prediction artifact contains no prediction rows")

    cve_counts = Counter(item[0] for item in parsed)
    duplicates = sorted(item for item, count in cve_counts.items() if count > 1)
    if duplicates:
        raise PredictionArtifactError(
            f"prediction artifact contains duplicate CVE rows: {', '.join(duplicates)}"
        )

    latest_snapshot = max(item[2] for item in parsed)
    if minimum_snapshot_month is not None and latest_snapshot < minimum_snapshot_month:
        raise PredictionArtifactError(
            f"prediction artifact latest snapshot {latest_snapshot} is older than required "
            f"{minimum_snapshot_month}"
        )

    parsed.sort(key=lambda item: (-item[3]["score_v1_ensemble"], item[0]))
    records = tuple(
        _to_record(
            cve_id=cve_id,
            published=published,
            snapshot_month=snapshot_month,
            scores=scores,
            artifact_id=artifact_id,
            rank=rank,
        )
        for rank, (cve_id, published, snapshot_month, scores) in enumerate(parsed, start=1)
    )
    return PredictionArtifact(
        artifact_id=artifact_id,
        source_kind=source_kind,
        records=records,
    )


def _json_rows(content: bytes) -> list[dict[str, Any]]:
    try:
        payload = json.loads(content)
        rows = payload["top_25_predictions_2026"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise PredictionArtifactError("summary JSON must contain top_25_predictions_2026") from exc
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise PredictionArtifactError("summary prediction rows must be JSON objects")
    return rows


def _csv_rows(content: bytes) -> list[dict[str, Any]]:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise PredictionArtifactError("prediction CSV must be UTF-8") from exc
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        raise PredictionArtifactError("prediction CSV is missing a header")
    missing = sorted(set(REQUIRED_COLUMNS) - set(reader.fieldnames))
    if missing:
        raise PredictionArtifactError(
            f"prediction artifact is missing required columns: {', '.join(missing)}"
        )
    return list(reader)


def _parse_row(row: dict[str, Any], index: int) -> tuple[str, date, str, dict[str, float]]:
    missing = [column for column in REQUIRED_COLUMNS if column not in row]
    if missing:
        raise PredictionArtifactError(
            f"prediction row {index} is missing required columns: {', '.join(missing)}"
        )

    cve_id = str(row["cve_id"]).strip().upper()
    if not CVE_PATTERN.fullmatch(cve_id):
        raise PredictionArtifactError(f"prediction row {index} has an invalid CVE identifier")
    try:
        published = date.fromisoformat(str(row["published"]).strip())
    except ValueError as exc:
        raise PredictionArtifactError(
            f"prediction row {index} has an invalid publication date"
        ) from exc
    snapshot_month = str(row["snapshot_month"]).strip()
    if not SNAPSHOT_PATTERN.fullmatch(snapshot_month):
        raise PredictionArtifactError(f"prediction row {index} has an invalid snapshot month")
    snapshot_year, snapshot_month_number = (int(part) for part in snapshot_month.split("-"))
    snapshot_date = date(
        snapshot_year,
        snapshot_month_number,
        monthrange(snapshot_year, snapshot_month_number)[1],
    )
    if published > snapshot_date:
        raise PredictionArtifactError(
            f"prediction row {index} was published after its snapshot month"
        )

    scores: dict[str, float] = {}
    for column in SCORE_COLUMNS:
        raw_value = row[column]
        if isinstance(raw_value, bool):
            raise PredictionArtifactError(f"prediction row {index} has an invalid {column} value")
        try:
            value = float(raw_value)
        except (TypeError, ValueError) as exc:
            raise PredictionArtifactError(
                f"prediction row {index} has an invalid {column} value"
            ) from exc
        if not math.isfinite(value) or not 0.0 <= value <= 1.0:
            raise PredictionArtifactError(
                f"prediction row {index} has an out-of-range {column} value"
            )
        scores[column] = value
    return cve_id, published, snapshot_month, scores


def _to_record(
    *,
    cve_id: str,
    published: date,
    snapshot_month: str,
    scores: dict[str, float],
    artifact_id: str,
    rank: int,
) -> PredictionArtifactRecord:
    year, month = (int(part) for part in snapshot_month.split("-"))
    snapshot_date = date(year, month, monthrange(year, month)[1])
    observed_at = datetime(
        snapshot_date.year,
        snapshot_date.month,
        snapshot_date.day,
        23,
        59,
        59,
        tzinfo=UTC,
    )
    evidence_id = "member1-artifact-row"
    prediction = Prediction(
        prediction_id=f"member1-v1-{snapshot_month}-{cve_id}",
        snapshot_date=snapshot_date,
        vulnerability=VulnerabilityRef(
            vulnerability_id=cve_id,
            source="member1-scoreboard-2026",
        ),
        score=scores["score_v1_ensemble"],
        score_scale=ScoreScale(minimum=0.0, maximum=1.0, higher_is_riskier=True),
        rank=rank,
        model_version=MODEL_VERSION,
        signals=[
            ExplanatorySignal(
                name=name,
                value=value,
                contribution=None,
                direction=SignalDirection.UNKNOWN,
                evidence_refs=[evidence_id],
            )
            for name, value in scores.items()
            if name != "score_v1_ensemble"
        ],
        evidence=[
            Evidence(
                evidence_id=evidence_id,
                kind="model_prediction_artifact",
                source="member1-v1-submission",
                observed_at=observed_at,
                value={
                    "artifact_id": artifact_id,
                    "published": published.isoformat(),
                    "snapshot_month": snapshot_month,
                    **scores,
                },
            )
        ],
    )
    return PredictionArtifactRecord(
        prediction=prediction,
        published=published,
        snapshot_month=snapshot_month,
        component_scores=dict(scores),
    )
