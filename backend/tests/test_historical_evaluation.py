from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.domain.historical import HistoricalOutcome, HistoricalSnapshot, RankingStrategy
from app.services.historical_evaluation import HistoricalEvaluationService

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "historical-snapshot.synthetic.json"


@pytest.fixture
def historical_payload() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_synthetic_snapshot_uses_shared_population_and_stable_ranks(
    historical_payload: dict,
) -> None:
    snapshot = HistoricalSnapshot.model_validate(historical_payload)

    result = HistoricalEvaluationService().evaluate(snapshot)

    assert snapshot.fixture_kind == "synthetic"
    assert result.coverage.total_candidates == 5
    assert result.coverage.shared_candidates == 4
    assert result.coverage.cvss_pair_candidates == 5
    assert result.coverage.epss_pair_candidates == 4
    assert [item.cve_id for item in result.rankings] == [
        "SYNTH-CVE-001",
        "SYNTH-CVE-002",
        "SYNTH-CVE-003",
        "SYNTH-CVE-004",
    ]
    assert result.rankings[0].model_rank == 1
    assert result.rankings[0].cvss_rank == 4
    assert result.rankings[0].epss_rank == 2
    assert result.rankings[0].outcome is HistoricalOutcome.CONFIRMED_KEV
    assert result.rankings[2].outcome is HistoricalOutcome.UNKNOWN
    assert result.rankings[2].kev_date_added is None


def test_metrics_use_available_cohort_size_and_null_unsupported_values(
    historical_payload: dict,
) -> None:
    result = HistoricalEvaluationService().evaluate(
        HistoricalSnapshot.model_validate(historical_payload)
    )
    metrics = {item.strategy: item for item in result.strategies}

    for strategy in RankingStrategy:
        first_budget = metrics[strategy].budgets[0]
        assert first_budget.budget == 10
        assert first_budget.evaluated_k == 4
        assert first_budget.hits == 1
        assert first_budget.precision == 0.25
        assert first_budget.recall == 1.0
    assert metrics[RankingStrategy.MODEL].average_precision == 1.0
    assert metrics[RankingStrategy.CVSS].average_precision == 0.25
    assert result.model_improvement_over_cvss["10"] == 0.0

    no_positive = deepcopy(historical_payload)
    no_positive["candidates"][0]["kev_date_added"] = None
    empty_metrics = (
        HistoricalEvaluationService()
        .evaluate(HistoricalSnapshot.model_validate(no_positive))
        .strategies[0]
    )
    assert empty_metrics.average_precision is None
    assert empty_metrics.budgets[0].recall is None


def test_hits_precision_and_recall_at_ten_use_identical_population(
    historical_payload: dict,
) -> None:
    template = historical_payload["candidates"][1]
    candidates = []
    for index in range(12):
        candidate = deepcopy(template)
        candidate["cve_id"] = f"SYNTH-CVE-{index + 1:03d}"
        candidate["model_score"] = float(1 - index / 20)
        candidate["cvss_score"] = float(index / 2)
        candidate["epss_score"] = float((11 - index) / 20)
        candidate["kev_date_added"] = "2025-03-10" if index < 2 else None
        candidates.append(candidate)
    historical_payload["candidates"] = candidates

    result = HistoricalEvaluationService().evaluate(
        HistoricalSnapshot.model_validate(historical_payload)
    )
    metrics = {item.strategy: item for item in result.strategies}

    assert result.coverage.shared_candidates == 12
    assert metrics[RankingStrategy.MODEL].budgets[0].hits == 2
    assert metrics[RankingStrategy.MODEL].budgets[0].precision == 0.2
    assert metrics[RankingStrategy.MODEL].budgets[0].recall == 1.0
    assert metrics[RankingStrategy.CVSS].budgets[0].hits == 0
    assert result.model_improvement_over_cvss["10"] is None


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda data: data["candidates"][0].update(is_out_of_sample=False), "training rows"),
        (
            lambda data: data["candidates"][0]["evidence"][0].update(
                observed_at="2025-02-01T00:00:00Z"
            ),
            "post-cutoff evidence",
        ),
        (
            lambda data: data["candidates"][0].update(kev_date_added="2025-01-20"),
            "already KEV-listed",
        ),
        (
            lambda data: data["candidates"][0].update(published_at="2025-02-01"),
            "published after",
        ),
    ],
)
def test_snapshot_rejects_temporal_leakage(historical_payload: dict, mutate, message: str) -> None:
    mutate(historical_payload)

    with pytest.raises(ValidationError, match=message):
        HistoricalSnapshot.model_validate(historical_payload)


def test_lower_model_scores_can_be_declared_riskier(historical_payload: dict) -> None:
    for candidate in historical_payload["candidates"]:
        candidate["model_score_scale"]["higher_is_riskier"] = False

    result = HistoricalEvaluationService().evaluate(
        HistoricalSnapshot.model_validate(historical_payload)
    )

    assert result.rankings[0].cve_id == "SYNTH-CVE-004"
