from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from app.domain.historical import HiddenThreatMode, HistoricalOutcome, HistoricalSnapshot
from app.services.hidden_threats import HiddenThreatService

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "historical-snapshot.synthetic.json"


def _pairwise_snapshot() -> HistoricalSnapshot:
    payload = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    template = payload["candidates"][1]
    candidates = []
    for index in range(6):
        candidate = deepcopy(template)
        candidate["cve_id"] = f"SYNTH-HIDDEN-{index + 1:03d}"
        candidate["model_score"] = float(1 - index / 10)
        candidate["cvss_score"] = float(index + 1)
        candidate["epss_score"] = float((5 - index) / 10)
        candidate["kev_date_added"] = "2025-03-10" if index == 0 else None
        candidates.append(candidate)
    candidates[5]["epss_score"] = None
    candidates[5]["epss_observed_at"] = None
    payload["candidates"] = candidates
    return HistoricalSnapshot.model_validate(payload)


def test_model_vs_cvss_finds_only_valid_top_k_disagreements() -> None:
    threats = HiddenThreatService().detect(
        _pairwise_snapshot(), HiddenThreatMode.MODEL_VS_CVSS, budget=2
    )

    assert [item.cve_id for item in threats] == ["SYNTH-HIDDEN-001", "SYNTH-HIDDEN-002"]
    assert threats[0].model_rank == 1
    assert threats[0].baseline_rank == 6
    assert threats[0].rank_difference == 5
    assert threats[0].outcome is HistoricalOutcome.CONFIRMED_KEV
    assert threats[0].kev_date_added is not None


def test_model_vs_epss_uses_distinct_pairwise_population() -> None:
    threats = HiddenThreatService().detect(
        _pairwise_snapshot(), HiddenThreatMode.MODEL_VS_EPSS, budget=2
    )

    assert threats == []


def test_unknown_baseline_never_qualifies_as_hidden_threat() -> None:
    snapshot = _pairwise_snapshot()
    missing_epss_id = "SYNTH-HIDDEN-006"

    threats = HiddenThreatService().detect(snapshot, HiddenThreatMode.MODEL_VS_EPSS, budget=5)

    assert missing_epss_id not in {item.cve_id for item in threats}


def test_budget_larger_than_pairwise_cohort_has_no_disagreement() -> None:
    threats = HiddenThreatService().detect(
        _pairwise_snapshot(), HiddenThreatMode.MODEL_VS_CVSS, budget=10
    )

    assert threats == []
