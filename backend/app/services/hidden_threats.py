from __future__ import annotations

from app.domain.historical import (
    HiddenThreatCandidate,
    HiddenThreatMode,
    HistoricalCandidate,
    HistoricalOutcome,
    HistoricalSnapshot,
)


class HiddenThreatService:
    """Finds model/baseline ranking disagreements on one frozen cohort."""

    def detect(
        self, snapshot: HistoricalSnapshot, mode: HiddenThreatMode, budget: int
    ) -> list[HiddenThreatCandidate]:
        if budget < 1:
            raise ValueError("hidden-threat budget must be positive")
        baseline_field = "cvss_score" if mode is HiddenThreatMode.MODEL_VS_CVSS else "epss_score"
        eligible = [
            item for item in snapshot.candidates if getattr(item, baseline_field) is not None
        ]
        model_higher = snapshot.candidates[0].model_score_scale.higher_is_riskier
        model_ranked = self._rank(eligible, "model_score", model_higher)
        baseline_ranked = self._rank(eligible, baseline_field, True)
        model_ranks = self._rank_map(model_ranked)
        baseline_ranks = self._rank_map(baseline_ranked)

        candidates: list[HiddenThreatCandidate] = []
        for item in model_ranked:
            model_rank = model_ranks[item.cve_id]
            baseline_rank = baseline_ranks[item.cve_id]
            # Missing baseline values never enter this pairwise cohort.
            if model_rank <= budget < baseline_rank:
                outcome = self._outcome(item, snapshot)
                candidates.append(
                    HiddenThreatCandidate(
                        cve_id=item.cve_id,
                        mode=mode,
                        budget=budget,
                        model_rank=model_rank,
                        baseline_rank=baseline_rank,
                        rank_difference=baseline_rank - model_rank,
                        model_score=item.model_score,
                        baseline_score=float(getattr(item, baseline_field)),
                        outcome=outcome,
                        kev_date_added=(
                            item.kev_date_added
                            if outcome is HistoricalOutcome.CONFIRMED_KEV
                            else None
                        ),
                        evidence=item.evidence,
                    )
                )
        return candidates

    @staticmethod
    def _rank(
        candidates: list[HistoricalCandidate], field: str, higher_is_riskier: bool
    ) -> list[HistoricalCandidate]:
        # The same CVE tie-breaker is used for model and baseline rankings.
        return sorted(
            candidates,
            key=lambda item: (
                -float(getattr(item, field)) if higher_is_riskier else float(getattr(item, field)),
                item.cve_id,
            ),
        )

    @staticmethod
    def _rank_map(ranked: list[HistoricalCandidate]) -> dict[str, int]:
        return {item.cve_id: index for index, item in enumerate(ranked, start=1)}

    @staticmethod
    def _outcome(candidate: HistoricalCandidate, snapshot: HistoricalSnapshot) -> HistoricalOutcome:
        if candidate.kev_date_added is None:
            return HistoricalOutcome.NOT_KEV_BY_CUTOFF
        if candidate.kev_date_added <= snapshot.evaluation_cutoff.date():
            return HistoricalOutcome.CONFIRMED_KEV
        return HistoricalOutcome.UNKNOWN
