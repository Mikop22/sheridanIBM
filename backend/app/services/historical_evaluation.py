from __future__ import annotations

from collections.abc import Callable

from app.domain.historical import (
    BudgetMetrics,
    EvaluationCoverage,
    HistoricalCandidate,
    HistoricalEvaluation,
    HistoricalOutcome,
    HistoricalSnapshot,
    RankedHistoricalCandidate,
    RankingStrategy,
    StrategyMetrics,
)

SUPPORTED_BUDGETS = (10, 25, 50, 100, 500)


class HistoricalEvaluationService:
    """Evaluates frozen out-of-sample rankings without using future features."""

    def evaluate(self, snapshot: HistoricalSnapshot) -> HistoricalEvaluation:
        shared = [
            item
            for item in snapshot.candidates
            if item.cvss_score is not None and item.epss_score is not None
        ]
        model_higher = snapshot.candidates[0].model_score_scale.higher_is_riskier
        model_ranked = self._rank(shared, lambda item: item.model_score, model_higher)
        cvss_ranked = self._rank(shared, lambda item: item.cvss_score, True)
        epss_ranked = self._rank(shared, lambda item: item.epss_score, True)

        rank_maps = {
            RankingStrategy.MODEL: self._rank_map(model_ranked),
            RankingStrategy.CVSS: self._rank_map(cvss_ranked),
            RankingStrategy.EPSS: self._rank_map(epss_ranked),
        }
        outcomes = {item.cve_id: self._outcome(item, snapshot) for item in shared}
        strategy_metrics = [
            self._metrics(strategy, ranked, outcomes)
            for strategy, ranked in (
                (RankingStrategy.MODEL, model_ranked),
                (RankingStrategy.CVSS, cvss_ranked),
                (RankingStrategy.EPSS, epss_ranked),
            )
        ]
        by_strategy = {item.strategy: item for item in strategy_metrics}

        rankings = [
            RankedHistoricalCandidate(
                cve_id=item.cve_id,
                model_rank=rank_maps[RankingStrategy.MODEL][item.cve_id],
                cvss_rank=rank_maps[RankingStrategy.CVSS][item.cve_id],
                epss_rank=rank_maps[RankingStrategy.EPSS][item.cve_id],
                outcome=outcomes[item.cve_id],
                # Do not expose a KEV date that was unknown at the evaluation cutoff.
                kev_date_added=(
                    item.kev_date_added
                    if outcomes[item.cve_id] is HistoricalOutcome.CONFIRMED_KEV
                    else None
                ),
            )
            for item in model_ranked
        ]
        return HistoricalEvaluation(
            month=snapshot.month,
            feature_cutoff=snapshot.feature_cutoff,
            evaluation_cutoff=snapshot.evaluation_cutoff,
            model_version=snapshot.candidates[0].model_version,
            coverage=EvaluationCoverage(
                total_candidates=len(snapshot.candidates),
                shared_candidates=len(shared),
                cvss_pair_candidates=sum(
                    item.cvss_score is not None for item in snapshot.candidates
                ),
                epss_pair_candidates=sum(
                    item.epss_score is not None for item in snapshot.candidates
                ),
            ),
            rankings=rankings,
            strategies=strategy_metrics,
            model_improvement_over_cvss=self._improvements(
                by_strategy[RankingStrategy.MODEL], by_strategy[RankingStrategy.CVSS]
            ),
            model_improvement_over_epss=self._improvements(
                by_strategy[RankingStrategy.MODEL], by_strategy[RankingStrategy.EPSS]
            ),
        )

    @staticmethod
    def _rank(
        candidates: list[HistoricalCandidate],
        score: Callable[[HistoricalCandidate], float | None],
        higher_is_riskier: bool,
    ) -> list[HistoricalCandidate]:
        # CVE ID is the stable tie-breaker across every ranking strategy.
        return sorted(
            candidates,
            key=lambda item: (
                -float(score(item)) if higher_is_riskier else float(score(item)),
                item.cve_id,
            ),
        )

    @staticmethod
    def _rank_map(ranked: list[HistoricalCandidate]) -> dict[str, int]:
        return {item.cve_id: index for index, item in enumerate(ranked, start=1)}

    @staticmethod
    def _outcome(candidate: HistoricalCandidate, snapshot: HistoricalSnapshot) -> HistoricalOutcome:
        date_added = candidate.kev_date_added
        if date_added is None:
            return HistoricalOutcome.NOT_KEV_BY_CUTOFF
        if date_added <= snapshot.evaluation_cutoff.date():
            return HistoricalOutcome.CONFIRMED_KEV
        # A later catalog addition must not influence this historical evaluation.
        return HistoricalOutcome.UNKNOWN

    def _metrics(
        self,
        strategy: RankingStrategy,
        ranked: list[HistoricalCandidate],
        outcomes: dict[str, HistoricalOutcome],
    ) -> StrategyMetrics:
        positives = sum(outcome is HistoricalOutcome.CONFIRMED_KEV for outcome in outcomes.values())
        labels = [outcomes[item.cve_id] is HistoricalOutcome.CONFIRMED_KEV for item in ranked]
        budgets: list[BudgetMetrics] = []
        for budget in SUPPORTED_BUDGETS:
            evaluated_k = min(budget, len(ranked))
            hits = sum(labels[:evaluated_k])
            budgets.append(
                BudgetMetrics(
                    budget=budget,
                    evaluated_k=evaluated_k,
                    hits=hits,
                    precision=(hits / evaluated_k if evaluated_k else None),
                    recall=(hits / positives if positives else None),
                )
            )
        return StrategyMetrics(
            strategy=strategy,
            average_precision=self._average_precision(labels, positives),
            budgets=budgets,
        )

    @staticmethod
    def _average_precision(labels: list[bool], positives: int) -> float | None:
        if not labels or positives == 0:
            return None
        precision_sum = 0.0
        hits = 0
        for rank, positive in enumerate(labels, start=1):
            if positive:
                hits += 1
                precision_sum += hits / rank
        return precision_sum / positives

    @staticmethod
    def _improvements(model: StrategyMetrics, baseline: StrategyMetrics) -> dict[str, float | None]:
        values: dict[str, float | None] = {}
        for model_budget, baseline_budget in zip(model.budgets, baseline.budgets, strict=True):
            baseline_hits = baseline_budget.hits
            values[str(model_budget.budget)] = (
                (model_budget.hits - baseline_hits) / baseline_hits if baseline_hits > 0 else None
            )
        return values
