from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum
from typing import Literal

from pydantic import Field, StrictBool, StrictFloat, model_validator

from app.domain.contracts import ContractModel, NonEmptyString, ScoreScale


class HistoricalEvidence(ContractModel):
    """A source observation that existed by the prediction cutoff."""

    evidence_id: NonEmptyString
    source: NonEmptyString
    observed_at: datetime

    @model_validator(mode="after")
    def require_timezone(self) -> HistoricalEvidence:
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise ValueError("historical evidence timestamps must include a timezone")
        return self


class HistoricalCandidate(ContractModel):
    """One out-of-sample vulnerability ranking row from Member 1."""

    cve_id: NonEmptyString
    description: NonEmptyString
    published_at: date
    model_score: StrictFloat
    model_score_scale: ScoreScale
    model_version: NonEmptyString
    is_out_of_sample: StrictBool
    split_name: NonEmptyString
    cvss_score: StrictFloat | None = Field(default=None, ge=0, le=10)
    cvss_source: NonEmptyString | None = None
    cvss_observed_at: datetime | None = None
    epss_score: StrictFloat | None = Field(default=None, ge=0, le=1)
    epss_observed_at: datetime | None = None
    kev_date_added: date | None = None
    evidence: list[HistoricalEvidence] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_baseline_metadata(self) -> HistoricalCandidate:
        if not self.is_out_of_sample:
            raise ValueError("historical evaluation rejects training rows")
        if self.cvss_score is not None and (
            self.cvss_source is None or self.cvss_observed_at is None
        ):
            raise ValueError("historical CVSS requires source and observation time")
        if self.epss_score is not None and self.epss_observed_at is None:
            raise ValueError("historical EPSS requires an observation time")
        for value in (self.cvss_observed_at, self.epss_observed_at):
            if value is not None and (value.tzinfo is None or value.utcoffset() is None):
                raise ValueError("baseline observation timestamps must include a timezone")
        return self


class HistoricalSnapshot(ContractModel):
    """A frozen monthly decision cohort and its later evaluation boundary."""

    fixture_kind: Literal["real", "synthetic"]
    month: str = Field(pattern=r"^\d{4}-(0[1-9]|1[0-2])$")
    feature_cutoff: datetime
    evaluation_cutoff: datetime
    candidates: list[HistoricalCandidate] = Field(min_length=1)

    @model_validator(mode="after")
    def enforce_temporal_integrity(self) -> HistoricalSnapshot:
        for timestamp in (self.feature_cutoff, self.evaluation_cutoff):
            if timestamp.tzinfo is None or timestamp.utcoffset() is None:
                raise ValueError("snapshot cutoffs must include a timezone")
        if self.evaluation_cutoff <= self.feature_cutoff:
            raise ValueError("evaluation cutoff must follow the feature cutoff")
        if self.feature_cutoff.strftime("%Y-%m") != self.month:
            raise ValueError("feature cutoff must fall within the selected month")

        ids = [candidate.cve_id for candidate in self.candidates]
        if len(ids) != len(set(ids)):
            raise ValueError("historical candidate CVE identifiers must be unique")
        versions = {candidate.model_version for candidate in self.candidates}
        scales = {
            (
                candidate.model_score_scale.minimum,
                candidate.model_score_scale.maximum,
                candidate.model_score_scale.higher_is_riskier,
            )
            for candidate in self.candidates
        }
        if len(versions) != 1 or len(scales) != 1:
            raise ValueError("one snapshot must use one model version and score scale")

        cutoff_date = self.feature_cutoff.date()
        for candidate in self.candidates:
            if candidate.published_at > cutoff_date:
                raise ValueError(f"{candidate.cve_id} was published after the feature cutoff")
            if candidate.kev_date_added is not None and candidate.kev_date_added <= cutoff_date:
                raise ValueError(f"{candidate.cve_id} was already KEV-listed at the cutoff")
            observations = [
                *(item.observed_at for item in candidate.evidence),
                candidate.cvss_observed_at,
                candidate.epss_observed_at,
            ]
            if any(item is not None and item > self.feature_cutoff for item in observations):
                raise ValueError(f"{candidate.cve_id} contains post-cutoff evidence")
        return self


class RankingStrategy(StrEnum):
    MODEL = "model"
    CVSS = "cvss"
    EPSS = "epss"


class HistoricalOutcome(StrEnum):
    CONFIRMED_KEV = "confirmed-kev"
    NOT_KEV_BY_CUTOFF = "not-kev-by-cutoff"
    UNKNOWN = "unknown"


class RankedHistoricalCandidate(ContractModel):
    cve_id: NonEmptyString
    model_rank: int = Field(ge=1)
    cvss_rank: int = Field(ge=1)
    epss_rank: int = Field(ge=1)
    outcome: HistoricalOutcome
    kev_date_added: date | None = None


class BudgetMetrics(ContractModel):
    budget: int = Field(ge=1)
    evaluated_k: int = Field(ge=0)
    hits: int = Field(ge=0)
    precision: float | None
    recall: float | None


class StrategyMetrics(ContractModel):
    strategy: RankingStrategy
    average_precision: float | None
    budgets: list[BudgetMetrics]


class EvaluationCoverage(ContractModel):
    total_candidates: int = Field(ge=0)
    shared_candidates: int = Field(ge=0)
    cvss_pair_candidates: int = Field(ge=0)
    epss_pair_candidates: int = Field(ge=0)


class HistoricalEvaluation(ContractModel):
    month: NonEmptyString
    feature_cutoff: datetime
    evaluation_cutoff: datetime
    model_version: NonEmptyString
    coverage: EvaluationCoverage
    rankings: list[RankedHistoricalCandidate]
    strategies: list[StrategyMetrics]
    model_improvement_over_cvss: dict[str, float | None]
    model_improvement_over_epss: dict[str, float | None]


class HiddenThreatMode(StrEnum):
    MODEL_VS_CVSS = "model_vs_cvss"
    MODEL_VS_EPSS = "model_vs_epss"


class HiddenThreatCandidate(ContractModel):
    cve_id: NonEmptyString
    mode: HiddenThreatMode
    budget: int = Field(ge=1)
    model_rank: int = Field(ge=1)
    baseline_rank: int = Field(ge=1)
    rank_difference: int
    model_score: StrictFloat
    baseline_score: StrictFloat
    outcome: HistoricalOutcome
    kev_date_added: date | None = None
    evidence: list[HistoricalEvidence]
