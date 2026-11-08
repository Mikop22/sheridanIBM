from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StringConstraints,
    model_validator,
)

SCHEMA_VERSION = "1.0"
NonEmptyString = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class ScoreScale(ContractModel):
    minimum: StrictFloat
    maximum: StrictFloat
    higher_is_riskier: StrictBool

    @model_validator(mode="after")
    def validate_bounds(self) -> ScoreScale:
        if self.minimum >= self.maximum:
            raise ValueError("score scale minimum must be less than maximum")
        return self


class VulnerabilityRef(ContractModel):
    vulnerability_id: NonEmptyString
    source: NonEmptyString
    aliases: list[NonEmptyString] = Field(default_factory=list)


class Evidence(ContractModel):
    evidence_id: NonEmptyString
    kind: NonEmptyString
    source: NonEmptyString
    observed_at: datetime
    value: dict[str, Any]

    @model_validator(mode="after")
    def require_timezone(self) -> Evidence:
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        return self


class SignalDirection(StrEnum):
    INCREASES_RISK = "increases_risk"
    DECREASES_RISK = "decreases_risk"
    NEUTRAL = "neutral"
    UNKNOWN = "unknown"


class ExplanatorySignal(ContractModel):
    name: NonEmptyString
    value: Any
    contribution: StrictFloat | None = None
    direction: SignalDirection = SignalDirection.UNKNOWN
    evidence_refs: list[NonEmptyString] = Field(default_factory=list)


class AffectedAsset(ContractModel):
    asset_id: NonEmptyString
    attributes: dict[str, Any] = Field(default_factory=dict)
    match_reason: NonEmptyString
    evidence_refs: list[NonEmptyString] = Field(default_factory=list)


class Prediction(ContractModel):
    schema_version: Literal[SCHEMA_VERSION] = SCHEMA_VERSION
    prediction_id: NonEmptyString
    snapshot_date: date
    vulnerability: VulnerabilityRef
    score: StrictFloat
    score_scale: ScoreScale
    rank: StrictInt | None = Field(default=None, ge=1)
    model_version: NonEmptyString
    signals: list[ExplanatorySignal] = Field(default_factory=list)
    affected_assets: list[AffectedAsset] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_prediction(self) -> Prediction:
        if not self.score_scale.minimum <= self.score <= self.score_scale.maximum:
            raise ValueError("score must fall within the declared score scale")

        evidence_ids = [item.evidence_id for item in self.evidence]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("evidence_id values must be unique")

        asset_ids = [item.asset_id for item in self.affected_assets]
        if len(asset_ids) != len(set(asset_ids)):
            raise ValueError("asset_id values must be unique")

        signal_names = [item.name for item in self.signals]
        if len(signal_names) != len(set(signal_names)):
            raise ValueError("signal names must be unique")

        available_evidence = set(evidence_ids)
        if any(item.observed_at.date() > self.snapshot_date for item in self.evidence):
            raise ValueError("evidence observed after the prediction snapshot is not allowed")
        for signal in self.signals:
            self._reject_dangling_refs(
                signal.evidence_refs, available_evidence, f"signal {signal.name!r}"
            )
        for asset in self.affected_assets:
            self._reject_dangling_refs(
                asset.evidence_refs, available_evidence, f"asset {asset.asset_id!r}"
            )
        return self

    @staticmethod
    def _reject_dangling_refs(refs: list[str], available: set[str], owner: str) -> None:
        missing = sorted(set(refs) - available)
        if missing:
            raise ValueError(f"{owner} has unknown evidence_refs: {missing}")

    def valid_source_refs(self) -> set[str]:
        refs = {
            "prediction:score",
            "prediction:score_scale",
            "prediction:model_version",
            "prediction:snapshot_date",
            "vulnerability:identity",
        }
        if self.rank is not None:
            refs.add("prediction:rank")
        refs.update(f"signal:{signal.name}" for signal in self.signals)
        refs.update(f"asset:{asset.asset_id}" for asset in self.affected_assets)
        refs.update(f"evidence:{item.evidence_id}" for item in self.evidence)
        return refs


class ExplanationProvider(StrEnum):
    LOCAL = "local"
    OLLAMA = "ollama"
    HUGGINGFACE = "huggingface"
    WATSONX = "watsonx"


class GenerationStatus(StrEnum):
    COMPLETE = "complete"
    UNAVAILABLE = "unavailable"
    INVALID_OUTPUT = "invalid_output"


class GroundedStatement(ContractModel):
    text: NonEmptyString
    source_refs: list[NonEmptyString] = Field(min_length=1)


class ExplanationEvidenceMetadata(ContractModel):
    evidence_id: NonEmptyString
    source: NonEmptyString
    observed_at: datetime


class ExplanationContext(ContractModel):
    prediction_snapshot: date
    model_version: NonEmptyString
    model_score: StrictFloat
    score_scale: ScoreScale
    score_meaning: NonEmptyString
    evidence: list[ExplanationEvidenceMetadata]
    missing_information: list[NonEmptyString]


class Explanation(ContractModel):
    schema_version: Literal[SCHEMA_VERSION] = SCHEMA_VERSION
    prediction_id: NonEmptyString
    provider: ExplanationProvider
    generation_status: GenerationStatus
    context: ExplanationContext
    observed_facts: list[GroundedStatement]
    interpretations: list[GroundedStatement]
    limitations: list[NonEmptyString]
    trace_id: NonEmptyString
    provider_metadata: dict[str, str] | None = None

    def validate_source_refs(self, prediction: Prediction) -> None:
        allowed = prediction.valid_source_refs()
        used = {
            ref
            for statement in [*self.observed_facts, *self.interpretations]
            for ref in statement.source_refs
        }
        unknown = sorted(used - allowed)
        if unknown:
            raise ValueError(f"explanation contains unknown source_refs: {unknown}")


class SecurityEvent(ContractModel):
    schema_version: Literal[SCHEMA_VERSION] = SCHEMA_VERSION
    event_id: NonEmptyString
    observed_at: datetime
    source: NonEmptyString
    prediction_id: NonEmptyString
    vulnerability_id: NonEmptyString
    asset_id: NonEmptyString
    evidence_refs: list[NonEmptyString] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_event(self) -> SecurityEvent:
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        if len(self.evidence_refs) != len(set(self.evidence_refs)):
            raise ValueError("evidence_refs values must be unique")
        return self


class EventProcessingStatus(StrEnum):
    NO_ACTION = "no_action"
    RECOMMENDATION_CREATED = "recommendation_created"
    INSUFFICIENT_INFORMATION = "insufficient_information"


class RecommendationStatus(StrEnum):
    RECORDED = "recorded"
    INVESTIGATING = "investigating"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"


class DecisionAction(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


class RecommendationDecision(ContractModel):
    schema_version: Literal[SCHEMA_VERSION] = SCHEMA_VERSION
    action: DecisionAction
    actor: NonEmptyString
    reason: NonEmptyString


class OperationalDecision(StrEnum):
    MONITOR = "MONITOR"
    INVESTIGATE = "INVESTIGATE"
    ACTION_REQUIRED = "ACTION_REQUIRED"
    URGENT = "URGENT"


class EligibilityOutcome(StrEnum):
    CODE_REMEDIABLE = "CODE_REMEDIABLE"
    OPERATIONAL_REMEDIATION = "OPERATIONAL_REMEDIATION"
    NEEDS_INVESTIGATION = "NEEDS_INVESTIGATION"
    NOT_ELIGIBLE = "NOT_ELIGIBLE"


class DecisionReason(ContractModel):
    code: NonEmptyString
    message: NonEmptyString
    source_refs: list[NonEmptyString] = Field(min_length=1)


class DecisionEvidence(ContractModel):
    source_ref: NonEmptyString
    category: NonEmptyString
    value: Any
    provenance: NonEmptyString


class EligibilityAssessment(ContractModel):
    outcome: EligibilityOutcome
    reason_codes: list[NonEmptyString] = Field(min_length=1)
    evidence_refs: list[NonEmptyString] = Field(default_factory=list)
    agent_eligible: StrictBool
    execution_authorized: Literal[False] = False


class AssetDecision(ContractModel):
    asset_id: NonEmptyString
    asset_name: NonEmptyString
    owner_team: NonEmptyString
    repository_identifier: NonEmptyString | None = None
    component_package: NonEmptyString | None = None
    match_status: NonEmptyString
    operational_decision: OperationalDecision
    reasons: list[DecisionReason] = Field(min_length=1)
    evidence_used: list[DecisionEvidence] = Field(min_length=1)
    proposed_next_action: NonEmptyString
    eligibility: EligibilityAssessment
    synthetic_scenario: Literal[True] = True
    mapping_provenance: Literal[
        "internally_consistent_synthetic_scenario_not_external_product_intelligence"
    ]

    @model_validator(mode="after")
    def validate_decision_source_refs(self) -> AssetDecision:
        available = {item.source_ref for item in self.evidence_used}
        used = {
            ref for reason in self.reasons for ref in reason.source_refs
        } | set(self.eligibility.evidence_refs)
        missing = sorted(used - available)
        if missing:
            raise ValueError(f"asset decision contains unsupported source_refs: {missing}")
        return self


class RemediationRecommendation(ContractModel):
    schema_version: Literal[SCHEMA_VERSION] = SCHEMA_VERSION
    recommendation_id: NonEmptyString
    event_id: NonEmptyString
    prediction_id: NonEmptyString
    vulnerability_id: NonEmptyString
    asset_id: NonEmptyString
    finding_id: NonEmptyString
    material_fingerprint: NonEmptyString
    risk_score: StrictFloat
    score_scale: ScoreScale
    trigger_reason: NonEmptyString
    evidence_refs: list[NonEmptyString] = Field(min_length=1)
    operational_decision: OperationalDecision
    decision_reasons: list[DecisionReason] = Field(min_length=1)
    evidence_used: list[DecisionEvidence] = Field(min_length=1)
    eligibility: EligibilityAssessment
    recommended_next_step: NonEmptyString
    approval_required: StrictBool
    workflow_status: RecommendationStatus
    created_at: datetime
    decided_at: datetime | None = None
    decided_by: NonEmptyString | None = None
    decision_reason: NonEmptyString | None = None


class EventProcessingOutcome(ContractModel):
    schema_version: Literal[SCHEMA_VERSION] = SCHEMA_VERSION
    event_id: NonEmptyString
    prediction_id: NonEmptyString
    finding_id: NonEmptyString | None = None
    material_fingerprint: NonEmptyString | None = None
    processing_status: EventProcessingStatus
    reason_code: NonEmptyString
    reason: NonEmptyString
    matched_vulnerability_id: NonEmptyString | None = None
    matched_asset_id: NonEmptyString | None = None
    recommendation_id: NonEmptyString | None = None
    operational_decision: OperationalDecision | None = None
    decision_reasons: list[DecisionReason] = Field(default_factory=list)
    evidence_used: list[DecisionEvidence] = Field(default_factory=list)
    eligibility: EligibilityAssessment | None = None
    proposed_next_action: NonEmptyString | None = None
    asset_decision: AssetDecision | None = None
    dry_run: StrictBool = False
    persisted: StrictBool = True
    reused_recommendation: StrictBool = False
    processed_at: datetime


class HealthStatus(ContractModel):
    status: Literal["ready", "not_ready"]
    explanation_provider: ExplanationProvider
    provider_ready: bool


class ErrorDetail(ContractModel):
    location: list[str | int] = Field(default_factory=list)
    message: str
    error_type: str | None = None


class ErrorBody(ContractModel):
    code: NonEmptyString
    message: NonEmptyString
    details: list[ErrorDetail] = Field(default_factory=list)


class ErrorResponse(ContractModel):
    schema_version: Literal[SCHEMA_VERSION] = SCHEMA_VERSION
    error: ErrorBody
    trace_id: NonEmptyString
