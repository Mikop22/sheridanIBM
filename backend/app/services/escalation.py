from __future__ import annotations

from dataclasses import dataclass

from app.domain.assets import AssetMatchStatus, BusinessCriticality, ExposureStatus
from app.domain.contracts import (
    AssetDecision,
    DecisionEvidence,
    DecisionReason,
    EligibilityAssessment,
    EligibilityOutcome,
    OperationalDecision,
    Prediction,
)
from app.services.asset_correlation import AssetCorrelation


@dataclass(frozen=True)
class EscalationPolicy:
    version: str = "synthetic-demo-v1"
    urgent_max_rank: int = 5
    action_max_rank: int = 15
    investigate_unknown_max_rank: int = 15

    def __post_init__(self) -> None:
        if self.urgent_max_rank < 1:
            raise ValueError("urgent_max_rank must be positive")
        if self.action_max_rank < self.urgent_max_rank:
            raise ValueError("action_max_rank must be at least urgent_max_rank")
        if self.investigate_unknown_max_rank < 1:
            raise ValueError("investigate_unknown_max_rank must be positive")


class EscalationEvaluator:
    def __init__(self, policy: EscalationPolicy) -> None:
        self.policy = policy

    def evaluate(self, prediction: Prediction, correlation: AssetCorrelation) -> AssetDecision:
        evidence = self._evidence(prediction, correlation)
        decision, reasons = self._decision(prediction, correlation)
        eligibility = self._eligibility(correlation, decision)
        return AssetDecision(
            asset_id=correlation.asset.asset_id,
            asset_name=correlation.asset.application_name,
            owner_team=correlation.asset.owner_team,
            repository_identifier=correlation.asset.repository_identifier,
            component_package=correlation.asset.component_package,
            match_status=correlation.match_status.value,
            operational_decision=decision,
            reasons=reasons,
            evidence_used=evidence,
            proposed_next_action=self._next_action(decision),
            eligibility=eligibility,
            mapping_provenance=(
                "internally_consistent_synthetic_scenario_not_external_product_intelligence"
            ),
        )

    def decision_for_unmapped_finding(self, prediction: Prediction) -> OperationalDecision:
        rank = prediction.rank
        if rank is not None and rank <= self.policy.investigate_unknown_max_rank:
            return OperationalDecision.INVESTIGATE
        return OperationalDecision.MONITOR

    def _decision(
        self, prediction: Prediction, correlation: AssetCorrelation
    ) -> tuple[OperationalDecision, list[DecisionReason]]:
        status = correlation.match_status
        rank = prediction.rank
        refs = correlation.evidence_refs
        rank_ref = "prediction:rank" if rank is not None else "prediction:rank:missing"
        has_exploitation_evidence = bool(
            correlation.mapping and correlation.mapping.exploitation_evidence_refs
        )

        if status is AssetMatchStatus.CONFIRMED_UNAFFECTED:
            return OperationalDecision.MONITOR, [
                DecisionReason(
                    code="ASSET_CONFIRMED_UNAFFECTED_IN_SYNTHETIC_SCENARIO",
                    message=(
                        "Affirmative synthetic-scenario evidence records this asset as unaffected; "
                        "this is not external product intelligence."
                    ),
                    source_refs=refs,
                )
            ]

        if status in {AssetMatchStatus.UNKNOWN, AssetMatchStatus.POTENTIALLY_AFFECTED}:
            reason_code = (
                "UNKNOWN_ASSET_RELEVANCE"
                if status is AssetMatchStatus.UNKNOWN
                else "POTENTIAL_ASSET_RELEVANCE"
            )
            if (
                rank is not None and rank <= self.policy.investigate_unknown_max_rank
            ) or has_exploitation_evidence:
                return OperationalDecision.INVESTIGATE, [
                    DecisionReason(
                        code=reason_code,
                        message=(
                            "Asset applicability is not confirmed and must not be treated as safe."
                        ),
                        source_refs=refs,
                    ),
                    DecisionReason(
                        code="MODEL_RANK_WITHIN_INVESTIGATION_BAND",
                        message=(
                            f"The supplied model rank {rank} is within the demonstration "
                            f"investigation band of 1-{self.policy.investigate_unknown_max_rank}."
                        ),
                        source_refs=[rank_ref, f"policy:{self.policy.version}"],
                    ),
                ]
            return OperationalDecision.MONITOR, [
                DecisionReason(
                    code=reason_code,
                    message="Asset applicability is not confirmed and remains explicitly unknown.",
                    source_refs=refs,
                ),
                DecisionReason(
                    code="MODEL_RANK_OUTSIDE_INVESTIGATION_BAND",
                    message=(
                        "The supplied rank does not enter the configurable demonstration "
                        "investigation band; the finding remains monitored."
                    ),
                    source_refs=[rank_ref, f"policy:{self.policy.version}"],
                ),
            ]

        missing = []
        if rank is None:
            missing.append(rank_ref)
        if correlation.asset.business_criticality is BusinessCriticality.UNKNOWN:
            missing.append(f"asset:{correlation.asset.asset_id}:criticality")
        if correlation.asset.exposure_status is ExposureStatus.UNKNOWN:
            missing.append(f"asset:{correlation.asset.asset_id}:exposure")
        if missing:
            return OperationalDecision.INVESTIGATE, [
                DecisionReason(
                    code="CONFIRMED_MATCH_WITH_INCOMPLETE_CONTEXT",
                    message="The synthetic affected match lacks context required for escalation.",
                    source_refs=[*refs, *missing],
                )
            ]

        critical = correlation.asset.business_criticality is BusinessCriticality.CRITICAL
        high_or_critical = correlation.asset.business_criticality in {
            BusinessCriticality.CRITICAL,
            BusinessCriticality.HIGH,
        }
        exposed = correlation.asset.exposure_status is ExposureStatus.INTERNET_FACING
        assert rank is not None
        if rank <= self.policy.urgent_max_rank and (
            (critical and exposed) or (has_exploitation_evidence and (high_or_critical or exposed))
        ):
            return OperationalDecision.URGENT, [
                DecisionReason(
                    code="VERIFIED_SYNTHETIC_ASSET_MATCH",
                    message=(
                        "The asset is affected within the internally consistent synthetic scenario."
                    ),
                    source_refs=refs,
                ),
                DecisionReason(
                    code="TOP_RANKED_CRITICAL_EXPOSED_ASSET",
                    message=(
                        f"Rank {rank}, critical business impact, and internet exposure jointly "
                        "meet the demonstration urgent rule."
                    ),
                    source_refs=[
                        rank_ref,
                        f"asset:{correlation.asset.asset_id}:criticality",
                        f"asset:{correlation.asset.asset_id}:exposure",
                        f"policy:{self.policy.version}",
                    ],
                ),
            ]
        if rank <= self.policy.action_max_rank and (
            high_or_critical or exposed or has_exploitation_evidence
        ):
            return OperationalDecision.ACTION_REQUIRED, [
                DecisionReason(
                    code="VERIFIED_SYNTHETIC_ASSET_MATCH",
                    message=(
                        "The asset is affected within the internally consistent synthetic scenario."
                    ),
                    source_refs=refs,
                ),
                DecisionReason(
                    code="RANK_AND_ORGANIZATIONAL_IMPACT_REQUIRE_ACTION",
                    message=(
                        f"Rank {rank} is within the demonstration action band and combines with "
                        "high organizational impact or exposure."
                    ),
                    source_refs=[
                        rank_ref,
                        f"asset:{correlation.asset.asset_id}:criticality",
                        f"asset:{correlation.asset.asset_id}:exposure",
                        f"policy:{self.policy.version}",
                    ],
                ),
            ]
        if rank <= self.policy.action_max_rank:
            return OperationalDecision.INVESTIGATE, [
                DecisionReason(
                    code="RANKED_CONFIRMED_MATCH_WITH_LIMITED_ORGANIZATIONAL_IMPACT",
                    message=(
                        "The model rank merits investigation, but criticality and exposure do not "
                        "justify action automatically."
                    ),
                    source_refs=[rank_ref, *refs, f"policy:{self.policy.version}"],
                )
            ]
        return OperationalDecision.MONITOR, [
            DecisionReason(
                code="CONFIRMED_MATCH_OUTSIDE_ACTION_BAND",
                message=(
                    "The affected synthetic asset remains monitored because the supplied rank is "
                    "outside the demonstration action band."
                ),
                source_refs=[rank_ref, *refs, f"policy:{self.policy.version}"],
            )
        ]

    def _eligibility(
        self, correlation: AssetCorrelation, decision: OperationalDecision
    ) -> EligibilityAssessment:
        status = correlation.match_status
        mapping = correlation.mapping
        if status is AssetMatchStatus.CONFIRMED_UNAFFECTED:
            return EligibilityAssessment(
                outcome=EligibilityOutcome.NOT_ELIGIBLE,
                reason_codes=["ASSET_CONFIRMED_UNAFFECTED"],
                evidence_refs=correlation.evidence_refs,
                agent_eligible=False,
            )
        if status is not AssetMatchStatus.CONFIRMED_AFFECTED or mapping is None:
            return EligibilityAssessment(
                outcome=EligibilityOutcome.NEEDS_INVESTIGATION,
                reason_codes=["AFFECTED_STATUS_NOT_CONFIRMED"],
                evidence_refs=correlation.evidence_refs,
                agent_eligible=False,
            )
        path = mapping.remediation_path
        if path is None:
            return EligibilityAssessment(
                outcome=EligibilityOutcome.NEEDS_INVESTIGATION,
                reason_codes=["REMEDIATION_PATH_NOT_VERIFIED"],
                evidence_refs=correlation.evidence_refs,
                agent_eligible=False,
            )
        if not path.verified_for_demo:
            return EligibilityAssessment(
                outcome=EligibilityOutcome.NOT_ELIGIBLE,
                reason_codes=["REMEDIATION_PATH_NOT_VERIFIED"],
                evidence_refs=path.evidence_refs,
                agent_eligible=False,
            )
        if path.kind == "code_dependency_change":
            consistent = bool(
                correlation.asset.repository_identifier
                and correlation.asset.component_package
                and path.repository_identifier == correlation.asset.repository_identifier
                and path.component_package == correlation.asset.component_package
            )
            if not consistent:
                return EligibilityAssessment(
                    outcome=EligibilityOutcome.NOT_ELIGIBLE,
                    reason_codes=["CODE_REMEDIATION_TARGET_MISMATCH"],
                    evidence_refs=path.evidence_refs,
                    agent_eligible=False,
                )
            return EligibilityAssessment(
                outcome=EligibilityOutcome.CODE_REMEDIABLE,
                reason_codes=["VERIFIED_DEMO_REPOSITORY_COMPONENT_AND_PATH"],
                evidence_refs=path.evidence_refs,
                agent_eligible=decision
                in {OperationalDecision.ACTION_REQUIRED, OperationalDecision.URGENT},
            )
        if path.kind == "operational_configuration_change":
            return EligibilityAssessment(
                outcome=EligibilityOutcome.OPERATIONAL_REMEDIATION,
                reason_codes=["VERIFIED_DEMO_OPERATIONAL_PATH"],
                evidence_refs=path.evidence_refs,
                agent_eligible=False,
            )
        return EligibilityAssessment(
            outcome=EligibilityOutcome.NOT_ELIGIBLE,
            reason_codes=["UNSUPPORTED_REMEDIATION_PATH"],
            evidence_refs=path.evidence_refs,
            agent_eligible=False,
        )

    def _evidence(
        self, prediction: Prediction, correlation: AssetCorrelation
    ) -> list[DecisionEvidence]:
        asset = correlation.asset
        evidence = [
            DecisionEvidence(
                source_ref=(
                    "prediction:rank"
                    if prediction.rank is not None
                    else "prediction:rank:missing"
                ),
                category="model_rank",
                value=prediction.rank,
                provenance="submitted prediction rank; no percentile was calculated",
            ),
            DecisionEvidence(
                source_ref="prediction:score",
                category="model_score",
                value=prediction.score,
                provenance="uncalibrated relative model score; not an exploitation probability",
            ),
            DecisionEvidence(
                source_ref="prediction:score_scale",
                category="score_semantics",
                value=prediction.score_scale.model_dump(mode="json"),
                provenance="declared prediction score scale and direction",
            ),
            DecisionEvidence(
                source_ref=f"asset:{asset.asset_id}:match",
                category="asset_match",
                value=correlation.match_status.value,
                provenance=(
                    "internally consistent synthetic scenario; not external product intelligence"
                ),
            ),
            DecisionEvidence(
                source_ref=f"asset:{asset.asset_id}:criticality",
                category="business_criticality",
                value=asset.business_criticality.value,
                provenance="synthetic demo inventory",
            ),
            DecisionEvidence(
                source_ref=f"asset:{asset.asset_id}:exposure",
                category="exposure_status",
                value=asset.exposure_status.value,
                provenance="synthetic demo inventory",
            ),
            DecisionEvidence(
                source_ref=f"policy:{self.policy.version}",
                category="escalation_policy",
                value={
                    "urgent_max_rank": self.policy.urgent_max_rank,
                    "action_max_rank": self.policy.action_max_rank,
                    "investigate_unknown_max_rank": self.policy.investigate_unknown_max_rank,
                },
                provenance="configurable demonstration defaults; not production thresholds",
            ),
        ]
        if correlation.mapping:
            evidence.extend(
                DecisionEvidence(
                    source_ref=ref,
                    category="synthetic_mapping_evidence",
                    value=correlation.mapping.assertion,
                    provenance=(
                        "internally consistent synthetic scenario; not external product "
                        "intelligence"
                    ),
                )
                for ref in correlation.mapping.evidence_refs
            )
        else:
            evidence.append(
                DecisionEvidence(
                    source_ref=f"inventory:asset:{asset.asset_id}",
                    category="inventory_presence",
                    value=True,
                    provenance="synthetic demo inventory; no CVE mapping assertion exists",
                )
            )
        if correlation.mapping and correlation.mapping.exploitation_evidence_refs:
            evidence.append(
                DecisionEvidence(
                    source_ref=correlation.mapping.exploitation_evidence_refs[0],
                    category="independent_exploitation_evidence",
                    value=True,
                    provenance="explicit referenced evidence",
                )
            )
        return evidence

    @staticmethod
    def _next_action(decision: OperationalDecision) -> str:
        return {
            OperationalDecision.MONITOR: (
                "Keep the finding visible and reevaluate when ranking or asset evidence changes."
            ),
            OperationalDecision.INVESTIGATE: (
                "Validate asset applicability and collect missing operational evidence."
            ),
            OperationalDecision.ACTION_REQUIRED: (
                "Prepare a reviewed remediation plan for human approval; do not execute changes."
            ),
            OperationalDecision.URGENT: (
                "Prioritize immediate human review and remediation planning; do not execute "
                "changes."
            ),
        }[decision]
