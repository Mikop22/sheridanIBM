from __future__ import annotations

from copy import deepcopy

from app.domain.assets import RemediationPath
from app.domain.contracts import OperationalDecision, Prediction
from app.services.asset_correlation import (
    AssetCorrelation,
    AssetCorrelationService,
    load_asset_inventory,
)
from app.services.escalation import EscalationEvaluator, EscalationPolicy


def _prediction(payload: dict, vulnerability_id: str, rank: int) -> Prediction:
    prepared = deepcopy(payload)
    prepared["vulnerability"]["vulnerability_id"] = vulnerability_id
    prepared["rank"] = rank
    return Prediction.model_validate(prepared)


def test_rank_and_asset_context_jointly_drive_escalation(prediction_payload: dict) -> None:
    correlations = AssetCorrelationService(load_asset_inventory())
    evaluator = EscalationEvaluator(EscalationPolicy())
    top_prediction = _prediction(prediction_payload, "CVE-2026-2699", 1)

    decisions = [
        evaluator.evaluate(top_prediction, item)
        for item in correlations.correlations_for("CVE-2026-2699")
    ]

    by_asset = {item.asset_id: item for item in decisions}
    assert by_asset["demo-asset-identity"].operational_decision is OperationalDecision.URGENT
    assert (
        by_asset["demo-asset-analytics"].operational_decision
        is OperationalDecision.INVESTIGATE
    )
    assert by_asset["demo-asset-identity"].eligibility.agent_eligible is True
    assert all(item.eligibility.execution_authorized is False for item in decisions)


def test_action_and_unaffected_outcomes_preserve_distinct_eligibility(
    prediction_payload: dict,
) -> None:
    correlations = AssetCorrelationService(load_asset_inventory())
    evaluator = EscalationEvaluator(EscalationPolicy())

    action = evaluator.evaluate(
        _prediction(prediction_payload, "CVE-2026-8037", 2),
        correlations.correlate("CVE-2026-8037", "demo-asset-payments"),
    )
    unaffected = evaluator.evaluate(
        _prediction(prediction_payload, "CVE-2026-1603", 3),
        correlations.correlate("CVE-2026-1603", "demo-asset-admin"),
    )

    assert action.operational_decision is OperationalDecision.ACTION_REQUIRED
    assert action.eligibility.outcome.value == "OPERATIONAL_REMEDIATION"
    assert action.eligibility.agent_eligible is False
    assert unaffected.operational_decision is OperationalDecision.MONITOR
    assert unaffected.match_status == "confirmed_unaffected"
    assert unaffected.eligibility.outcome.value == "NOT_ELIGIBLE"


def test_critical_and_exposed_asset_alone_cannot_require_action(
    prediction_payload: dict,
) -> None:
    correlations = AssetCorrelationService(load_asset_inventory())
    evaluator = EscalationEvaluator(EscalationPolicy())
    lower_ranked = _prediction(prediction_payload, "CVE-2026-2699", 20)
    correlation = correlations.correlate("CVE-2026-2699", "demo-asset-identity")

    decision = evaluator.evaluate(lower_ranked, correlation)

    assert decision.operational_decision is OperationalDecision.MONITOR
    assert decision.eligibility.agent_eligible is False


def test_unknown_mapping_uses_rank_without_becoming_unaffected(
    prediction_payload: dict,
) -> None:
    correlations = AssetCorrelationService(load_asset_inventory())
    evaluator = EscalationEvaluator(EscalationPolicy())
    correlation = correlations.correlate("CVE-2026-2699", "demo-asset-catalog")

    high = evaluator.evaluate(_prediction(prediction_payload, "CVE-2026-2699", 4), correlation)
    low = evaluator.evaluate(_prediction(prediction_payload, "CVE-2026-2699", 20), correlation)

    assert high.match_status == "unknown"
    assert high.operational_decision is OperationalDecision.INVESTIGATE
    assert low.match_status == "unknown"
    assert low.operational_decision is OperationalDecision.MONITOR


def test_unknown_investigation_rank_boundary_is_configurable(
    prediction_payload: dict,
) -> None:
    correlations = AssetCorrelationService(load_asset_inventory())
    evaluator = EscalationEvaluator(EscalationPolicy(investigate_unknown_max_rank=15))
    correlation = correlations.correlate("CVE-2026-2699", "demo-asset-catalog")

    boundary = evaluator.evaluate(
        _prediction(prediction_payload, "CVE-2026-2699", 15), correlation
    )
    outside = evaluator.evaluate(
        _prediction(prediction_payload, "CVE-2026-2699", 16), correlation
    )

    assert boundary.operational_decision is OperationalDecision.INVESTIGATE
    assert outside.operational_decision is OperationalDecision.MONITOR


def test_confirmed_match_with_missing_rank_requires_investigation(
    prediction_payload: dict,
) -> None:
    correlations = AssetCorrelationService(load_asset_inventory())
    evaluator = EscalationEvaluator(EscalationPolicy())
    prepared = deepcopy(prediction_payload)
    prepared["vulnerability"]["vulnerability_id"] = "CVE-2026-2699"
    prepared["rank"] = None

    decision = evaluator.evaluate(
        Prediction.model_validate(prepared),
        correlations.correlate("CVE-2026-2699", "demo-asset-identity"),
    )

    assert decision.operational_decision is OperationalDecision.INVESTIGATE
    assert decision.reasons[0].code == "CONFIRMED_MATCH_WITH_INCOMPLETE_CONTEXT"


def test_referenced_exploitation_evidence_can_promote_ranked_investigation(
    prediction_payload: dict,
) -> None:
    service = AssetCorrelationService(load_asset_inventory())
    evaluator = EscalationEvaluator(EscalationPolicy())
    base = service.correlate("CVE-2026-44825", "demo-asset-observability")
    mapping = base.mapping.model_copy(
        update={"exploitation_evidence_refs": ["demo-evidence-observability-possible"]}
    )
    correlation = AssetCorrelation(base.asset, base.match_status, mapping)

    decision = evaluator.evaluate(
        _prediction(prediction_payload, "CVE-2026-44825", 20), correlation
    )

    assert decision.operational_decision is OperationalDecision.INVESTIGATE
    assert any(
        item.category == "independent_exploitation_evidence"
        for item in decision.evidence_used
    )


def test_unsupported_or_mismatched_code_paths_are_not_agent_eligible(
    prediction_payload: dict,
) -> None:
    service = AssetCorrelationService(load_asset_inventory())
    evaluator = EscalationEvaluator(EscalationPolicy())
    base = service.correlate("CVE-2026-2699", "demo-asset-identity")
    prediction = _prediction(prediction_payload, "CVE-2026-2699", 1)

    unsupported_mapping = base.mapping.model_copy(
        update={
            "remediation_path": RemediationPath(
                kind="future_unknown_path",
                verified_for_demo=True,
                evidence_refs=["demo-evidence-identity-match"],
            )
        }
    )
    mismatch_mapping = base.mapping.model_copy(
        update={
            "remediation_path": RemediationPath(
                kind="code_dependency_change",
                verified_for_demo=True,
                repository_identifier="demo/wrong-repository",
                component_package="demo-auth-middleware",
                evidence_refs=["demo-evidence-identity-match"],
            )
        }
    )

    unsupported = evaluator.evaluate(
        prediction,
        AssetCorrelation(base.asset, base.match_status, unsupported_mapping),
    )
    mismatch = evaluator.evaluate(
        prediction,
        AssetCorrelation(base.asset, base.match_status, mismatch_mapping),
    )

    assert unsupported.eligibility.outcome.value == "NOT_ELIGIBLE"
    assert unsupported.eligibility.reason_codes == ["UNSUPPORTED_REMEDIATION_PATH"]
    assert mismatch.eligibility.reason_codes == ["CODE_REMEDIATION_TARGET_MISMATCH"]
    assert unsupported.eligibility.agent_eligible is False
    assert mismatch.eligibility.agent_eligible is False
