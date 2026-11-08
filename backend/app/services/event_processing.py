from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from app.domain.contracts import (
    AssetDecision,
    EventProcessingOutcome,
    EventProcessingStatus,
    OperationalDecision,
    Prediction,
    RecommendationStatus,
    RemediationRecommendation,
    SecurityEvent,
)
from app.domain.errors import EventAlreadyExistsError, PredictionNotFoundError
from app.event_repository import SecurityEventRepository
from app.repositories import PredictionRepository
from app.services.asset_correlation import AssetCorrelationService
from app.services.escalation import EscalationEvaluator


class SecurityEventProcessor:
    def __init__(
        self,
        predictions: PredictionRepository,
        events: SecurityEventRepository,
        correlations: AssetCorrelationService,
        evaluator: EscalationEvaluator,
    ) -> None:
        self._predictions = predictions
        self._events = events
        self._correlations = correlations
        self._evaluator = evaluator

    def process(self, event: SecurityEvent, *, dry_run: bool = False) -> EventProcessingOutcome:
        request_fingerprint = self._request_fingerprint(event)
        if not dry_run:
            existing = self._events.find_event(event.event_id)
            if existing is not None:
                if existing.fingerprint != request_fingerprint:
                    raise EventAlreadyExistsError(event.event_id)
                return existing.outcome

        try:
            prediction = self._predictions.get(event.prediction_id)
        except PredictionNotFoundError:
            return self._outcome_without_decision(
                event,
                request_fingerprint,
                "prediction_not_found",
                "The referenced prediction is not available for deterministic evaluation.",
                dry_run=dry_run,
            )

        vulnerability_ids = {
            prediction.vulnerability.vulnerability_id,
            *prediction.vulnerability.aliases,
        }
        if event.vulnerability_id not in vulnerability_ids:
            return self._outcome_without_decision(
                event,
                request_fingerprint,
                "vulnerability_not_matched",
                "The event vulnerability identifier does not match the referenced prediction.",
                dry_run=dry_run,
            )

        correlation = self._correlations.correlate(
            prediction.vulnerability.vulnerability_id, event.asset_id
        )
        if correlation is None:
            return self._outcome_without_decision(
                event,
                request_fingerprint,
                "asset_not_in_inventory",
                "The event asset is not present in the configured synthetic inventory.",
                matched_vulnerability_id=prediction.vulnerability.vulnerability_id,
                dry_run=dry_run,
            )

        available_evidence = {item.evidence_id for item in prediction.evidence}
        unsupported = sorted(set(event.evidence_refs) - available_evidence)
        if unsupported:
            return self._outcome_without_decision(
                event,
                request_fingerprint,
                "unsupported_evidence",
                "The event contains evidence references not supplied by the prediction.",
                matched_vulnerability_id=prediction.vulnerability.vulnerability_id,
                matched_asset_id=correlation.asset.asset_id,
                dry_run=dry_run,
            )

        asset_decision = self._evaluator.evaluate(prediction, correlation)
        finding_id = self._finding_id(prediction, correlation.asset.asset_id)
        material_fingerprint = self._material_fingerprint(
            prediction, asset_decision, event.evidence_refs, self._evaluator.policy.version
        )
        recommendation = self._recommendation(
            event, prediction, asset_decision, finding_id, material_fingerprint
        )
        processing_status = (
            EventProcessingStatus.NO_ACTION
            if asset_decision.operational_decision is OperationalDecision.MONITOR
            else EventProcessingStatus.RECOMMENDATION_CREATED
        )
        outcome = EventProcessingOutcome(
            event_id=event.event_id,
            prediction_id=event.prediction_id,
            finding_id=finding_id,
            material_fingerprint=material_fingerprint,
            processing_status=processing_status,
            reason_code=asset_decision.reasons[0].code,
            reason=asset_decision.reasons[0].message,
            matched_vulnerability_id=prediction.vulnerability.vulnerability_id,
            matched_asset_id=correlation.asset.asset_id,
            recommendation_id=None if dry_run else recommendation.recommendation_id,
            operational_decision=asset_decision.operational_decision,
            decision_reasons=asset_decision.reasons,
            evidence_used=asset_decision.evidence_used,
            eligibility=asset_decision.eligibility,
            proposed_next_action=asset_decision.proposed_next_action,
            asset_decision=asset_decision,
            dry_run=dry_run,
            persisted=not dry_run,
            processed_at=datetime.now(UTC),
        )
        if dry_run:
            return outcome
        return self._events.record_event(
            request_fingerprint,
            finding_id,
            material_fingerprint,
            outcome,
            recommendation,
        )

    def _outcome_without_decision(
        self,
        event: SecurityEvent,
        request_fingerprint: str,
        reason_code: str,
        reason: str,
        *,
        matched_vulnerability_id: str | None = None,
        matched_asset_id: str | None = None,
        dry_run: bool,
    ) -> EventProcessingOutcome:
        outcome = EventProcessingOutcome(
            event_id=event.event_id,
            prediction_id=event.prediction_id,
            processing_status=EventProcessingStatus.INSUFFICIENT_INFORMATION,
            reason_code=reason_code,
            reason=reason,
            matched_vulnerability_id=matched_vulnerability_id,
            matched_asset_id=matched_asset_id,
            dry_run=dry_run,
            persisted=not dry_run,
            processed_at=datetime.now(UTC),
        )
        if dry_run:
            return outcome
        return self._events.record_event(request_fingerprint, None, None, outcome, None)

    def _recommendation(
        self,
        event: SecurityEvent,
        prediction: Prediction,
        decision: AssetDecision,
        finding_id: str,
        material_fingerprint: str,
    ) -> RemediationRecommendation:
        recommendation_id = f"rec-{material_fingerprint[:20]}"
        approval_required = decision.operational_decision in {
            OperationalDecision.ACTION_REQUIRED,
            OperationalDecision.URGENT,
        }
        workflow_status = {
            OperationalDecision.MONITOR: RecommendationStatus.RECORDED,
            OperationalDecision.INVESTIGATE: RecommendationStatus.INVESTIGATING,
            OperationalDecision.ACTION_REQUIRED: RecommendationStatus.PENDING_APPROVAL,
            OperationalDecision.URGENT: RecommendationStatus.PENDING_APPROVAL,
        }[decision.operational_decision]
        evidence_refs = list(
            dict.fromkeys(
                [
                    *event.evidence_refs,
                    *(ref for reason in decision.reasons for ref in reason.source_refs),
                    *decision.eligibility.evidence_refs,
                ]
            )
        )
        return RemediationRecommendation(
            recommendation_id=recommendation_id,
            event_id=event.event_id,
            prediction_id=prediction.prediction_id,
            vulnerability_id=prediction.vulnerability.vulnerability_id,
            asset_id=decision.asset_id,
            finding_id=finding_id,
            material_fingerprint=material_fingerprint,
            risk_score=prediction.score,
            score_scale=prediction.score_scale,
            trigger_reason=decision.reasons[0].message,
            evidence_refs=evidence_refs,
            operational_decision=decision.operational_decision,
            decision_reasons=decision.reasons,
            evidence_used=decision.evidence_used,
            eligibility=decision.eligibility,
            recommended_next_step=decision.proposed_next_action,
            approval_required=approval_required,
            workflow_status=workflow_status,
            created_at=datetime.now(UTC),
        )

    @staticmethod
    def _finding_id(prediction: Prediction, asset_id: str) -> str:
        payload = (
            f"{prediction.prediction_id}\0{prediction.vulnerability.vulnerability_id}\0{asset_id}"
        )
        return f"finding-{hashlib.sha256(payload.encode()).hexdigest()[:20]}"

    @staticmethod
    def _request_fingerprint(event: SecurityEvent) -> str:
        payload = json.dumps(event.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()

    @staticmethod
    def _material_fingerprint(
        prediction: Prediction,
        decision: AssetDecision,
        event_evidence_refs: list[str],
        policy_version: str,
    ) -> str:
        payload = {
            "prediction": {
                "prediction_id": prediction.prediction_id,
                "snapshot_date": prediction.snapshot_date.isoformat(),
                "model_version": prediction.model_version,
                "rank": prediction.rank,
                "score": prediction.score,
                "score_scale": prediction.score_scale.model_dump(mode="json"),
            },
            "asset_decision": decision.model_dump(mode="json"),
            "event_evidence_refs": sorted(event_evidence_refs),
            "policy_version": policy_version,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode()).hexdigest()
