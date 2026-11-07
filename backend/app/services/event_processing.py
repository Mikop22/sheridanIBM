from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from datetime import UTC, datetime

from app.domain.contracts import (
    EventProcessingOutcome,
    EventProcessingStatus,
    Prediction,
    RecommendationStatus,
    RemediationRecommendation,
    SecurityEvent,
)
from app.domain.errors import EventAlreadyExistsError, PredictionNotFoundError
from app.event_repository import SecurityEventRepository
from app.repositories import PredictionRepository


@dataclass(frozen=True)
class RiskThreshold:
    value: float | None
    scale_minimum: float | None
    scale_maximum: float | None
    higher_is_riskier: bool | None


class SecurityEventProcessor:
    def __init__(
        self,
        predictions: PredictionRepository,
        events: SecurityEventRepository,
        threshold: RiskThreshold,
    ) -> None:
        self._predictions = predictions
        self._events = events
        self._threshold = threshold

    def process(self, event: SecurityEvent) -> EventProcessingOutcome:
        fingerprint = self._fingerprint(event)
        existing = self._events.find_event(event.event_id)
        if existing is not None:
            if existing.fingerprint != fingerprint:
                raise EventAlreadyExistsError(event.event_id)
            return existing.outcome

        try:
            prediction = self._predictions.get(event.prediction_id)
        except PredictionNotFoundError:
            return self._record(
                event,
                fingerprint,
                EventProcessingStatus.INSUFFICIENT_INFORMATION,
                "prediction_not_found",
                "The referenced prediction is not available for deterministic evaluation.",
            )

        vulnerability_ids = {
            prediction.vulnerability.vulnerability_id,
            *prediction.vulnerability.aliases,
        }
        if event.vulnerability_id not in vulnerability_ids:
            return self._record(
                event,
                fingerprint,
                EventProcessingStatus.INSUFFICIENT_INFORMATION,
                "vulnerability_not_matched",
                "The event vulnerability identifier does not match the referenced prediction.",
            )

        asset = next(
            (item for item in prediction.affected_assets if item.asset_id == event.asset_id), None
        )
        if asset is None:
            return self._record(
                event,
                fingerprint,
                EventProcessingStatus.INSUFFICIENT_INFORMATION,
                "asset_not_matched",
                "The event asset is not an affected asset in the referenced prediction.",
                matched_vulnerability_id=prediction.vulnerability.vulnerability_id,
            )

        available_evidence = {item.evidence_id for item in prediction.evidence}
        unsupported = sorted(set(event.evidence_refs) - available_evidence)
        if unsupported:
            return self._record(
                event,
                fingerprint,
                EventProcessingStatus.INSUFFICIENT_INFORMATION,
                "unsupported_evidence",
                "The event contains evidence references not supplied by the prediction.",
                matched_vulnerability_id=prediction.vulnerability.vulnerability_id,
                matched_asset_id=asset.asset_id,
            )

        threshold_error = self._threshold_error(prediction)
        if threshold_error is not None:
            return self._record(
                event,
                fingerprint,
                EventProcessingStatus.INSUFFICIENT_INFORMATION,
                "incompatible_score_semantics",
                threshold_error,
                matched_vulnerability_id=prediction.vulnerability.vulnerability_id,
                matched_asset_id=asset.asset_id,
            )

        if not self._meets_threshold(prediction):
            return self._record(
                event,
                fingerprint,
                EventProcessingStatus.NO_ACTION,
                "below_configured_threshold",
                "The existing prediction score does not meet the configured alert threshold.",
                matched_vulnerability_id=prediction.vulnerability.vulnerability_id,
                matched_asset_id=asset.asset_id,
            )

        recommendation = self._recommendation(event, prediction, asset.evidence_refs)
        return self._record(
            event,
            fingerprint,
            EventProcessingStatus.RECOMMENDATION_CREATED,
            "configured_threshold_met",
            recommendation.trigger_reason,
            matched_vulnerability_id=prediction.vulnerability.vulnerability_id,
            matched_asset_id=asset.asset_id,
            recommendation=recommendation,
        )

    def _threshold_error(self, prediction: Prediction) -> str | None:
        configured = self._threshold
        values = (
            configured.value,
            configured.scale_minimum,
            configured.scale_maximum,
            configured.higher_is_riskier,
        )
        if any(value is None for value in values):
            return "A complete scale-bound alert threshold has not been configured."
        scale = prediction.score_scale
        if not (
            math.isclose(configured.scale_minimum, scale.minimum)
            and math.isclose(configured.scale_maximum, scale.maximum)
            and configured.higher_is_riskier is scale.higher_is_riskier
        ):
            return "The configured alert threshold semantics do not match the prediction scale."
        if not scale.minimum <= configured.value <= scale.maximum:
            return "The configured alert threshold is outside the prediction score scale."
        return None

    def _meets_threshold(self, prediction: Prediction) -> bool:
        threshold = self._threshold.value
        assert threshold is not None
        if prediction.score_scale.higher_is_riskier:
            return prediction.score >= threshold
        return prediction.score <= threshold

    def _recommendation(
        self, event: SecurityEvent, prediction: Prediction, asset_evidence_refs: list[str]
    ) -> RemediationRecommendation:
        evidence_refs = list(dict.fromkeys([*event.evidence_refs, *asset_evidence_refs]))
        threshold = self._threshold.value
        direction = "at or above" if prediction.score_scale.higher_is_riskier else "at or below"
        trigger_reason = (
            f"The existing score {prediction.score!r} is {direction} the configured threshold "
            f"{threshold!r} on the matching declared scale."
        )
        digest = hashlib.sha256(
            f"{event.event_id}\0{prediction.prediction_id}\0{event.asset_id}".encode()
        ).hexdigest()[:20]
        return RemediationRecommendation(
            recommendation_id=f"rec-{digest}",
            event_id=event.event_id,
            prediction_id=prediction.prediction_id,
            vulnerability_id=prediction.vulnerability.vulnerability_id,
            asset_id=event.asset_id,
            risk_score=prediction.score,
            score_scale=prediction.score_scale,
            trigger_reason=trigger_reason,
            evidence_refs=evidence_refs,
            recommended_next_step=(
                "Review the supplied evidence and validate the affected asset before authorizing "
                "any remediation."
            ),
            approval_required=True,
            workflow_status=RecommendationStatus.PENDING_APPROVAL,
            created_at=datetime.now(UTC),
        )

    def _record(
        self,
        event: SecurityEvent,
        fingerprint: str,
        status: EventProcessingStatus,
        reason_code: str,
        reason: str,
        *,
        matched_vulnerability_id: str | None = None,
        matched_asset_id: str | None = None,
        recommendation: RemediationRecommendation | None = None,
    ) -> EventProcessingOutcome:
        outcome = EventProcessingOutcome(
            event_id=event.event_id,
            prediction_id=event.prediction_id,
            processing_status=status,
            reason_code=reason_code,
            reason=reason,
            matched_vulnerability_id=matched_vulnerability_id,
            matched_asset_id=matched_asset_id,
            recommendation_id=(
                recommendation.recommendation_id if recommendation is not None else None
            ),
            processed_at=datetime.now(UTC),
        )
        return self._events.record_event(fingerprint, outcome, recommendation)

    @staticmethod
    def _fingerprint(event: SecurityEvent) -> str:
        payload = json.dumps(event.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()
