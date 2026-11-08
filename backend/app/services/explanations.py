from __future__ import annotations

import hashlib
import json
from typing import Protocol

from app.domain.contracts import (
    Explanation,
    ExplanationContext,
    ExplanationEvidenceMetadata,
    ExplanationProvider,
    GenerationStatus,
    GroundedStatement,
    Prediction,
    SignalDirection,
)
from app.services.providers import ExternalExplanationClient, ProviderFailure, ProviderOutput


class ExplanationService(Protocol):
    def explain(self, prediction: Prediction) -> Explanation: ...


class LocalExplanationService:
    """Builds deterministic explanations exclusively from submitted fields."""

    def explain(self, prediction: Prediction) -> Explanation:
        facts = self._facts(prediction)
        interpretations = self._interpretations(prediction)
        explanation = Explanation(
            prediction_id=prediction.prediction_id,
            provider=ExplanationProvider.LOCAL,
            generation_status=GenerationStatus.COMPLETE,
            context=self._context(prediction),
            observed_facts=facts,
            interpretations=interpretations,
            limitations=self._limitations(prediction),
            trace_id=self._trace_id(prediction),
            provider_metadata={
                "engine": "deterministic-template-v1",
                "requested_provider": ExplanationProvider.LOCAL.value,
                "actual_provider": ExplanationProvider.LOCAL.value,
                "requested_generation_status": GenerationStatus.COMPLETE.value,
                "fallback_status": "not_used",
            },
        )
        explanation.validate_source_refs(prediction)
        return explanation

    @staticmethod
    def _context(prediction: Prediction) -> ExplanationContext:
        direction = "higher" if prediction.score_scale.higher_is_riskier else "lower"
        missing: list[str] = []
        if not prediction.evidence:
            missing.append("supporting evidence")
        if not prediction.signals:
            missing.append("explanatory model signals")
        if not prediction.affected_assets:
            missing.append("affected asset associations")
        return ExplanationContext(
            prediction_snapshot=prediction.snapshot_date,
            model_version=prediction.model_version,
            model_score=prediction.score,
            score_scale=prediction.score_scale,
            score_meaning=(
                f"This is the submitted model score; {direction} values are declared riskier. "
                "It is not treated as an exploitation probability."
            ),
            evidence=[
                ExplanationEvidenceMetadata(
                    evidence_id=item.evidence_id,
                    source=item.source,
                    observed_at=item.observed_at,
                )
                for item in prediction.evidence
            ],
            missing_information=missing,
        )

    @staticmethod
    def _facts(prediction: Prediction) -> list[GroundedStatement]:
        scale = prediction.score_scale
        risk_direction = "higher" if scale.higher_is_riskier else "lower"
        facts = [
            GroundedStatement(
                text=(
                    f"The submitted model assigned score {prediction.score!r} on the declared "
                    f"scale {scale.minimum!r} to {scale.maximum!r}; {risk_direction} values "
                    "represent greater risk."
                ),
                source_refs=["prediction:score", "prediction:score_scale"],
            ),
            GroundedStatement(
                text=f"The submitted prediction used model version {prediction.model_version!r}.",
                source_refs=["prediction:model_version"],
            ),
        ]
        if prediction.rank is not None:
            facts.append(
                GroundedStatement(
                    text=f"The submitted risk rank is {prediction.rank}.",
                    source_refs=["prediction:rank"],
                )
            )
        for signal in prediction.signals:
            evidence_refs = [f"evidence:{ref}" for ref in signal.evidence_refs]
            contribution = (
                " with no supplied contribution value"
                if signal.contribution is None
                else f" with supplied contribution {signal.contribution!r}"
            )
            facts.append(
                GroundedStatement(
                    text=(
                        f"Signal {signal.name!r} has submitted value {signal.value!r}, direction "
                        f"{signal.direction.value!r}{contribution}."
                    ),
                    source_refs=[f"signal:{signal.name}", *evidence_refs],
                )
            )
        for asset in prediction.affected_assets:
            evidence_refs = [f"evidence:{ref}" for ref in asset.evidence_refs]
            facts.append(
                GroundedStatement(
                    text=(
                        f"Asset {asset.asset_id!r} is associated with this prediction because "
                        f"{asset.match_reason}."
                    ),
                    source_refs=[f"asset:{asset.asset_id}", *evidence_refs],
                )
            )
        return facts

    @staticmethod
    def _interpretations(prediction: Prediction) -> list[GroundedStatement]:
        interpretations: list[GroundedStatement] = []
        increasing = [
            item for item in prediction.signals if item.direction is SignalDirection.INCREASES_RISK
        ]
        decreasing = [
            item for item in prediction.signals if item.direction is SignalDirection.DECREASES_RISK
        ]
        if increasing or decreasing:
            refs = [f"signal:{item.name}" for item in [*increasing, *decreasing]]
            interpretations.append(
                GroundedStatement(
                    text=(
                        f"The supplied explanatory signals identify {len(increasing)} factor(s) "
                        f"that increase risk and {len(decreasing)} factor(s) that decrease risk; "
                        "this service did not recalculate the model score."
                    ),
                    source_refs=refs,
                )
            )
        if prediction.affected_assets:
            interpretations.append(
                GroundedStatement(
                    text=(
                        f"The prediction associates the vulnerability with "
                        f"{len(prediction.affected_assets)} supplied asset(s); this association "
                        "does not independently establish exploitability."
                    ),
                    source_refs=[f"asset:{asset.asset_id}" for asset in prediction.affected_assets],
                )
            )
        return interpretations

    @staticmethod
    def _limitations(prediction: Prediction) -> list[str]:
        limitations = [
            "This explanation is limited to the submitted prediction and evidence.",
            "The explanation does not change or independently validate the model score or rank.",
            "No vulnerability details or remediation claims were generated.",
        ]
        if not prediction.evidence:
            limitations.append("No supporting evidence records were supplied.")
        if not prediction.signals:
            limitations.append("No explanatory model signals were supplied.")
        return limitations

    @staticmethod
    def _trace_id(prediction: Prediction) -> str:
        payload = json.dumps(
            prediction.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return f"local-{hashlib.sha256(payload).hexdigest()[:20]}"


class ExternalExplanationService:
    """Uses validated model output, with the local engine as a safe fallback."""

    def __init__(
        self,
        requested_provider: ExplanationProvider,
        client: ExternalExplanationClient,
        local_service: LocalExplanationService | None = None,
    ) -> None:
        if requested_provider is ExplanationProvider.LOCAL:
            raise ValueError("external explanation service requires an external provider")
        self._requested_provider = requested_provider
        self._client = client
        self._local = local_service or LocalExplanationService()

    def explain(self, prediction: Prediction) -> Explanation:
        baseline = self._local.explain(prediction)
        try:
            result = self._client.generate(prediction)
        except ProviderFailure as exc:
            return baseline.model_copy(
                update={
                    "provider_metadata": {
                        "engine": "deterministic-template-v1",
                        "requested_provider": self._requested_provider.value,
                        "actual_provider": ExplanationProvider.LOCAL.value,
                        "requested_generation_status": exc.status,
                        "fallback_status": "used",
                    }
                }
            )

        provider_metadata = {
            "requested_provider": self._requested_provider.value,
            "actual_provider": self._requested_provider.value,
            "model_id": result.model_id,
            "requested_generation_status": GenerationStatus.COMPLETE.value,
            "fallback_status": "not_used",
        }
        if result.requested_model_id is not None:
            provider_metadata["requested_model_id"] = result.requested_model_id
        if result.inference_provider is not None:
            provider_metadata["inference_provider"] = result.inference_provider

        explanation = Explanation(
            prediction_id=prediction.prediction_id,
            provider=self._requested_provider,
            generation_status=GenerationStatus.COMPLETE,
            context=baseline.context,
            observed_facts=baseline.observed_facts,
            interpretations=self._safe_interpretations(result.output),
            limitations=[
                *baseline.limitations,
                (
                    "External model-authored free text is not exposed; only its validated "
                    "selection of submitted source references is reported."
                ),
            ],
            trace_id=self._trace_id(prediction, result.output.model_dump(mode="json")),
            provider_metadata=provider_metadata,
        )
        explanation.validate_source_refs(prediction)
        return explanation

    @staticmethod
    def _safe_interpretations(output: ProviderOutput) -> list[GroundedStatement]:
        return [
            GroundedStatement(
                text=(
                    "The external provider identified these submitted source references as "
                    f"relevant: {', '.join(statement.source_refs)}. No additional "
                    "model-authored factual claim was accepted."
                ),
                source_refs=statement.source_refs,
            )
            for statement in output.interpretations
        ]

    def _trace_id(self, prediction: Prediction, output: dict) -> str:
        payload = json.dumps(
            {"prediction": prediction.model_dump(mode="json"), "output": output},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return f"{self._requested_provider.value}-{hashlib.sha256(payload).hexdigest()[:20]}"
