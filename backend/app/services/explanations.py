from __future__ import annotations

import hashlib
import json
from typing import Protocol

from app.domain.contracts import (
    Explanation,
    ExplanationProvider,
    GenerationStatus,
    GroundedStatement,
    Prediction,
    SignalDirection,
)


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
            observed_facts=facts,
            interpretations=interpretations,
            limitations=self._limitations(prediction),
            trace_id=self._trace_id(prediction),
            provider_metadata={"engine": "deterministic-template-v1"},
        )
        explanation.validate_source_refs(prediction)
        return explanation

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
