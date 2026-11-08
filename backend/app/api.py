from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status

from app.domain.contracts import (
    ErrorResponse,
    EventProcessingOutcome,
    Explanation,
    HealthStatus,
    OperationalDecision,
    Prediction,
    RecommendationDecision,
    RemediationRecommendation,
    SecurityEvent,
)
from app.domain.errors import (
    FrontendVulnerabilityNotFoundError,
)
from app.domain.frontend_contracts import (
    FrontendAffectedAsset,
    FrontendAlerts,
    FrontendArtifactProvenance,
    FrontendAsset,
    FrontendAssetMatch,
    FrontendAssets,
    FrontendDecisionActivity,
    FrontendDecisionReason,
    FrontendEvidenceIndicator,
    FrontendOverview,
    FrontendPersistentDecision,
    FrontendVulnerability,
    FrontendVulnerabilityDetail,
    FrontendVulnerabilityList,
)
from app.event_repository import SecurityEventRepository
from app.repositories import PredictionRepository
from app.services.asset_correlation import AssetCorrelationService
from app.services.escalation import EscalationEvaluator
from app.services.event_processing import SecurityEventProcessor
from app.services.explanations import ExplanationService, LocalExplanationService
from app.services.prediction_artifacts import (
    SCORE_INTERPRETATION,
    PredictionArtifact,
    PredictionArtifactRecord,
)

router = APIRouter()


def get_repository(request: Request) -> PredictionRepository:
    return request.app.state.prediction_repository


def get_explanation_service(request: Request) -> ExplanationService:
    return request.app.state.explanation_service


def get_event_processor(request: Request) -> SecurityEventProcessor:
    return request.app.state.event_processor


def get_event_repository(request: Request) -> SecurityEventRepository:
    return request.app.state.event_repository


def get_prediction_artifact(request: Request) -> PredictionArtifact:
    return request.app.state.prediction_artifact


def get_asset_correlations(request: Request) -> AssetCorrelationService:
    return request.app.state.asset_correlations


def get_escalation_evaluator(request: Request) -> EscalationEvaluator:
    return request.app.state.escalation_evaluator


RepositoryDependency = Annotated[PredictionRepository, Depends(get_repository)]
ExplanationDependency = Annotated[ExplanationService, Depends(get_explanation_service)]
EventProcessorDependency = Annotated[SecurityEventProcessor, Depends(get_event_processor)]
EventRepositoryDependency = Annotated[SecurityEventRepository, Depends(get_event_repository)]
ArtifactDependency = Annotated[PredictionArtifact, Depends(get_prediction_artifact)]
CorrelationDependency = Annotated[AssetCorrelationService, Depends(get_asset_correlations)]
EscalationDependency = Annotated[EscalationEvaluator, Depends(get_escalation_evaluator)]


@router.get(
    "/health",
    response_model=HealthStatus,
    responses={503: {"model": HealthStatus}},
    tags=["operations"],
)
def health(request: Request, response: Response) -> HealthStatus:
    provider = request.app.state.settings.explanation_provider
    provider_ready = request.app.state.settings.provider_ready()
    if not provider_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return HealthStatus(
        status="ready" if provider_ready else "not_ready",
        explanation_provider=provider.value,
        provider_ready=provider_ready,
    )


@router.post(
    "/v1/predictions",
    response_model=Prediction,
    status_code=status.HTTP_201_CREATED,
    responses={
        409: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
    },
    tags=["predictions"],
)
def create_prediction(prediction: Prediction, repository: RepositoryDependency) -> Prediction:
    return repository.create(prediction)


@router.get(
    "/v1/predictions/{prediction_id}",
    response_model=Prediction,
    responses={404: {"model": ErrorResponse}},
    tags=["predictions"],
)
def get_prediction(prediction_id: str, repository: RepositoryDependency) -> Prediction:
    return repository.get(prediction_id)


@router.post(
    "/v1/predictions/{prediction_id}/explanation",
    response_model=Explanation,
    responses={
        404: {"model": ErrorResponse},
    },
    tags=["explanations"],
)
def explain_prediction(
    prediction_id: str,
    repository: RepositoryDependency,
    explanation_service: ExplanationDependency,
) -> Explanation:
    return explanation_service.explain(repository.get(prediction_id))


@router.post(
    "/v1/security-events",
    response_model=EventProcessingOutcome,
    responses={
        409: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
    },
    tags=["security-events"],
)
def submit_security_event(
    event: SecurityEvent, event_processor: EventProcessorDependency, dry_run: bool = False
) -> EventProcessingOutcome:
    return event_processor.process(event, dry_run=dry_run)


@router.get(
    "/v1/security-events/{event_id}",
    response_model=EventProcessingOutcome,
    responses={404: {"model": ErrorResponse}, 503: {"model": ErrorResponse}},
    tags=["security-events"],
)
def get_security_event(
    event_id: str, event_repository: EventRepositoryDependency
) -> EventProcessingOutcome:
    return event_repository.get_event(event_id)


@router.get(
    "/v1/predictions/{prediction_id}/recommendations",
    response_model=list[RemediationRecommendation],
    responses={503: {"model": ErrorResponse}},
    tags=["recommendations"],
)
def get_recommendations(
    prediction_id: str,
    event_repository: EventRepositoryDependency,
) -> list[RemediationRecommendation]:
    return event_repository.list_recommendations(prediction_id)


@router.post(
    "/v1/recommendations/{recommendation_id}/decision",
    response_model=RemediationRecommendation,
    responses={
        404: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
    },
    tags=["recommendations"],
)
def decide_recommendation(
    recommendation_id: str,
    decision: RecommendationDecision,
    event_repository: EventRepositoryDependency,
) -> RemediationRecommendation:
    return event_repository.decide(recommendation_id, decision)


def _frontend_vulnerability(
    record: PredictionArtifactRecord,
    artifact: PredictionArtifact,
    correlations: AssetCorrelationService,
    evaluator: EscalationEvaluator,
) -> FrontendVulnerability:
    prediction = record.prediction
    explanation = LocalExplanationService().explain(prediction)
    evidence_indicators = [
        FrontendEvidenceIndicator(
            key=name,
            label=name,
            value=value,
            status="present",
            observedAt=prediction.evidence[0].observed_at,
            source=prediction.evidence[0].source,
            explanation="Diagnostic model output; no causal contribution was supplied.",
        )
        for name, value in record.component_scores.items()
    ]
    evidence_indicators.extend(
        [
            FrontendEvidenceIndicator(
                key="cvss",
                label="CVSS",
                value=None,
                status="unknown",
                observedAt=None,
                source=None,
                explanation="CVSS was not included in the prediction artifact.",
            ),
            FrontendEvidenceIndicator(
                key="epss",
                label="EPSS",
                value=None,
                status="unknown",
                observedAt=None,
                source=None,
                explanation="EPSS was not included in the prediction artifact.",
            ),
        ]
    )
    asset_decisions = [
        evaluator.evaluate(prediction, correlation)
        for correlation in correlations.correlations_for(
            prediction.vulnerability.vulnerability_id
        )
    ]
    decision_order = {
        OperationalDecision.MONITOR: 0,
        OperationalDecision.INVESTIGATE: 1,
        OperationalDecision.ACTION_REQUIRED: 2,
        OperationalDecision.URGENT: 3,
    }
    aggregate = max(
        asset_decisions,
        key=lambda item: (decision_order[item.operational_decision], item.asset_id),
        default=None,
    )
    if aggregate is None:
        operational_decision = evaluator.decision_for_unmapped_finding(prediction)
        in_band = operational_decision is OperationalDecision.INVESTIGATE
        decision_reasons = [
            FrontendDecisionReason(
                code="NO_EXPLICIT_ASSET_MAPPING",
                message=(
                    "No synthetic scenario mapping exists; asset relevance remains unknown and is "
                    "not evidence of safety."
                ),
                sourceRefs=["asset:mapping:missing"],
            ),
            FrontendDecisionReason(
                code=(
                    "MODEL_RANK_WITHIN_INVESTIGATION_BAND"
                    if in_band
                    else "MODEL_RANK_OUTSIDE_INVESTIGATION_BAND"
                ),
                message=(
                    "The supplied model rank places this unknown finding in investigation."
                    if in_band
                    else "The supplied model rank leaves this unknown finding in monitoring."
                ),
                sourceRefs=["prediction:rank", f"policy:{evaluator.policy.version}"],
            ),
        ]
        affected_asset = None
        match_status = "unknown"
        eligibility = "NEEDS_INVESTIGATION"
        agent_eligible = False
        suggested_action = (
            "Validate whether the finding applies to any inventoried asset."
            if in_band
            else "Monitor ranking and asset evidence for material changes."
        )
    else:
        operational_decision = aggregate.operational_decision
        decision_reasons = [
            FrontendDecisionReason(
                code=reason.code, message=reason.message, sourceRefs=reason.source_refs
            )
            for reason in aggregate.reasons
        ]
        asset = correlations.get_asset(aggregate.asset_id)
        assert asset is not None
        affected_asset = FrontendAffectedAsset(
            id=asset.asset_id,
            name=asset.application_name,
            service=asset.service_name,
            owner=asset.owner_team,
        )
        match_status = aggregate.match_status
        eligibility = aggregate.eligibility.outcome.value
        agent_eligible = aggregate.eligibility.agent_eligible
        suggested_action = aggregate.proposed_next_action
    state = {
        OperationalDecision.MONITOR: "monitoring",
        OperationalDecision.INVESTIGATE: "investigating",
        OperationalDecision.ACTION_REQUIRED: "action_pending",
        OperationalDecision.URGENT: "action_pending",
    }[operational_decision]
    missing_information = [
        "vulnerability description",
        "CVSS score",
        "EPSS score",
        "feature contribution values",
    ]
    if aggregate is None:
        missing_information.append("affected asset associations")
    return FrontendVulnerability(
        cveId=prediction.vulnerability.vulnerability_id,
        snapshotMonth=record.snapshot_month,
        modelRank=prediction.rank,
        rankingScore=prediction.score,
        evidenceIndicators=evidence_indicators,
        affectedAsset=affected_asset,
        modelVersion=prediction.model_version,
        scoreScale=prediction.score_scale,
        scoreInterpretation=SCORE_INTERPRETATION,
        componentScores=record.component_scores,
        artifact=FrontendArtifactProvenance(
            artifactId=artifact.artifact_id,
            sourceKind=artifact.source_kind,
            recordCount=len(artifact.records),
        ),
        missingInformation=missing_information,
        assetMatchStatus=match_status,
        investigationState=state,
        operationalDecision=operational_decision.value,
        decisionReasons=decision_reasons,
        assetDecisions=asset_decisions,
        remediationEligibility=eligibility,
        agentEligible=agent_eligible,
        suggestedAction=suggested_action,
        groundedExplanation=explanation,
    )


@router.get("/api/vulnerabilities", response_model=FrontendVulnerabilityList, tags=["frontend"])
def frontend_vulnerabilities(
    artifact: ArtifactDependency,
    correlations: CorrelationDependency,
    evaluator: EscalationDependency,
) -> FrontendVulnerabilityList:
    """Return startup-loaded Member 1 predictions without request-time model execution."""
    return FrontendVulnerabilityList(
        vulnerabilities=[
            _frontend_vulnerability(record, artifact, correlations, evaluator)
            for record in artifact.records
        ]
    )


@router.get("/api/overview", response_model=FrontendOverview, tags=["frontend"])
def frontend_overview() -> FrontendOverview:
    """Return nullable totals instead of inventing dashboard statistics."""
    return FrontendOverview(generatedAt=datetime.now(UTC))


@router.get(
    "/api/vulnerabilities/{vulnerability_id}",
    response_model=FrontendVulnerabilityDetail,
    responses={404: {"model": ErrorResponse}},
    tags=["frontend"],
)
def frontend_vulnerability_detail(
    vulnerability_id: str,
    artifact: ArtifactDependency,
    correlations: CorrelationDependency,
    evaluator: EscalationDependency,
) -> FrontendVulnerabilityDetail:
    record = artifact.find_cve(vulnerability_id)
    if record is None:
        raise FrontendVulnerabilityNotFoundError(vulnerability_id)
    return FrontendVulnerabilityDetail(
        vulnerability=_frontend_vulnerability(record, artifact, correlations, evaluator)
    )


@router.get("/api/assets", response_model=FrontendAssets, tags=["frontend"])
def frontend_assets(correlations: CorrelationDependency) -> FrontendAssets:
    """Return the explicitly labeled synthetic inventory and scenario mappings."""
    inventory = correlations.inventory
    evidence = {item.evidence_id: item.description for item in inventory.evidence}
    status_labels = {
        "confirmed_affected": "Confirmed",
        "potentially_affected": "Possible",
        "unknown": "Unknown",
        "confirmed_unaffected": "Unaffected",
    }
    return FrontendAssets(
        assets=[
            FrontendAsset(
                assetId=asset.asset_id,
                name=asset.application_name,
                product=asset.component_package,
                version=asset.installed_version,
                environment=asset.environment.title(),
                internetExposed=(
                    True
                    if asset.exposure_status.value == "internet_facing"
                    else False if asset.exposure_status.value == "internal" else None
                ),
                businessCriticality=asset.business_criticality.value.title(),
                owner=asset.owner_team,
                repositoryIdentifier=asset.repository_identifier,
                componentPackage=asset.component_package,
            )
            for asset in inventory.assets
        ],
        matches=[
            FrontendAssetMatch(
                cveId=mapping.vulnerability_id,
                assetId=mapping.asset_id,
                matchStatus=status_labels[mapping.match_status.value],
                canonicalMatchStatus=mapping.match_status.value,
                supportingEvidence=[
                    mapping.assertion,
                    *(evidence[ref] for ref in mapping.evidence_refs),
                ],
                provenance=inventory.verification_meaning,
            )
            for mapping in inventory.mappings
        ],
        organizationLabel=inventory.organization_label,
        synthetic=True,
        provenance=inventory.verification_meaning,
    )


@router.get("/api/alerts", response_model=FrontendAlerts, tags=["frontend"])
def frontend_alerts(event_repository: EventRepositoryDependency) -> FrontendAlerts:
    """Expose persistent decisions without claiming an external alert was delivered."""
    return FrontendAlerts(
        decisions=[
            FrontendPersistentDecision(
                recommendationId=item.recommendation_id,
                findingId=item.finding_id,
                cveId=item.vulnerability_id,
                assetId=item.asset_id,
                operationalDecision=item.operational_decision.value,
                workflowStatus=item.workflow_status.value,
                reasonCodes=[reason.code for reason in item.decision_reasons],
                evidenceRefs=item.evidence_refs,
                remediationEligibility=item.eligibility.outcome.value,
                agentEligible=item.eligibility.agent_eligible,
                executionAuthorized=False,
                proposedNextAction=item.recommended_next_step,
                createdAt=item.created_at,
                decidedAt=item.decided_at,
                decidedBy=item.decided_by,
                decisionReason=item.decision_reason,
                activityHistory=[
                    FrontendDecisionActivity(
                        eventId=outcome.event_id,
                        processedAt=outcome.processed_at,
                        reasonCode=outcome.reason_code,
                        reusedRecommendation=outcome.reused_recommendation,
                    )
                    for outcome in event_repository.list_finding_outcomes(item.finding_id)
                ],
            )
            for item in event_repository.list_all_recommendations()
        ]
    )
