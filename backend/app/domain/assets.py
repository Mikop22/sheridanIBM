from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import Field, StrictBool, model_validator

from app.domain.contracts import ContractModel, NonEmptyString


class BusinessCriticality(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class ExposureStatus(StrEnum):
    INTERNET_FACING = "internet_facing"
    INTERNAL = "internal"
    UNKNOWN = "unknown"


class AssetMatchStatus(StrEnum):
    CONFIRMED_AFFECTED = "confirmed_affected"
    POTENTIALLY_AFFECTED = "potentially_affected"
    UNKNOWN = "unknown"
    CONFIRMED_UNAFFECTED = "confirmed_unaffected"


class InventoryEvidence(ContractModel):
    evidence_id: NonEmptyString
    source: Literal["synthetic_scenario_assertion"] = "synthetic_scenario_assertion"
    observed_at: datetime
    description: NonEmptyString


class RemediationPath(ContractModel):
    kind: NonEmptyString
    verified_for_demo: StrictBool
    repository_identifier: NonEmptyString | None = None
    component_package: NonEmptyString | None = None
    evidence_refs: list[NonEmptyString] = Field(min_length=1)


class CompanyAsset(ContractModel):
    asset_id: NonEmptyString
    application_name: NonEmptyString
    service_name: NonEmptyString
    repository_identifier: NonEmptyString | None = None
    owner_team: NonEmptyString
    component_package: NonEmptyString | None = None
    installed_version: NonEmptyString | None = None
    business_criticality: BusinessCriticality
    exposure_status: ExposureStatus
    environment: Literal["production", "development", "unknown"]


class SyntheticScenarioMapping(ContractModel):
    vulnerability_id: NonEmptyString
    asset_id: NonEmptyString
    match_status: AssetMatchStatus
    assertion: NonEmptyString
    verified_for_demo: Literal[True] = True
    evidence_refs: list[NonEmptyString] = Field(min_length=1)
    exploitation_evidence_refs: list[NonEmptyString] = Field(default_factory=list)
    remediation_path: RemediationPath | None = None


class AssetInventory(ContractModel):
    inventory_id: NonEmptyString
    organization_label: NonEmptyString
    provenance: Literal["synthetic_demo"] = "synthetic_demo"
    synthetic: Literal[True] = True
    verification_meaning: Literal[
        "internally_consistent_synthetic_scenario_not_external_product_intelligence"
    ]
    assets: list[CompanyAsset] = Field(min_length=5, max_length=10)
    evidence: list[InventoryEvidence] = Field(min_length=1)
    mappings: list[SyntheticScenarioMapping] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_inventory(self) -> AssetInventory:
        asset_ids = [asset.asset_id for asset in self.assets]
        if len(asset_ids) != len(set(asset_ids)):
            raise ValueError("asset_id values must be unique")
        evidence_ids = [item.evidence_id for item in self.evidence]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("inventory evidence_id values must be unique")
        mapping_keys = [
            (mapping.vulnerability_id.upper(), mapping.asset_id) for mapping in self.mappings
        ]
        if len(mapping_keys) != len(set(mapping_keys)):
            raise ValueError("vulnerability and asset mappings must be unique")

        known_assets = set(asset_ids)
        known_evidence = set(evidence_ids)
        for mapping in self.mappings:
            if mapping.asset_id not in known_assets:
                raise ValueError(f"mapping references unknown asset {mapping.asset_id!r}")
            refs = [*mapping.evidence_refs, *mapping.exploitation_evidence_refs]
            if mapping.remediation_path is not None:
                refs.extend(mapping.remediation_path.evidence_refs)
            missing = sorted(set(refs) - known_evidence)
            if missing:
                raise ValueError(f"mapping contains unknown evidence_refs: {missing}")
        return self
