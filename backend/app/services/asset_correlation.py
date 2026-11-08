from __future__ import annotations

import json
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

from app.domain.assets import (
    AssetInventory,
    AssetMatchStatus,
    CompanyAsset,
    SyntheticScenarioMapping,
)


@dataclass(frozen=True)
class AssetCorrelation:
    asset: CompanyAsset
    match_status: AssetMatchStatus
    mapping: SyntheticScenarioMapping | None

    @property
    def evidence_refs(self) -> list[str]:
        if self.mapping is None:
            return [f"inventory:asset:{self.asset.asset_id}"]
        return list(self.mapping.evidence_refs)


def load_asset_inventory(path: Path | None = None) -> AssetInventory:
    if path is None:
        content = files("app.data").joinpath("asset-inventory.synthetic.json").read_text(
            encoding="utf-8"
        )
    else:
        content = path.read_text(encoding="utf-8")
    return AssetInventory.model_validate(json.loads(content))


class AssetCorrelationService:
    def __init__(self, inventory: AssetInventory) -> None:
        self.inventory = inventory
        self._assets = {asset.asset_id: asset for asset in inventory.assets}
        self._mappings = {
            (mapping.vulnerability_id.upper(), mapping.asset_id): mapping
            for mapping in inventory.mappings
        }

    def get_asset(self, asset_id: str) -> CompanyAsset | None:
        return self._assets.get(asset_id)

    def correlate(self, vulnerability_id: str, asset_id: str) -> AssetCorrelation | None:
        asset = self.get_asset(asset_id)
        if asset is None:
            return None
        mapping = self._mappings.get((vulnerability_id.upper(), asset_id))
        return AssetCorrelation(
            asset=asset,
            match_status=(mapping.match_status if mapping else AssetMatchStatus.UNKNOWN),
            mapping=mapping,
        )

    def correlations_for(self, vulnerability_id: str) -> list[AssetCorrelation]:
        normalized = vulnerability_id.upper()
        correlations = [
            AssetCorrelation(
                asset=self._assets[mapping.asset_id],
                match_status=mapping.match_status,
                mapping=mapping,
            )
            for mapping in self.inventory.mappings
            if mapping.vulnerability_id.upper() == normalized
        ]
        return sorted(correlations, key=lambda item: item.asset.asset_id)
