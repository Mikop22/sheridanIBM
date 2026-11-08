from __future__ import annotations

from app.domain.assets import AssetMatchStatus
from app.services.asset_correlation import AssetCorrelationService, load_asset_inventory


def test_synthetic_inventory_is_small_labeled_and_internally_consistent() -> None:
    inventory = load_asset_inventory()

    assert len(inventory.assets) == 7
    assert inventory.synthetic is True
    assert inventory.provenance == "synthetic_demo"
    assert inventory.verification_meaning.endswith("not_external_product_intelligence")
    assert all(mapping.verified_for_demo for mapping in inventory.mappings)


def test_explicit_mapping_states_and_absent_mapping_remains_unknown() -> None:
    service = AssetCorrelationService(load_asset_inventory())

    assert (
        service.correlate("CVE-2026-2699", "demo-asset-identity").match_status
        is AssetMatchStatus.CONFIRMED_AFFECTED
    )
    assert (
        service.correlate("CVE-2026-2699", "demo-asset-analytics").match_status
        is AssetMatchStatus.POTENTIALLY_AFFECTED
    )
    assert (
        service.correlate("CVE-2026-1603", "demo-asset-admin").match_status
        is AssetMatchStatus.CONFIRMED_UNAFFECTED
    )
    absent = service.correlate("CVE-2026-2699", "demo-asset-catalog")
    assert absent.match_status is AssetMatchStatus.UNKNOWN
    assert absent.mapping is None


def test_unknown_asset_is_not_silently_created() -> None:
    service = AssetCorrelationService(load_asset_inventory())

    assert service.correlate("CVE-2026-2699", "not-in-inventory") is None


def test_multiple_asset_correlations_are_preserved() -> None:
    service = AssetCorrelationService(load_asset_inventory())

    correlations = service.correlations_for("cve-2026-2699")

    assert [item.asset.asset_id for item in correlations] == [
        "demo-asset-analytics",
        "demo-asset-identity",
    ]
