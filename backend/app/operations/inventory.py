from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DemoAsset:
    """A synthetic company asset aligned to a published affected range.

    The CVE identifiers, versions, and advisory ids are sourced. The asset
    names, owners, and installed versions are a demo inventory, not a scan of
    a real network.
    """

    asset_id: str
    name: str
    owner: str
    team: str
    criticality: str
    repository: str | None
    product: str
    installed_version: str
    fixed_version: str | None
    advisory_id: str | None
    route: str
    cve_id: str
    source: str
    scripted_dispatch: bool
    note: str


LOADMASTER = DemoAsset(
    asset_id="edge-load-balancer",
    name="Edge load balancer",
    owner="Network",
    team="network",
    criticality="critical",
    repository=None,
    product="Progress LoadMaster",
    installed_version="7.2.60.0",
    fixed_version=None,
    advisory_id=None,
    route="appliance",
    cve_id="CVE-2026-8037",
    source="https://nvd.nist.gov/vuln/detail/CVE-2026-8037",
    scripted_dispatch=True,
    note=(
        "Synthetic inventory. NVD lists LoadMaster builds before 7.2.63.2 as affected, "
        "and the KEV entry date is 2026-08-07. The July snapshot decision must not use that date."
    ),
)

PORTAL = DemoAsset(
    asset_id="customer-portal",
    name="Customer Portal",
    owner="Portal",
    team="portal",
    criticality="high",
    repository="Mikop22/securitydemo",
    product="org.springframework.cloud:spring-cloud-config-server",
    installed_version="4.3.1",
    fixed_version="4.3.2",
    advisory_id="GHSA-3qwq-q9vm-5j42",
    route="dependency_upgrade",
    cve_id="CVE-2026-22739",
    source="https://github.com/advisories/GHSA-3qwq-q9vm-5j42",
    scripted_dispatch=True,
    note=(
        "Synthetic inventory. The advisory lists 4.3.2 and 5.0.2 as patched. "
        "This repository stays on the 4.3 line."
    ),
)

SHAREFILE = DemoAsset(
    asset_id="file-gateway",
    name="File gateway",
    owner="Platform",
    team="platform",
    criticality="critical",
    repository=None,
    product="Progress ShareFile Storage Zones Controller",
    installed_version="5.12.3",
    fixed_version=None,
    advisory_id=None,
    route="appliance",
    cve_id="CVE-2026-2699",
    source="https://nvd.nist.gov/vuln/detail/CVE-2026-2699",
    scripted_dispatch=False,
    note=(
        "Synthetic inventory. Rank 1 stays visible for this scripted run and is not dispatched. "
        "NVD lists 5.x builds before 5.12.4 as affected."
    ),
)

ASSETS = (LOADMASTER, PORTAL, SHAREFILE)
BY_CVE = {asset.cve_id: asset for asset in ASSETS}
KEV_ADDED_ON = "2026-08-07"


def asset_for(cve_id: str) -> DemoAsset | None:
    return BY_CVE.get(cve_id)
