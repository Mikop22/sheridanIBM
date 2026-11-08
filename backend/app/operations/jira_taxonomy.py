"""Demo Jira taxonomy: Epics by CVE, typed children by remediation route."""

from __future__ import annotations

from dataclasses import dataclass

from app.operations.inventory import DemoAsset


ROUTE_ISSUE_TYPE: dict[str, str] = {
    "appliance": "Bug",
    "dependency_upgrade": "Task",
    "code_patch": "Story",
}

ROUTE_LABEL: dict[str, str] = {
    "appliance": "appliance-firmware",
    "dependency_upgrade": "dependency-upgrade",
    "code_patch": "code-patch",
}


@dataclass(frozen=True)
class JiraEpicSpec:
    cve_id: str
    summary: str
    body: str
    labels: tuple[str, ...]


@dataclass(frozen=True)
class JiraChildSpec:
    issue_type: str
    priority: str
    labels: tuple[str, ...]
    summary: str


def cve_label(cve_id: str) -> str:
    return cve_id.lower()


def epic_for_cve(cve_id: str, description: str | None) -> JiraEpicSpec:
    titles = {
        "CVE-2026-8037": "Progress LoadMaster unauthenticated RCE",
        "CVE-2026-22739": "Spring Cloud Config path traversal",
        "CVE-2026-2699": "ShareFile Storage Zones Controller RCE",
    }
    blurb = description or "SignalZero-ranked vulnerability under active remediation."
    title = titles.get(cve_id, "SignalZero prioritized vulnerability")
    return JiraEpicSpec(
        cve_id=cve_id,
        summary=f"{cve_id} · {title}",
        body="\n".join(
            [
                "## Campaign",
                f"Epic for all SignalZero remediation work related to {cve_id}.",
                "",
                "## Vulnerability Summary",
                blurb,
                "",
                "## Organization",
                "- Child Bugs: appliance / incident-style remediations",
                "- Child Tasks: dependency upgrades",
                "- Child Stories: first-party code patches",
            ]
        ),
        labels=("signalzero", "epic", cve_label(cve_id)),
    )


def child_spec(
    asset: DemoAsset,
    *,
    cve_id: str,
    summary: str,
    urgent: bool,
) -> JiraChildSpec:
    issue_type = ROUTE_ISSUE_TYPE.get(asset.route, "Task")
    route_label = ROUTE_LABEL.get(asset.route, asset.route.replace("_", "-"))
    labels = [
        "signalzero",
        cve_label(cve_id),
        route_label,
        f"team-{asset.team}",
        f"asset-{asset.asset_id}",
    ]
    if urgent:
        labels.append("cisa-kev")
    if asset.criticality == "critical" or urgent:
        priority = "Highest" if urgent else "High"
    elif asset.criticality == "high":
        priority = "High"
    else:
        priority = "Medium"
    return JiraChildSpec(
        issue_type=issue_type,
        priority=priority,
        labels=tuple(labels),
        summary=summary,
    )
