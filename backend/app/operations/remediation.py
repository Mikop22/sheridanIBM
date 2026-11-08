from __future__ import annotations

from app.operations.rankings import format_score

REPOSITORY = "Mikop22/securitydemo"
DEPENDENCY_BRANCH = "signalzero/cve-2026-22739"
CODE_BRANCH = "signalzero/cve-2026-22739-code"

# Backwards-compatible alias used by older call sites.
BRANCH = DEPENDENCY_BRANCH

_PR_SECTIONS = (
    "Use this pull request shape exactly. "
    "Title: `[SignalZero] CVE-2026-22739: {short change} ({route})`. "
    "Body sections in order: `## Proposed change`, `## Verify`, "
    "`## Review notes`, `## Context`. "
    "Optional `## Agent provenance` only when a real Entire checkpoint id exists; omit otherwise. "
    "Put the ranking score and 'not an exploitation probability' only under `## Context`. "
    "Put the checks-do-not-prove caveat once under `## Review notes`, with draft-only and "
    "synthetic-inventory notes. "
    "Do not invent Threat evidence / Code evidence / Agent reasoning sections, "
    "files-inspected lists, or Entire boilerplate without a checkpoint id."
)


def agent_task(*, ranking_score: float, rank: int) -> str:
    return dependency_agent_task(ranking_score=ranking_score, rank=rank)


def dependency_agent_task(*, ranking_score: float, rank: int) -> str:
    score = format_score(ranking_score)
    return (
        "In Mikop22/securitydemo, CVE-2026-22739 affects "
        "org.springframework.cloud:spring-cloud-config-server 4.3.1. "
        "advisory/GHSA-3qwq-q9vm-5j42.md names 4.3.2 as the patched version on the 4.3 line. "
        "Do not upgrade to 5.0.2. "
        "Change only the dependency pin to 4.3.2. "
        "Do not edit the advisory or check_version.py. "
        "check_version.py must exit 0. "
        f"Commit on branch {DEPENDENCY_BRANCH}. "
        "Open a draft pull request. Do not merge. "
        "Title example: "
        "`[SignalZero] CVE-2026-22739: bump spring-cloud-config-server 4.3.1→4.3.2 (dependency)`. "
        "Proposed change: bump the pin in pom.xml only and stay on the 4.3 line. "
        "Verify with `python3 check_version.py` (expect exit 0). "
        "Review notes must state that a passing check does not prove the path traversal is closed. "
        f"Context: ranking score {score}, rank {rank} of 72670, snapshot 2026-03; "
        "label it as a ranking score, not an exploitation probability; "
        "advisory GHSA-3qwq-q9vm-5j42; asset Customer Portal (customer-portal); "
        "inventory synthetic. "
        f"{_PR_SECTIONS}"
    )


def code_agent_task(*, ranking_score: float, rank: int) -> str:
    score = format_score(ranking_score)
    return (
        "In Mikop22/securitydemo, CVE-2026-22739 / GHSA-3qwq-q9vm-5j42 is the ranking signal. "
        "Customer Portal also has a first-party bug in portal/config_loader.py: "
        "resolve_config_path joins a caller-supplied profile into a filesystem path "
        "without proving the result stays under portal/configs. "
        "Read advisory/LOCAL-PROFILE-TRAVERSAL.md and portal/tests/test_config_loader.py. "
        "Rewrite resolve_config_path (and only the loader helpers you must touch) so that "
        "absolute paths, parent segments, and null bytes are rejected, "
        "resolved paths stay inside the config root, and profiles default and prod still load. "
        "Do not delete or weaken the tests. Do not change pom.xml in this pull request. "
        "python3 check_code_fix.py must exit 0. "
        f"Commit on branch {CODE_BRANCH}. Open a draft pull request. Do not merge. "
        "Title example: "
        "`[SignalZero] CVE-2026-22739: contain profile path resolution in portal/configs "
        "(code_patch)`. "
        "Proposed change: rewrite resolve_config_path containment only; leave pom.xml alone. "
        "Verify with `python3 check_code_fix.py` (expect exit 0). "
        "Review notes must state that passing tests do not prove a remote Spring server "
        "is patched. "
        f"Context: ranking score {score}, rank {rank} of 72670, snapshot 2026-03; "
        "label it as a ranking score, not an exploitation probability; "
        "local evidence advisory/LOCAL-PROFILE-TRAVERSAL.md; "
        "asset Customer Portal config loader (customer-portal-config-loader); inventory synthetic. "
        f"{_PR_SECTIONS}"
    )


def branch_for_route(route: str) -> str:
    if route == "code_patch":
        return CODE_BRANCH
    return DEPENDENCY_BRANCH


def task_for_route(route: str, *, ranking_score: float, rank: int) -> str:
    if route == "code_patch":
        return code_agent_task(ranking_score=ranking_score, rank=rank)
    return dependency_agent_task(ranking_score=ranking_score, rank=rank)
