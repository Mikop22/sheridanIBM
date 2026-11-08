from __future__ import annotations

from app.operations.rankings import format_score

BRANCH = "signalzero/cve-2026-22739"
REPOSITORY = "Mikop22/securitydemo"


def agent_task(*, ranking_score: float, rank: int) -> str:
    score = format_score(ranking_score)
    return (
        "In Mikop22/securitydemo, CVE-2026-22739 affects "
        "org.springframework.cloud:spring-cloud-config-server 4.3.1. "
        "advisory/GHSA-3qwq-q9vm-5j42.md names 4.3.2 as the patched version on the 4.3 line. "
        "Do not upgrade to 5.0.2. "
        "Change only the dependency pin to 4.3.2. "
        "Do not edit the advisory or check_version.py. "
        f"check_version.py must exit 0. "
        f"Commit on branch {BRANCH}. "
        "Open a draft pull request. Do not merge. "
        f"The v1 ensemble ranking score is {score}, rank {rank} of 72670. "
        "Describe that number as a ranking score, not an exploitation probability. "
        "State that a passing check does not prove the path traversal is closed. "
        "If Entire is enabled, leave it enabled and include the checkpoint id in the pull request."
    )
