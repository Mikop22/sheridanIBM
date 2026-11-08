from __future__ import annotations

from dataclasses import dataclass

ENTER_ACT = 0.99
HOLD_ACT = 0.95
ROUTINE_BUDGET = 3
REVIEW_BUDGET = 5


@dataclass(frozen=True)
class Decision:
    level: str
    reason: str
    upsert_jira: bool
    notify_urgent: bool
    queue_remediation: bool


def notification_allowed(kind: str, already_sent: int) -> bool:
    """Urgent safety notices bypass the cap. Routine and review notices do not."""

    if kind == "slack_urgent":
        return True
    if kind == "slack_routine":
        return already_sent < ROUTINE_BUDGET
    if kind == "slack_review":
        return already_sent < REVIEW_BUDGET
    return False


def _meets_act(percentile: float, prior_level: str | None) -> bool:
    if prior_level in {"act", "escalate"}:
        return percentile >= HOLD_ACT
    return percentile >= ENTER_ACT


def decide(
    *,
    population_percentile: float,
    match_status: str,
    owner_known: bool,
    criticality: str,
    urgent: bool,
    route: str,
    fix_verified: bool,
    prior_level: str | None,
    human_resolved: bool,
) -> Decision:
    if human_resolved:
        return Decision(
            level="observe",
            reason="A human resolution is recorded.",
            upsert_jira=False,
            notify_urgent=False,
            queue_remediation=False,
        )
    if match_status == "unmatched":
        return Decision(
            level="observe",
            reason="No confirmed asset match.",
            upsert_jira=False,
            notify_urgent=False,
            queue_remediation=False,
        )
    if prior_level == "escalate":
        level = "escalate"
        reason = "Escalate remains until a human records a resolution."
    elif match_status == "possible":
        level = "investigate"
        reason = "The asset match is only possible."
    elif (
        _meets_act(population_percentile, prior_level)
        and owner_known
        and urgent
        and criticality == "critical"
    ):
        level = "escalate"
        reason = "Confirmed critical asset with urgent evidence."
    elif _meets_act(population_percentile, prior_level) and owner_known:
        level = "act"
        reason = "Confirmed asset with a known owner at the action percentile."
    elif population_percentile >= HOLD_ACT:
        level = "investigate"
        reason = "Percentile is elevated and below the action threshold."
    else:
        level = "observe"
        reason = "Confirmed asset is below the investigation percentile."

    return Decision(
        level=level,
        reason=reason,
        upsert_jira=level in {"act", "escalate"},
        notify_urgent=level == "escalate",
        queue_remediation=(
            level == "act"
            and route in {"dependency_upgrade", "code_patch"}
            and fix_verified
        ),
    )
