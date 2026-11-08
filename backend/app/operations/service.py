from __future__ import annotations

import hashlib
import json
from urllib.parse import urlsplit

from app.config import Settings
from app.operations.delivery import Delivery, Outbound, build_delivery
from app.operations.errors import OperationsRequestError
from app.operations.inventory import ASSETS, KEV_ADDED_ON, SHAREFILE, DemoAsset, asset_for
from app.operations.models import (
    DeliveryView,
    FindingView,
    JobView,
    JudgeScriptReport,
    PreviewView,
    RankingsResponse,
    RankingView,
    ReadinessResponse,
    StepView,
)
from app.operations.policy import decide, notification_allowed
from app.operations.rankings import SCOREBOARD_ROWS, RankingCatalog, RankingRow, format_score
from app.operations.remediation import BRANCH, REPOSITORY, agent_task
from app.operations.store import EventRow, FindingRow, JobRow, OperationsStore, today_utc

STEP_ORDER = ("july", "kev", "portal", "replay")


class OperationsService:
    def __init__(self, settings: Settings, rankings: RankingCatalog | None = None) -> None:
        self._settings = settings
        self._rankings = rankings or RankingCatalog()
        self._store = OperationsStore(settings.operations_database_path)

    def readiness(self) -> ReadinessResponse:
        missing = [
            name
            for name, present in (
                ("SLACK_WEBHOOK_URL", self._settings.slack_webhook_url.strip()),
                ("JIRA_BASE_URL", self._settings.jira_base_url.strip()),
                ("JIRA_EMAIL", self._settings.jira_email.strip()),
                ("JIRA_API_TOKEN", self._settings.jira_api_token.strip()),
                ("JIRA_PROJECT_KEY", self._settings.jira_project_key.strip()),
                ("ENTIRE_TOKEN", self._settings.entire_token.strip()),
                ("GH_TOKEN", self._settings.github_token.strip()),
            )
            if not present
        ]
        live = self._settings.operations_delivery == "live"
        note = (
            "Live calls are enabled for channels whose credentials are present."
            if live
            else "OPERATIONS_DELIVERY is recording. Credentials are not called."
        )
        return ReadinessResponse(
            delivery_mode=self._settings.operations_delivery,
            live_calls_enabled=live,
            missing=missing,
            github_push_verified=False,
            note=note + " Push access to Mikop22/securitydemo is not verified from this process.",
        )

    def rankings(self) -> RankingsResponse:
        rows = []
        for row in self._rankings.load():
            asset = asset_for(row.cve_id)
            rows.append(
                RankingView(
                    cve_id=row.cve_id,
                    published=row.published,
                    snapshot_month=row.snapshot_month,
                    ranking_score=row.ranking_score,
                    rank=row.rank,
                    scoreboard_rows=SCOREBOARD_ROWS,
                    population_percentile=row.population_percentile,
                    asset_id=None if asset is None else asset.asset_id,
                    match_status="unmatched" if asset is None else "confirmed",
                    inventory_synthetic=asset is not None,
                )
            )
        return RankingsResponse(
            source="model/results/submission_v1_summary.json",
            rankings=rows,
        )

    def run_judge_script(self, through: str) -> JudgeScriptReport:
        if through not in STEP_ORDER:
            raise OperationsRequestError(f"unknown judge step {through!r}")
        last = STEP_ORDER.index(through)
        steps: list[StepView] = []
        for name in STEP_ORDER[: last + 1]:
            steps.extend(self._run_step(name))
        return self._report(steps)

    def state(self) -> JudgeScriptReport:
        return self._report([])

    def record_pull_request(
        self, cve_id: str, pr_url: str, checks_passed: bool
    ) -> JudgeScriptReport:
        parsed = urlsplit(pr_url)
        if parsed.scheme != "https" or parsed.hostname != "github.com":
            raise OperationsRequestError("pr_url must be an https://github.com pull request URL")
        asset = asset_for(cve_id)
        if asset is None or asset.route != "dependency_upgrade":
            raise OperationsRequestError(f"{cve_id} has no code-remediation job")
        finding_key = _key(asset)
        job = self._store.get_job(finding_key)
        if job is None:
            raise OperationsRequestError(
                "Queue the remediation job before recording a pull request."
            )
        finding = self._store.get_finding(finding_key)
        if finding is None:
            raise OperationsRequestError("The finding record is missing.")
        self._store.save_job(
            JobRow(
                finding_key=finding_key,
                status="pull_request_recorded",
                branch=job.branch,
                repository=job.repository,
                task=job.task,
                pr_url=pr_url,
                checks_passed=checks_passed,
            )
        )
        actions: list[str] = ["RECORD_PULL_REQUEST"]
        reason = (
            "Pull request recorded. A passing check does not prove the vulnerability is closed."
        )
        if finding.review_notified:
            reason = "Pull request updated. The review notice was already sent."
        else:
            kind = "slack_review"
            sent = self._store.count_deliveries(asset.team, kind, today_utc())
            if notification_allowed(kind, sent):
                ranking = self._rankings.get(cve_id)
                text = _review_text(
                    ranking,
                    asset,
                    finding.jira_issue_key or "unset",
                    pr_url,
                    checks_passed,
                )
                self._send(self._delivery().post_slack(finding_key, asset.team, kind, text))
                finding = FindingRow(
                    finding_key=finding.finding_key,
                    cve_id=finding.cve_id,
                    asset_id=finding.asset_id,
                    level=finding.level,
                    jira_issue_key=finding.jira_issue_key,
                    urgent_notified=finding.urgent_notified,
                    review_notified=True,
                    evidence_hash=finding.evidence_hash,
                    team=finding.team,
                    route=finding.route,
                    urgent=finding.urgent,
                )
                self._store.save_finding(finding)
                actions.append("NOTIFY_SLACK_REVIEW")
            else:
                reason = "Pull request recorded. The review-notice budget is exhausted."
        step = StepView(
            step="pull_request",
            finding_key=finding_key,
            level=finding.level,
            actions=actions,
            suppressed=False,
            reason=reason,
        )
        self._store.add_event(
            EventRow(
                step=step.step,
                finding_key=step.finding_key,
                level=step.level,
                actions=",".join(step.actions),
                suppressed=False,
                reason=step.reason,
            )
        )
        return self._report([step])

    def _run_step(self, name: str) -> list[StepView]:
        if name == "july":
            return [self._apply("july", "CVE-2026-8037", urgent=False)]
        if name == "kev":
            return [self._apply("kev", "CVE-2026-8037", urgent=True)]
        if name == "portal":
            return [self._apply("portal", "CVE-2026-22739", urgent=False)]
        return [
            self._apply("replay", "CVE-2026-8037", urgent=True),
            self._apply("replay", "CVE-2026-22739", urgent=False),
        ]

    def _apply(self, step: str, cve_id: str, *, urgent: bool) -> StepView:
        ranking = self._rankings.get(cve_id)
        asset = asset_for(cve_id)
        if asset is None or not asset.scripted_dispatch:
            raise OperationsRequestError(f"{cve_id} is not dispatched by the judge script")
        finding_key = _key(asset)
        prior = self._store.get_finding(finding_key)
        decision = decide(
            population_percentile=ranking.population_percentile,
            match_status="confirmed",
            owner_known=bool(asset.owner),
            criticality=asset.criticality,
            urgent=urgent,
            route=asset.route,
            fix_verified=bool(asset.fixed_version and asset.advisory_id and asset.repository),
            prior_level=None if prior is None else prior.level,
            human_resolved=False,
        )
        digest = _evidence_hash(ranking, asset, urgent)
        if prior is not None and prior.urgent and not urgent:
            step_view = StepView(
                step=step,
                finding_key=finding_key,
                level=prior.level,
                actions=[],
                suppressed=True,
                reason="A later urgent observation is already recorded.",
            )
            self._store.add_event(_event(step_view))
            return step_view
        if prior is not None and prior.evidence_hash == digest and prior.level == decision.level:
            step_view = StepView(
                step=step,
                finding_key=finding_key,
                level=prior.level,
                actions=[],
                suppressed=True,
                reason="No material change. The existing record was left in place.",
            )
            self._store.add_event(_event(step_view))
            return step_view

        issue_key = None if prior is None else prior.jira_issue_key
        urgent_notified = False if prior is None else prior.urgent_notified
        review_notified = False if prior is None else prior.review_notified
        actions: list[str] = []
        delivery = self._delivery()
        if decision.upsert_jira:
            body = _jira_body(step, ranking, asset, urgent)
            summary = f"{ranking.cve_id} on {asset.name}"
            if issue_key is None:
                outbound = delivery.create_jira(finding_key, asset.team, summary, body)
                issue_key = outbound.external_id
            else:
                outbound = delivery.update_jira(finding_key, asset.team, issue_key, body)
            self._send(outbound)
            actions.append("UPSERT_JIRA")
        if decision.notify_urgent and not urgent_notified:
            kind = "slack_urgent"
            sent = self._store.count_deliveries(asset.team, kind, today_utc())
            if notification_allowed(kind, sent):
                text = _urgent_text(ranking, asset, issue_key or "unset")
                self._send(delivery.post_slack(finding_key, asset.team, kind, text))
                urgent_notified = True
                actions.append("NOTIFY_SLACK_URGENT")
        if decision.queue_remediation and self._store.get_job(finding_key) is None:
            self._store.save_job(
                JobRow(
                    finding_key=finding_key,
                    status=_job_status(self._settings),
                    branch=BRANCH,
                    repository=REPOSITORY,
                    task=agent_task(ranking_score=ranking.ranking_score, rank=ranking.rank),
                    pr_url=None,
                    checks_passed=None,
                )
            )
            actions.append("QUEUE_REMEDIATION")

        self._store.save_finding(
            FindingRow(
                finding_key=finding_key,
                cve_id=asset.cve_id,
                asset_id=asset.asset_id,
                level=decision.level,
                jira_issue_key=issue_key,
                urgent_notified=urgent_notified,
                review_notified=review_notified,
                evidence_hash=digest,
                team=asset.team,
                route=asset.route,
                urgent=urgent or (prior.urgent if prior is not None else False),
            )
        )
        step_view = StepView(
            step=step,
            finding_key=finding_key,
            level=decision.level,
            actions=actions,
            suppressed=False,
            reason=decision.reason,
        )
        self._store.add_event(_event(step_view))
        return step_view

    def _delivery(self) -> Delivery:
        return build_delivery(self._settings)

    def _send(self, outbound: Outbound) -> None:
        self._store.add_delivery(outbound.row())

    def _report(self, steps: list[StepView]) -> JudgeScriptReport:
        return JudgeScriptReport(
            steps=steps,
            findings=[
                FindingView(
                    finding_key=row.finding_key,
                    cve_id=row.cve_id,
                    asset_id=row.asset_id,
                    level=row.level,
                    jira_issue_key=row.jira_issue_key,
                    urgent_notified=row.urgent_notified,
                    review_notified=row.review_notified,
                    team=row.team,
                    route=row.route,
                )
                for row in self._store.list_findings()
            ],
            deliveries=[
                DeliveryView(
                    kind=row.kind,
                    finding_key=row.finding_key,
                    team=row.team,
                    delivered=row.delivered,
                    mode=row.mode,
                    external_id=row.external_id,
                    body=row.body,
                    detail=row.detail,
                )
                for row in self._store.list_deliveries()
            ],
            jobs=[
                JobView(
                    finding_key=row.finding_key,
                    status=row.status,
                    branch=row.branch,
                    repository=row.repository,
                    task=row.task,
                    pr_url=row.pr_url,
                    checks_passed=row.checks_passed,
                )
                for row in self._store.list_jobs()
            ],
            undispatched=[_preview(self._rankings.get(SHAREFILE.cve_id))],
        )


def _preview(ranking: RankingRow) -> PreviewView:
    decision = decide(
        population_percentile=ranking.population_percentile,
        match_status="confirmed",
        owner_known=True,
        criticality=SHAREFILE.criticality,
        urgent=False,
        route=SHAREFILE.route,
        fix_verified=False,
        prior_level=None,
        human_resolved=False,
    )
    return PreviewView(
        cve_id=SHAREFILE.cve_id,
        asset_id=SHAREFILE.asset_id,
        level=decision.level,
        reason=decision.reason,
        dispatch=False,
        note=SHAREFILE.note,
        source=SHAREFILE.source,
    )


def _job_status(settings: Settings) -> str:
    if settings.github_token.strip() and settings.entire_token.strip():
        return "ready_for_agent"
    return "blocked_pending_credentials"


def _key(asset: DemoAsset) -> str:
    return f"{asset.cve_id}::{asset.asset_id}"


def _evidence_hash(ranking: RankingRow, asset: DemoAsset, urgent: bool) -> str:
    payload = json.dumps(
        {
            "cve_id": ranking.cve_id,
            "rank": ranking.rank,
            "score": format_score(ranking.ranking_score),
            "urgent": urgent,
            "installed_version": asset.installed_version,
            "fixed_version": asset.fixed_version,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _event(step: StepView) -> EventRow:
    return EventRow(
        step=step.step,
        finding_key=step.finding_key,
        level=step.level,
        actions=",".join(step.actions),
        suppressed=step.suppressed,
        reason=step.reason,
    )


def _jira_body(step: str, ranking: RankingRow, asset: DemoAsset, urgent: bool) -> str:
    score = format_score(ranking.ranking_score)
    base = (
        f"{ranking.cve_id} matches {asset.name} ({asset.product} {asset.installed_version}). "
        f"Rank {ranking.rank} of {SCOREBOARD_ROWS} in snapshot {ranking.snapshot_month}. "
        f"Ranking score {score} is not an exploitation probability. "
        f"Source: {asset.source}. Inventory is synthetic."
    )
    if asset.route == "appliance" and not urgent:
        return (
            base + " This decision does not use the later KEV listing. "
            "No code change is proposed; the asset is an appliance."
        )
    if urgent:
        return (
            base + f" CISA KEV added this CVE on {KEV_ADDED_ON}, after snapshot "
            f"{ranking.snapshot_month}. No code change is proposed; the asset is an appliance."
        )
    return (
        base + f" Verified fixed version on this line is {asset.fixed_version} "
        f"({asset.advisory_id}). 5.0.2 is out of scope. "
        "A coding agent may open a draft pull request. Nothing is merged from this record."
    )


def _urgent_text(ranking: RankingRow, asset: DemoAsset, issue_key: str) -> str:
    score = format_score(ranking.ranking_score)
    return (
        f"Urgent: {ranking.cve_id} on {asset.asset_id} is in the CISA KEV catalog "
        f"(added {KEV_ADDED_ON}). SignalZero ranked it {ranking.rank} of {SCOREBOARD_ROWS} "
        f"in the {ranking.snapshot_month} snapshot, before that listing. "
        f"Ranking score {score} is not an exploitation probability. "
        f"Jira: {issue_key}. No code change is proposed; this asset is an appliance."
    )


def _review_text(
    ranking: RankingRow,
    asset: DemoAsset,
    issue_key: str,
    pr_url: str,
    checks_passed: bool,
) -> str:
    return (
        f"Fix ready for review: {ranking.cve_id} in {asset.name}. "
        f"Draft PR bumps {asset.product} {asset.installed_version} to {asset.fixed_version}. "
        f"Checks passed: {checks_passed}. "
        "A passing check does not prove the vulnerability is closed. "
        f"Jira: {issue_key}. PR: {pr_url}."
    )


def known_assets() -> tuple[DemoAsset, ...]:
    return ASSETS
