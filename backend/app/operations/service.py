from __future__ import annotations

import hashlib
import json
from urllib.parse import urlsplit

from app.config import Settings
from app.operations.delivery import Delivery, Outbound, build_delivery
from app.operations.errors import OperationsRequestError
from app.operations.inventory import (
    ASSETS,
    KEV_ADDED_ON,
    SHAREFILE,
    DemoAsset,
    asset_by_id,
    asset_for,
)
from app.operations.jira_taxonomy import child_spec, epic_for_cve
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
from app.operations.remediation import REPOSITORY, branch_for_route, task_for_route
from app.operations.store import EventRow, FindingRow, JobRow, OperationsStore, today_utc

STEP_ORDER = ("july", "kev", "portal", "codefix", "replay")


class OperationsService:
    def __init__(self, settings: Settings, rankings: RankingCatalog | None = None) -> None:
        self._settings = settings
        self._rankings = rankings or RankingCatalog()
        self._store = OperationsStore(settings.operations_database_path)
        self._delivery_instance: Delivery | None = None

    @property
    def settings(self) -> Settings:
        return self._settings

    @property
    def store(self) -> OperationsStore:
        return self._store

    def readiness(self) -> ReadinessResponse:
        slack_ready = bool(self._settings.slack_webhook_url.strip()) or all(
            value.strip()
            for value in (
                self._settings.slack_channel_id,
                self._settings.slack_app_id,
                self._settings.slack_team_id,
            )
        )
        missing = [
            name
            for name, present in (
                (
                    "SLACK_WEBHOOK_URL or SLACK_CHANNEL_ID/SLACK_APP_ID/SLACK_TEAM_ID",
                    slack_ready,
                ),
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
        candidates = [
            row
            for row in self._store.list_findings()
            if row.cve_id == cve_id and row.route in {"dependency_upgrade", "code_patch"}
        ]
        open_jobs = []
        for row in candidates:
            job = self._store.get_job(row.finding_key)
            if job is not None and job.pr_url is None:
                open_jobs.append((row, job))
        if not open_jobs:
            # Fall back to the most recent remediated finding for updates.
            paired = []
            for row in candidates:
                job = self._store.get_job(row.finding_key)
                if job is not None:
                    paired.append((row, job))
            if not paired:
                raise OperationsRequestError(f"{cve_id} has no queued remediation finding")
            finding, job = paired[-1]
        else:
            finding, job = open_jobs[0]
        asset = asset_by_id(finding.asset_id)
        if asset is None or asset.route not in {"dependency_upgrade", "code_patch"}:
            raise OperationsRequestError(f"{cve_id} has no code-remediation job")
        finding_key = finding.finding_key
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
            return [self._apply("july", "edge-load-balancer", urgent=False)]
        if name == "kev":
            return [self._apply("kev", "edge-load-balancer", urgent=True)]
        if name == "portal":
            return [self._apply("portal", "customer-portal", urgent=False)]
        if name == "codefix":
            return [self._apply("codefix", "customer-portal-config-loader", urgent=False)]
        return [
            self._apply("replay", "edge-load-balancer", urgent=True),
            self._apply("replay", "customer-portal", urgent=False),
            self._apply("replay", "customer-portal-config-loader", urgent=False),
        ]

    def _apply(self, step: str, asset_id: str, *, urgent: bool) -> StepView:
        asset = asset_by_id(asset_id)
        if asset is None or not asset.scripted_dispatch:
            raise OperationsRequestError(f"{asset_id} is not dispatched by the judge script")
        ranking = self._rankings.get(asset.cve_id)
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
            summary = f"[{ranking.cve_id}] {asset.name} ({asset.product} {asset.installed_version})"
            epic = epic_for_cve(ranking.cve_id, ranking.description)
            child = child_spec(asset, cve_id=ranking.cve_id, summary=summary, urgent=urgent)
            epic_outbound = delivery.ensure_jira_epic(
                finding_key,
                asset.team,
                cve_id=epic.cve_id,
                summary=epic.summary,
                body=epic.body,
                labels=list(epic.labels),
            )
            if "Reused" not in epic_outbound.detail:
                self._send(epic_outbound)
                actions.append("UPSERT_JIRA_EPIC")
            parent_key = epic_outbound.external_id
            if issue_key is None:
                outbound = delivery.create_jira(
                    finding_key,
                    asset.team,
                    child.summary,
                    body,
                    issue_type=child.issue_type,
                    priority=child.priority,
                    labels=list(child.labels),
                    parent_key=parent_key,
                )
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
                    branch=branch_for_route(asset.route),
                    repository=REPOSITORY,
                    task=task_for_route(
                        asset.route,
                        ranking_score=ranking.ranking_score,
                        rank=ranking.rank,
                    ),
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
        if self._delivery_instance is None:
            self._delivery_instance = build_delivery(self._settings)
        return self._delivery_instance

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
    description = ranking.description or "No CVE description supplied in prediction artifact."
    lines = [
        "## Vulnerability Summary",
        description,
        "",
        "## Affected Asset & Priority",
        f"- Asset: {asset.name} ({asset.asset_id}) · Owner: {asset.owner} Team",
        f"- Affected Component: {asset.product} {asset.installed_version}",
        f"- Vigil Model Rank: #{ranking.rank} of {SCOREBOARD_ROWS} (Snapshot {ranking.snapshot_month})",
        f"- Relative Ranking Score: {score} (Ranking score {score} is not an exploitation probability)",
        f"- Advisory / Source: {asset.source}",
    ]
    if asset.repository:
        lines.append(f"- Repository: https://github.com/{asset.repository}")
    lines.extend(["", "## Recommended Remediation"])
    if asset.route == "appliance" and not urgent:
        lines.extend(
            [
                "- Route: Managed network appliance — manual vendor firmware upgrade required (no automated code PR).",
                "- Notes: Initial July snapshot assessment prior to CISA KEV listing; inventory is synthetic.",
            ]
        )
    elif urgent:
        lines.extend(
            [
                f"- Urgent Escalation: Added to CISA KEV on {KEV_ADDED_ON} (after snapshot {ranking.snapshot_month}).",
                "- Action Required: Patch Progress LoadMaster firmware to 7.2.63.2 or later immediately.",
                "- Route: Managed network appliance — no code change is proposed from this record (inventory is synthetic).",
            ]
        )
    elif asset.route == "code_patch":
        lines.extend(
            [
                f"- Route: First-party code patch ({asset.advisory_id})",
                "- Action Required: Rewrite resolve_config_path in portal/config_loader.py so profile paths stay contained under portal/configs.",
                "- Draft Pull Request: https://github.com/Mikop22/securitydemo/pull/2 (automated check_code_fix.py passing; awaiting human review).",
                "- Review Caveat: Passing tests do not prove a remote Spring server is patched. Nothing is merged automatically (inventory is synthetic).",
            ]
        )
    else:
        lines.extend(
            [
                f"- Route: Dependency upgrade ({asset.advisory_id})",
                f"- Action Required: Upgrade {asset.product} from {asset.installed_version} to {asset.fixed_version} in pom.xml (stay on the 4.3.x line; 5.0.2 is out of scope).",
                "- Draft Pull Request: https://github.com/Mikop22/securitydemo/pull/1 (automated check_version.py passing; awaiting human review).",
                "- Review Caveat: Passing version check does not prove the path traversal is closed. Nothing is merged automatically (inventory is synthetic).",
            ]
        )
    return "\n".join(lines)


def _urgent_text(ranking: RankingRow, asset: DemoAsset, issue_key: str) -> str:
    score = format_score(ranking.ranking_score)
    description = ranking.description or "Unauthenticated remote vulnerability requiring immediate triage."
    return (
        f"*Urgent — no code change* · *{ranking.cve_id} (Model Rank #{ranking.rank} · CISA KEV)*\n"
        f"CVE: {ranking.cve_id} · *Asset:* {asset.name} (`{asset.product}` {asset.installed_version}) · *Owner:* {asset.owner} Team\n\n"
        f"*What is the issue?*\n"
        f"{description}\n\n"
        f"*Action Required*\n"
        f"• *Asset ID:* `{asset.asset_id}` (Managed appliance — manual firmware patch required; no automated code PR)\n"
        f"• *KEV Listing:* Added on {KEV_ADDED_ON} (after snapshot {ranking.snapshot_month})\n"
        f"• *Model Context:* Rank {ranking.rank}/{SCOREBOARD_ROWS} · Ranking score {score} is not an exploitation probability\n"
        f"• *Tracking:* Jira `{issue_key}` · <{asset.source}|Advisory>"
    )


def _review_text(
    ranking: RankingRow,
    asset: DemoAsset,
    issue_key: str,
    pr_url: str,
    checks_passed: bool,
) -> str:
    description = ranking.description or "High-priority vulnerability matched to repository asset."
    if asset.route == "code_patch":
        change = f"Contain profile path resolution under `portal/configs` (`{asset.product}`)"
        caveat = "Passing tests do not prove a remote Spring server is patched"
    else:
        change = (
            f"Bump `{asset.product}` `{asset.installed_version}` → "
            f"`{asset.fixed_version}` in `pom.xml`"
        )
        caveat = "Passing check does not prove the vulnerability is closed"
    checks = "pass" if checks_passed else "fail"
    return (
        f"*Draft fix for review* · *{ranking.cve_id} (Model Rank #{ranking.rank})*\n"
        f"CVE: {ranking.cve_id} · *Asset:* {asset.name} (`{asset.product}` {asset.installed_version}) · *Owner:* {asset.owner} Team\n\n"
        f"*What is the issue?*\n"
        f"{description}\n\n"
        f"*Proposed Remediation*\n"
        f"• *Change:* {change}\n"
        f"• Checks: {checks} ({caveat})\n"
        f"• *Pull Request:* {pr_url} (draft — do not merge)\n"
        f"• *Jira Ticket:* `{issue_key}` · <{asset.source}|Advisory>"
    )


def known_assets() -> tuple[DemoAsset, ...]:
    return ASSETS
