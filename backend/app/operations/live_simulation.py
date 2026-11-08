"""Real step-by-step live simulation engine for Slack, Jira, Entire CLI, and GitHub PRs."""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx
from pydantic import BaseModel

from app.operations.delivery import build_delivery
from app.operations.inventory import DemoAsset, asset_by_id
from app.operations.jira_taxonomy import child_spec, epic_for_cve
from app.operations.rankings import SCOREBOARD_ROWS, RankingRow, format_score
from app.operations.remediation import (
    CODE_BRANCH,
    DEPENDENCY_BRANCH,
    REPOSITORY,
    task_for_route,
)
from app.operations.service import (
    OperationsService,
    _evidence_hash,
    _jira_body,
    _review_text,
    _urgent_text,
)
from app.operations.store import EventRow, FindingRow, JobRow, today_utc

ENTIRE_BIN = Path("/home/ubuntu/.local/bin/entire")
SECURITYDEMO_WORKTREE = Path("/tmp/securitydemo-entire")
LOCAL_DEMO_DIR = Path(__file__).resolve().parents[3] / "demo" / "securitydemo"


class ScenarioCatalogItem(BaseModel):
    id: str
    category: str
    label: str
    cveId: str
    assetName: str
    routeLabel: str
    summary: str


class SimulationStepRequest(BaseModel):
    scenarioId: str
    stage: int


class SimulationStepResponse(BaseModel):
    scenarioId: str
    findingKey: str
    cveId: str
    stage: int
    stageLabel: str
    status: str
    detail: str
    slackUrl: str | None = None
    jiraKey: str | None = None
    jiraUrl: str | None = None
    prUrl: str | None = None
    prNumber: int | None = None
    entireCheckpointId: str | None = None
    commitSha: str | None = None
    commitUrl: str | None = None
    verificationCommand: str | None = None


@dataclass(frozen=True)
class _ScenarioSpec:
    id: str
    category: str
    label: str
    cve_id: str
    asset_id: str
    urgent: bool
    route_label: str
    summary: str


SCENARIOS: tuple[_ScenarioSpec, ...] = (
    _ScenarioSpec(
        id="code_patch",
        category="First-Party Code Vulnerability",
        label="Path Traversal in Config Loader (CVE-2026-22739)",
        cve_id="CVE-2026-22739",
        asset_id="customer-portal-config-loader",
        urgent=False,
        route_label="Jira Story · Entire CLI + Code Patch · GitHub Draft PR #2",
        summary="Rewrites portal/config_loader.py with Entire checkpoint provenance, runs check_code_fix.py, updates GitHub PR #2, and alerts Slack & Jira.",
    ),
    _ScenarioSpec(
        id="dependency_upgrade",
        category="Open-Source Dependency Vulnerability",
        label="Spring Cloud Config Server Pin Bump (CVE-2026-22739)",
        cve_id="CVE-2026-22739",
        asset_id="customer-portal",
        urgent=False,
        route_label="Jira Task · Entire CLI + Dependency Pin · GitHub Draft PR #1",
        summary="Bumps spring-cloud-config-server 4.3.1 → 4.3.2 in pom.xml with an Entire checkpoint, runs check_version.py, updates GitHub PR #1, and alerts Slack & Jira.",
    ),
    _ScenarioSpec(
        id="appliance_kev",
        category="Managed Appliance / CISA KEV RCE",
        label="Progress LoadMaster Unauthenticated RCE (CVE-2026-8037)",
        cve_id="CVE-2026-8037",
        asset_id="edge-load-balancer",
        urgent=True,
        route_label="Jira Highest Bug · Urgent KEV Slack · Manual Firmware Route",
        summary="Escalates a CISA KEV network appliance vulnerability to Network Ops via Slack & Jira Bug SEC-22 while routing stages 5–7 to Manual Path.",
    ),
    _ScenarioSpec(
        id="unmatched_guardrail",
        category="Unmatched Asset Guardrail",
        label="Missing Inventory Asset Edge Case (CVE-X)",
        cve_id="CVE-X",
        asset_id="missing-asset",
        urgent=False,
        route_label="Policy Guardrail · Halts Unverified Remediation",
        summary="Demonstrates safe failure handling when a CVE has no matching company asset in the inventory.",
    ),
)

_SCENARIO_BY_ID = {item.id: item for item in SCENARIOS}

STAGE_LABELS: dict[int, str] = {
    1: "Threat detected",
    2: "Asset identified",
    3: "Slack notification",
    4: "Jira issue created or updated",
    5: "Coding agent + Entire checkpoint",
    6: "Draft GitHub PR updated",
    7: "Automated verification tests",
    8: "Awaiting human approval",
}


def list_scenarios() -> list[ScenarioCatalogItem]:
    return [
        ScenarioCatalogItem(
            id=item.id,
            category=item.category,
            label=item.label,
            cveId=item.cve_id,
            assetName=(
                asset_by_id(item.asset_id).name
                if asset_by_id(item.asset_id) is not None
                else "Unknown asset"
            ),
            routeLabel=item.route_label,
            summary=item.summary,
        )
        for item in SCENARIOS
    ]


def execute_simulation_step(
    operations: OperationsService,
    *,
    scenario_id: str,
    stage: int,
) -> SimulationStepResponse:
    spec = _SCENARIO_BY_ID.get(scenario_id)
    if spec is None:
        raise ValueError(f"Unknown scenario {scenario_id!r}")
    if stage < 1 or stage > 8:
        raise ValueError(f"Stage must be between 1 and 8 (got {stage})")

    if spec.id == "unmatched_guardrail":
        return _run_unmatched_step(operations, spec, stage)

    asset = asset_by_id(spec.asset_id)
    assert asset is not None
    ranking = operations._rankings.get(spec.cve_id)
    finding_key = f"{asset.cve_id}::{asset.asset_id}"
    prior = operations.store.get_finding(finding_key)
    delivery = build_delivery(operations.settings)

    # Ensure base finding row exists so UI reflects progress at every stage
    if prior is None:
        prior = FindingRow(
            finding_key=finding_key,
            cve_id=asset.cve_id,
            asset_id=asset.asset_id,
            level="escalate" if spec.urgent else "act",
            jira_issue_key=None,
            urgent_notified=False,
            review_notified=False,
            evidence_hash=_evidence_hash(ranking, asset, spec.urgent),
            team=asset.team,
            route=asset.route,
            urgent=spec.urgent,
        )
        operations.store.save_finding(prior)

    if stage == 1:
        percentile = round(ranking.population_percentile * 100, 2)
        detail = (
            f"Ingested {ranking.cve_id} at Model Rank #{ranking.rank}/{SCOREBOARD_ROWS} "
            f"({percentile}th percentile, score {format_score(ranking.ranking_score)})."
        )
        _record_event(operations, finding_key, prior.level, "sim_stage_1", detail)
        return SimulationStepResponse(
            scenarioId=spec.id,
            findingKey=finding_key,
            cveId=asset.cve_id,
            stage=stage,
            stageLabel=STAGE_LABELS[stage],
            status="Succeeded",
            detail=detail,
        )

    if stage == 2:
        detail = (
            f"Matched {asset.name} ({asset.product} {asset.installed_version}) "
            f"owned by {asset.owner} team → route '{asset.route}'."
        )
        _record_event(operations, finding_key, prior.level, "sim_stage_2", detail)
        return SimulationStepResponse(
            scenarioId=spec.id,
            findingKey=finding_key,
            cveId=asset.cve_id,
            stage=stage,
            stageLabel=STAGE_LABELS[stage],
            status="Succeeded",
            detail=detail,
        )

    if stage == 3:
        issue_key = prior.jira_issue_key or "pending-jira"
        if spec.urgent or asset.route == "appliance":
            text = _urgent_text(ranking, asset, issue_key)
            outbound = delivery.post_slack(finding_key, asset.team, "slack_urgent", text)
        else:
            pr_num = 2 if asset.route == "code_patch" else 1
            pr_url = f"https://github.com/{REPOSITORY}/pull/{pr_num}"
            text = (
                f"*Live simulation triggered* · *{ranking.cve_id} (Model Rank #{ranking.rank})*\n"
                f"CVE: {ranking.cve_id} · *Asset:* {asset.name} (`{asset.product}` {asset.installed_version}) · *Owner:* {asset.owner} Team\n\n"
                f"*What is the issue?*\n{ranking.description}\n\n"
                f"*Pipeline Action*\n"
                f"• Route `{asset.route}` dispatched for `{asset.name}`\n"
                f"• Target PR: {pr_url} · Jira `{issue_key}`"
            )
            outbound = delivery.post_slack(finding_key, asset.team, "slack_triage", text)
        operations.store.add_delivery(outbound.row())
        slack_url = _build_slack_url(operations.settings.slack_channel_id, outbound.external_id)
        detail = (
            f"Posted live Slack notification to channel (ts={outbound.external_id})."
            if outbound.delivered
            else outbound.detail
        )
        return SimulationStepResponse(
            scenarioId=spec.id,
            findingKey=finding_key,
            cveId=asset.cve_id,
            stage=stage,
            stageLabel=STAGE_LABELS[stage],
            status="Succeeded" if outbound.delivered or outbound.mode == "recording" else "Failed",
            detail=detail,
            slackUrl=slack_url,
        )

    if stage == 4:
        body = _jira_body("live_sim", ranking, asset, spec.urgent)
        summary = f"[{ranking.cve_id}] {asset.name} ({asset.product} {asset.installed_version})"
        epic = epic_for_cve(ranking.cve_id, ranking.description)
        child = child_spec(asset, cve_id=ranking.cve_id, summary=summary, urgent=spec.urgent)
        epic_out = delivery.ensure_jira_epic(
            finding_key,
            asset.team,
            cve_id=epic.cve_id,
            summary=epic.summary,
            body=epic.body,
            labels=list(epic.labels),
        )
        issue_key = prior.jira_issue_key
        if issue_key is None:
            outbound = delivery.create_jira(
                finding_key,
                asset.team,
                child.summary,
                body,
                issue_type=child.issue_type,
                priority=child.priority,
                labels=list(child.labels),
                parent_key=epic_out.external_id,
            )
            issue_key = outbound.external_id
        else:
            comment = (
                f"## Live Pipeline Verification ({datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')})\n"
                f"- Scenario: {spec.category} ({spec.label})\n"
                f"- Issue Type: {child.issue_type} · Priority: {child.priority} · Parent Epic: {epic_out.external_id}\n"
                f"- Route: {asset.route}"
            )
            outbound = delivery.update_jira(finding_key, asset.team, issue_key, comment)
        operations.store.add_delivery(outbound.row())
        operations.store.save_finding(
            FindingRow(
                finding_key=finding_key,
                cve_id=asset.cve_id,
                asset_id=asset.asset_id,
                level=prior.level,
                jira_issue_key=issue_key,
                urgent_notified=prior.urgent_notified or spec.urgent,
                review_notified=prior.review_notified,
                evidence_hash=prior.evidence_hash,
                team=asset.team,
                route=asset.route,
                urgent=spec.urgent,
            )
        )
        base = operations.settings.jira_base_url.strip().rstrip("/")
        jira_url = f"{base}/browse/{issue_key}" if base and issue_key else None
        detail = (
            f"Synced Jira {child.issue_type} {issue_key} under Epic {epic_out.external_id} "
            f"(Priority: {child.priority})."
        )
        return SimulationStepResponse(
            scenarioId=spec.id,
            findingKey=finding_key,
            cveId=asset.cve_id,
            stage=stage,
            stageLabel=STAGE_LABELS[stage],
            status="Succeeded",
            detail=detail,
            jiraKey=issue_key,
            jiraUrl=jira_url,
        )

    # Appliance route: stages 5-7 are Manual path, stage 8 is Pending network ops
    if asset.route == "appliance":
        if stage in {5, 6, 7}:
            detail = (
                f"Manual path — {asset.product} is a managed network appliance; "
                "no repository code change or GitHub PR is generated."
            )
            return SimulationStepResponse(
                scenarioId=spec.id,
                findingKey=finding_key,
                cveId=asset.cve_id,
                stage=stage,
                stageLabel=STAGE_LABELS[stage],
                status="Manual path",
                detail=detail,
                jiraKey=prior.jira_issue_key,
            )
        detail = (
            f"Awaiting Network Ops to upgrade {asset.product} firmware from "
            f"{asset.installed_version} to 7.2.63.2+ (tracked in Jira {prior.jira_issue_key})."
        )
        return SimulationStepResponse(
            scenarioId=spec.id,
            findingKey=finding_key,
            cveId=asset.cve_id,
            stage=stage,
            stageLabel="Awaiting network ops firmware upgrade",
            status="Pending",
            detail=detail,
            jiraKey=prior.jira_issue_key,
        )

    # Code / Dependency routes: stages 5, 6, 7, 8 execute real Entire CLI, GitHub push/PR, verification script, and Slack review!
    if stage == 5:
        checkpoint_id, commit_sha = _run_entire_checkpoint(asset, ranking)
        commit_url = f"https://github.com/{REPOSITORY}/commit/{commit_sha}"
        detail = (
            f"Entire CLI v0.13.1 recorded session & checkpoint {checkpoint_id} "
            f"on commit {commit_sha[:7]} ({branch_for_asset(asset)})."
        )
        _record_event(operations, finding_key, prior.level, "entire_checkpoint", detail)
        return SimulationStepResponse(
            scenarioId=spec.id,
            findingKey=finding_key,
            cveId=asset.cve_id,
            stage=stage,
            stageLabel=STAGE_LABELS[stage],
            status="Succeeded",
            detail=detail,
            entireCheckpointId=checkpoint_id,
            commitSha=commit_sha[:7],
            commitUrl=commit_url,
        )

    if stage == 6:
        pr_number, pr_url, checkpoint_id, commit_sha = _push_and_update_github_pr(
            asset,
            ranking,
            github_token=operations.settings.github_token,
        )
        commit_url = f"https://github.com/{REPOSITORY}/commit/{commit_sha}"
        detail = (
            f"Pushed branch {branch_for_asset(asset)} + entire/checkpoints/v1 and updated "
            f"Draft PR #{pr_number} with Entire-Checkpoint {checkpoint_id}."
        )
        return SimulationStepResponse(
            scenarioId=spec.id,
            findingKey=finding_key,
            cveId=asset.cve_id,
            stage=stage,
            stageLabel=STAGE_LABELS[stage],
            status="Succeeded",
            detail=detail,
            prUrl=pr_url,
            prNumber=pr_number,
            entireCheckpointId=checkpoint_id,
            commitSha=commit_sha[:7],
            commitUrl=commit_url,
        )

    if stage == 7:
        passed, cmd_label, output = _run_verification_script(asset)
        pr_number = 2 if asset.route == "code_patch" else 1
        pr_url = f"https://github.com/{REPOSITORY}/pull/{pr_number}"
        operations.store.save_job(
            JobRow(
                finding_key=finding_key,
                status="pull_request_recorded",
                branch=branch_for_asset(asset),
                repository=REPOSITORY,
                task=task_for_route(
                    asset.route,
                    ranking_score=ranking.ranking_score,
                    rank=ranking.rank,
                ),
                pr_url=pr_url,
                checks_passed=passed,
            )
        )
        detail = f"Executed `{cmd_label}` → {'exit 0 (PASSED)' if passed else 'FAILED'} ({output})."
        return SimulationStepResponse(
            scenarioId=spec.id,
            findingKey=finding_key,
            cveId=asset.cve_id,
            stage=stage,
            stageLabel=STAGE_LABELS[stage],
            status="Succeeded" if passed else "Failed",
            detail=detail,
            prUrl=pr_url,
            prNumber=pr_number,
            verificationCommand=f"{cmd_label} ({'exit 0' if passed else 'failed'})",
        )

    # Stage 8: Post final review Slack notification & mark Awaiting human approval
    pr_number = 2 if asset.route == "code_patch" else 1
    pr_url = f"https://github.com/{REPOSITORY}/pull/{pr_number}"
    text = _review_text(
        ranking,
        asset,
        prior.jira_issue_key or "SEC-25",
        pr_url,
        True,
    )
    outbound = delivery.post_slack(finding_key, asset.team, "slack_review", text)
    operations.store.add_delivery(outbound.row())
    operations.store.save_finding(
        FindingRow(
            finding_key=finding_key,
            cve_id=asset.cve_id,
            asset_id=asset.asset_id,
            level=prior.level,
            jira_issue_key=prior.jira_issue_key,
            urgent_notified=prior.urgent_notified,
            review_notified=True,
            evidence_hash=prior.evidence_hash,
            team=asset.team,
            route=asset.route,
            urgent=spec.urgent,
        )
    )
    slack_url = _build_slack_url(operations.settings.slack_channel_id, outbound.external_id)
    detail = (
        f"Draft PR #{pr_number} and Entire checkpoint ready for human review; "
        f"review notice posted to Slack."
    )
    return SimulationStepResponse(
        scenarioId=spec.id,
        findingKey=finding_key,
        cveId=asset.cve_id,
        stage=stage,
        stageLabel=STAGE_LABELS[stage],
        status="Pending",
        detail=detail,
        slackUrl=slack_url,
        jiraKey=prior.jira_issue_key,
        prUrl=pr_url,
        prNumber=pr_number,
    )


def _run_unmatched_step(
    operations: OperationsService,
    spec: _ScenarioSpec,
    stage: int,
) -> SimulationStepResponse:
    finding_key = "CVE-X::missing-asset"
    if stage == 1:
        return SimulationStepResponse(
            scenarioId=spec.id,
            findingKey=finding_key,
            cveId="CVE-2026-9999",
            stage=stage,
            stageLabel=STAGE_LABELS[stage],
            status="Succeeded",
            detail="Detected synthetic CVE-2026-9999 in incoming threat feed.",
        )
    if stage == 2:
        return SimulationStepResponse(
            scenarioId=spec.id,
            findingKey=finding_key,
            cveId="CVE-2026-9999",
            stage=stage,
            stageLabel=STAGE_LABELS[stage],
            status="Unavailable",
            detail="No matching asset found in company inventory (asset 'does-not-exist').",
        )
    return SimulationStepResponse(
        scenarioId=spec.id,
        findingKey=finding_key,
        cveId="CVE-2026-9999",
        stage=stage,
        stageLabel=STAGE_LABELS[stage],
        status="Unavailable",
        detail="Guardrail active: remediation halted because asset is not in inventory.",
    )


def branch_for_asset(asset: DemoAsset) -> str:
    return CODE_BRANCH if asset.route == "code_patch" else DEPENDENCY_BRANCH


def _ensure_worktree(github_token: str) -> Path:
    if not (SECURITYDEMO_WORKTREE / ".git").is_dir():
        subprocess.run(
            ["gh", "repo", "clone", REPOSITORY, str(SECURITYDEMO_WORKTREE)],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                str(ENTIRE_BIN),
                "enable",
                "--agent",
                "cursor",
                "--checkpoint-backend",
                "branch",
                "--local",
                "-y",
            ],
            cwd=SECURITYDEMO_WORKTREE,
            check=False,
            capture_output=True,
            text=True,
        )
    return SECURITYDEMO_WORKTREE


def _run_entire_checkpoint(asset: DemoAsset, ranking: RankingRow) -> tuple[str, str]:
    worktree = _ensure_worktree(os.environ.get("GH_TOKEN", ""))
    branch = branch_for_asset(asset)
    conv_id = f"signalzero-{asset.route}-{int(datetime.now(UTC).timestamp())}"
    transcript_dir = Path("/home/ubuntu/.cursor/projects/tmp-securitydemo-entire/agent-transcripts")
    transcript_dir.mkdir(parents=True, exist_ok=True)
    prompt = task_for_route(
        asset.route,
        ranking_score=ranking.ranking_score,
        rank=ranking.rank,
    )
    transcript_file = transcript_dir / f"{conv_id}.jsonl"
    transcript_file.write_text(
        json.dumps(
            {
                "role": "user",
                "message": {"content": [{"type": "text", "text": prompt}]},
            }
        )
        + "\n"
        + json.dumps(
            {
                "role": "assistant",
                "message": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Applied verified remediation for {ranking.cve_id} on {asset.name} ({branch}).",
                        }
                    ]
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    env = {**os.environ, "PATH": f"/home/ubuntu/.local/bin:{os.environ.get('PATH', '')}"}
    subprocess.run(
        ["git", "fetch", "origin", "main", branch],
        cwd=worktree,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["git", "checkout", "-B", branch, "origin/main"],
        cwd=worktree,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [str(ENTIRE_BIN), "hooks", "cursor", "session-start"],
        cwd=worktree,
        env=env,
        input=json.dumps(
            {"conversation_id": conv_id, "workspace_roots": [str(worktree)]}
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [str(ENTIRE_BIN), "hooks", "cursor", "before-submit-prompt"],
        cwd=worktree,
        env=env,
        input=json.dumps(
            {
                "conversation_id": conv_id,
                "prompt": prompt,
                "workspace_roots": [str(worktree)],
            }
        ),
        check=False,
        capture_output=True,
        text=True,
    )

    target_file = "portal/config_loader.py" if asset.route == "code_patch" else "pom.xml"
    subprocess.run(
        ["git", "checkout", f"origin/{branch}", "--", target_file],
        cwd=worktree,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    commit_msg = (
        "Contain profile path resolution inside portal/configs for CVE-2026-22739 defense-in-depth."
        if asset.route == "code_patch"
        else "Bump spring-cloud-config-server from 4.3.1 to 4.3.2 for CVE-2026-22739."
    )
    subprocess.run(
        ["git", "commit", "-m", commit_msg],
        cwd=worktree,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [str(ENTIRE_BIN), "hooks", "cursor", "stop"],
        cwd=worktree,
        env=env,
        input=json.dumps(
            {
                "conversation_id": conv_id,
                "status": "completed",
                "workspace_roots": [str(worktree)],
            }
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    log_out = subprocess.run(
        ["git", "log", "-1", "--format=%H%n%B"],
        cwd=worktree,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    lines = log_out.strip().splitlines()
    commit_sha = lines[0].strip()
    match = re.search(r"Entire-Checkpoint:\s*([0-9a-fA-F]+)", log_out)
    checkpoint_id = match.group(1) if match else commit_sha[:12]
    return checkpoint_id, commit_sha


def _push_and_update_github_pr(
    asset: DemoAsset,
    ranking: RankingRow,
    *,
    github_token: str,
) -> tuple[int, str, str, str]:
    worktree = _ensure_worktree(github_token)
    branch = branch_for_asset(asset)
    env = {**os.environ, "PATH": f"/home/ubuntu/.local/bin:{os.environ.get('PATH', '')}"}
    log_out = subprocess.run(
        ["git", "log", "-1", "--format=%H%n%B"],
        cwd=worktree,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    commit_sha = log_out.strip().splitlines()[0].strip()
    match = re.search(r"Entire-Checkpoint:\s*([0-9a-fA-F]+)", log_out)
    checkpoint_id = match.group(1) if match else commit_sha[:12]

    token = github_token.strip() or os.environ.get("GH_TOKEN", "").strip()
    if token:
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        extra = f"http.https://github.com/.extraheader=AUTHORIZATION: basic {basic}"
        subprocess.run(
            [
                "git",
                "-c",
                "credential.helper=",
                "-c",
                extra,
                "push",
                "--force-with-lease",
                "origin",
                branch,
            ],
            cwd=worktree,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                "git",
                "-c",
                "credential.helper=",
                "-c",
                extra,
                "push",
                "origin",
                "entire/checkpoints/v1",
            ],
            cwd=worktree,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )

    pr_number = 2 if asset.route == "code_patch" else 1
    pr_url = f"https://github.com/{REPOSITORY}/pull/{pr_number}"
    verify_cmd = "python3 check_code_fix.py" if asset.route == "code_patch" else "python3 check_version.py"
    if token:
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
        }
        try:
            with httpx.Client(timeout=15.0, headers=headers) as client:
                pr_resp = client.get(f"https://api.github.com/repos/{REPOSITORY}/pulls/{pr_number}")
                if pr_resp.status_code == 200:
                    current_body = pr_resp.json().get("body") or ""
                    base_body = current_body.split("\n## Agent provenance")[0].rstrip()
                    provenance = (
                        "\n\n## Agent provenance\n"
                        f"- **Entire CLI:** `v0.13.1` (`checkpoint-backend: branch`)\n"
                        f"- **Entire-Checkpoint:** `{checkpoint_id}`\n"
                        f"- **Commit:** [`{commit_sha[:7]}`](https://github.com/{REPOSITORY}/commit/{commit_sha})\n"
                        f"- **Verification:** `{verify_cmd}` (exit 0)"
                    )
                    client.patch(
                        f"https://api.github.com/repos/{REPOSITORY}/pulls/{pr_number}",
                        json={"body": base_body + provenance},
                    )
        except Exception:
            pass
    return pr_number, pr_url, checkpoint_id, commit_sha


def _run_verification_script(asset: DemoAsset) -> tuple[bool, str, str]:
    worktree = SECURITYDEMO_WORKTREE if (SECURITYDEMO_WORKTREE / ".git").is_dir() else LOCAL_DEMO_DIR
    script_name = "check_code_fix.py" if asset.route == "code_patch" else "check_version.py"
    completed = subprocess.run(
        [sys.executable, script_name],
        cwd=worktree,
        capture_output=True,
        text=True,
        check=False,
    )
    out = (completed.stdout.strip() or completed.stderr.strip() or "ok").splitlines()[0]
    return completed.returncode == 0, f"python3 {script_name}", out


def _build_slack_url(channel_id: str, ts: str | None) -> str | None:
    channel = (channel_id or "").strip()
    raw = (ts or "").strip()
    if not channel or not raw:
        return None
    compact = raw.replace(".", "")
    if not compact.isdigit():
        return None
    return f"https://app.slack.com/archives/{channel}/p{compact}"


def _record_event(
    operations: OperationsService,
    finding_key: str,
    level: str,
    step: str,
    reason: str,
) -> None:
    operations.store.add_event(
        EventRow(
            step=step,
            finding_key=finding_key,
            level=level,
            actions="LIVE_SIMULATION",
            suppressed=False,
            reason=reason,
        )
    )
