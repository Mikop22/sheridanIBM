from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

import httpx

from app.config import Settings
from app.operations.store import DeliveryRow, today_utc


@dataclass(frozen=True)
class Outbound:
    kind: str
    finding_key: str
    team: str
    delivered: bool
    mode: str
    external_id: str | None
    body: str
    detail: str

    def row(self) -> DeliveryRow:
        return DeliveryRow(
            kind=self.kind,
            finding_key=self.finding_key,
            team=self.team,
            delivered=self.delivered,
            mode=self.mode,
            external_id=self.external_id,
            body=self.body,
            detail=self.detail,
            created_on=today_utc(),
        )


class Delivery(Protocol):
    def create_jira(self, finding_key: str, team: str, summary: str, body: str) -> Outbound: ...

    def update_jira(self, finding_key: str, team: str, issue_key: str, body: str) -> Outbound: ...

    def post_slack(self, finding_key: str, team: str, kind: str, text: str) -> Outbound: ...


def local_issue_key(finding_key: str) -> str:
    return "REC-" + finding_key.replace("::", "-").replace("_", "-")


class RecordingDelivery:
    """Store the payload and do not call Slack or Jira."""

    def create_jira(self, finding_key: str, team: str, summary: str, body: str) -> Outbound:
        text = f"{summary}\n\n{body}"
        return Outbound(
            kind="jira_create",
            finding_key=finding_key,
            team=team,
            delivered=False,
            mode="recording",
            external_id=local_issue_key(finding_key),
            body=text,
            detail="Recorded locally. OPERATIONS_DELIVERY is not live.",
        )

    def update_jira(self, finding_key: str, team: str, issue_key: str, body: str) -> Outbound:
        return Outbound(
            kind="jira_update",
            finding_key=finding_key,
            team=team,
            delivered=False,
            mode="recording",
            external_id=issue_key,
            body=body,
            detail="Recorded locally. OPERATIONS_DELIVERY is not live.",
        )

    def post_slack(self, finding_key: str, team: str, kind: str, text: str) -> Outbound:
        return Outbound(
            kind=kind,
            finding_key=finding_key,
            team=team,
            delivered=False,
            mode="recording",
            external_id=None,
            body=text,
            detail="Recorded locally. OPERATIONS_DELIVERY is not live.",
        )


def adf(text: str) -> dict[str, object]:
    blocks: list[dict[str, object]] = []
    bullets: list[dict[str, object]] = []

    def flush_bullets() -> None:
        nonlocal bullets
        if bullets:
            blocks.append({"type": "bulletList", "content": bullets})
            bullets = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            flush_bullets()
            continue
        if line.startswith("## "):
            flush_bullets()
            blocks.append(
                {
                    "type": "heading",
                    "attrs": {"level": 3},
                    "content": [{"type": "text", "text": line[3:].strip()}],
                }
            )
        elif line.startswith("- "):
            bullets.append(
                {
                    "type": "listItem",
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": line[2:].strip()}],
                        }
                    ],
                }
            )
        else:
            flush_bullets()
            blocks.append(
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": line}],
                }
            )
    flush_bullets()
    if not blocks:
        blocks = [{"type": "paragraph", "content": [{"type": "text", "text": text}]}]
    return {
        "type": "doc",
        "version": 1,
        "content": blocks,
    }


class LiveDelivery:
    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None) -> None:
        self._settings = settings
        self._transport = transport

    def create_jira(self, finding_key: str, team: str, summary: str, body: str) -> Outbound:
        missing = _jira_missing(self._settings)
        if missing:
            return _blocked("jira_create", finding_key, team, f"{summary}\n\n{body}", missing)
        payload = {
            "fields": {
                "project": {"key": self._settings.jira_project_key},
                "summary": summary,
                "issuetype": {"name": self._settings.jira_issue_type},
                "description": adf(body),
            }
        }
        response = self._client().post("/rest/api/3/issue", json=payload)
        response.raise_for_status()
        key = str(response.json()["key"])
        return Outbound(
            kind="jira_create",
            finding_key=finding_key,
            team=team,
            delivered=True,
            mode="live",
            external_id=key,
            body=f"{summary}\n\n{body}",
            detail="Created in Jira.",
        )

    def update_jira(self, finding_key: str, team: str, issue_key: str, body: str) -> Outbound:
        missing = _jira_missing(self._settings)
        if missing:
            return _blocked("jira_update", finding_key, team, body, missing, issue_key)
        response = self._client().post(
            f"/rest/api/3/issue/{issue_key}/comment",
            json={"body": adf(body)},
        )
        response.raise_for_status()
        return Outbound(
            kind="jira_update",
            finding_key=finding_key,
            team=team,
            delivered=True,
            mode="live",
            external_id=issue_key,
            body=body,
            detail="Comment added in Jira.",
        )

    def post_slack(self, finding_key: str, team: str, kind: str, text: str) -> Outbound:
        webhook = self._settings.slack_webhook_url.strip()
        if webhook:
            response = httpx.post(webhook, json={"text": text}, timeout=20.0)
            response.raise_for_status()
            return Outbound(
                kind=kind,
                finding_key=finding_key,
                team=team,
                delivered=True,
                mode="live",
                external_id=None,
                body=text,
                detail="Posted to Slack via webhook.",
            )
        missing = _slack_cli_missing(self._settings)
        if missing:
            return _blocked(kind, finding_key, team, text, missing)
        payload = _post_via_slack_cli(self._settings, text)
        return Outbound(
            kind=kind,
            finding_key=finding_key,
            team=team,
            delivered=True,
            mode="live",
            external_id=str(payload.get("ts")) if payload.get("ts") else None,
            body=text,
            detail="Posted to Slack via the authenticated Slack CLI bot.",
        )

    def _client(self) -> httpx.Client:
        base = self._settings.jira_base_url.strip().rstrip("/")
        return httpx.Client(
            base_url=base,
            auth=(self._settings.jira_email, self._settings.jira_api_token),
            transport=self._transport,
            timeout=20.0,
        )


def build_delivery(settings: Settings) -> Delivery:
    if settings.operations_delivery == "live":
        return LiveDelivery(settings)
    return RecordingDelivery()


def _jira_missing(settings: Settings) -> list[str]:
    pairs = (
        ("JIRA_BASE_URL", settings.jira_base_url),
        ("JIRA_EMAIL", settings.jira_email),
        ("JIRA_API_TOKEN", settings.jira_api_token),
        ("JIRA_PROJECT_KEY", settings.jira_project_key),
    )
    missing = [name for name, value in pairs if not value.strip()]
    if settings.jira_base_url.strip():
        parsed = urlsplit(settings.jira_base_url.strip())
        if parsed.scheme != "https" or not parsed.hostname:
            missing.append("JIRA_BASE_URL")
    return missing


def _slack_cli_missing(settings: Settings) -> list[str]:
    pairs = (
        ("SLACK_CHANNEL_ID", settings.slack_channel_id),
        ("SLACK_APP_ID", settings.slack_app_id),
        ("SLACK_TEAM_ID", settings.slack_team_id),
    )
    missing = [name for name, value in pairs if not value.strip()]
    if not _resolve_slack_cli(settings):
        missing.append("SLACK_CLI_PATH")
    return missing


def _resolve_slack_cli(settings: Settings) -> str | None:
    configured = settings.slack_cli_path.strip()
    if configured:
        path = Path(configured)
        return str(path) if path.is_file() else None
    default = Path.home() / ".slack" / "bin" / "slack"
    if default.is_file():
        return str(default)
    return shutil.which("slack")


def _slack_project_dir() -> Path | None:
    candidate = Path(__file__).resolve().parents[3] / "signalzero-slack"
    if (candidate / ".slack" / "apps.dev.json").is_file():
        return candidate
    return None


def _post_via_slack_cli(settings: Settings, text: str) -> dict[str, object]:
    command = [
        _resolve_slack_cli(settings) or "slack",
        "api",
        "chat.postMessage",
        f"channel={settings.slack_channel_id.strip()}",
        f"text={text}",
        f"--app={settings.slack_app_id.strip()}",
        f"--team={settings.slack_team_id.strip()}",
        "--skip-update",
    ]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
        cwd=_slack_project_dir(),
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "slack cli failed"
        raise RuntimeError(detail)
    payload = json.loads(completed.stdout)
    if not payload.get("ok"):
        raise RuntimeError(str(payload.get("error") or payload))
    return payload


def _blocked(
    kind: str,
    finding_key: str,
    team: str,
    body: str,
    missing: list[str],
    external_id: str | None = None,
) -> Outbound:
    return Outbound(
        kind=kind,
        finding_key=finding_key,
        team=team,
        delivered=False,
        mode="blocked",
        external_id=external_id,
        body=body,
        detail="Missing " + ", ".join(missing) + ".",
    )
