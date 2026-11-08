from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


@dataclass(frozen=True)
class FindingRow:
    finding_key: str
    cve_id: str
    asset_id: str
    level: str
    jira_issue_key: str | None
    urgent_notified: bool
    review_notified: bool
    evidence_hash: str
    team: str
    route: str
    urgent: bool


@dataclass(frozen=True)
class DeliveryRow:
    kind: str
    finding_key: str
    team: str
    delivered: bool
    mode: str
    external_id: str | None
    body: str
    detail: str
    created_on: str


@dataclass(frozen=True)
class JobRow:
    finding_key: str
    status: str
    branch: str
    repository: str
    task: str
    pr_url: str | None
    checks_passed: bool | None


@dataclass(frozen=True)
class EventRow:
    step: str
    finding_key: str
    level: str
    actions: str
    suppressed: bool
    reason: str


class OperationsStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS findings (
                finding_key TEXT PRIMARY KEY,
                cve_id TEXT NOT NULL,
                asset_id TEXT NOT NULL,
                level TEXT NOT NULL,
                jira_issue_key TEXT,
                urgent_notified INTEGER NOT NULL,
                review_notified INTEGER NOT NULL,
                evidence_hash TEXT NOT NULL,
                team TEXT NOT NULL,
                route TEXT NOT NULL,
                urgent INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS deliveries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                finding_key TEXT NOT NULL,
                team TEXT NOT NULL,
                delivered INTEGER NOT NULL,
                mode TEXT NOT NULL,
                external_id TEXT,
                body TEXT NOT NULL,
                detail TEXT NOT NULL,
                created_on TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS jobs (
                finding_key TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                branch TEXT NOT NULL,
                repository TEXT NOT NULL,
                task TEXT NOT NULL,
                pr_url TEXT,
                checks_passed INTEGER
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                step TEXT NOT NULL,
                finding_key TEXT NOT NULL,
                level TEXT NOT NULL,
                actions TEXT NOT NULL,
                suppressed INTEGER NOT NULL,
                reason TEXT NOT NULL
            );
            """
        )
        return connection

    def get_finding(self, finding_key: str) -> FindingRow | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM findings WHERE finding_key = ?",
                (finding_key,),
            ).fetchone()
        return _finding(row) if row is not None else None

    def save_finding(self, finding: FindingRow) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO findings (
                    finding_key, cve_id, asset_id, level, jira_issue_key,
                    urgent_notified, review_notified, evidence_hash, team, route, urgent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(finding_key) DO UPDATE SET
                    level = excluded.level,
                    jira_issue_key = excluded.jira_issue_key,
                    urgent_notified = excluded.urgent_notified,
                    review_notified = excluded.review_notified,
                    evidence_hash = excluded.evidence_hash,
                    team = excluded.team,
                    route = excluded.route,
                    urgent = excluded.urgent
                """,
                (
                    finding.finding_key,
                    finding.cve_id,
                    finding.asset_id,
                    finding.level,
                    finding.jira_issue_key,
                    int(finding.urgent_notified),
                    int(finding.review_notified),
                    finding.evidence_hash,
                    finding.team,
                    finding.route,
                    int(finding.urgent),
                ),
            )

    def add_delivery(self, delivery: DeliveryRow) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO deliveries (
                    kind, finding_key, team, delivered, mode, external_id, body, detail, created_on
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    delivery.kind,
                    delivery.finding_key,
                    delivery.team,
                    int(delivery.delivered),
                    delivery.mode,
                    delivery.external_id,
                    delivery.body,
                    delivery.detail,
                    delivery.created_on,
                ),
            )

    def count_deliveries(self, team: str, kind: str, created_on: str) -> int:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS n FROM deliveries
                WHERE team = ? AND kind = ? AND created_on = ? AND mode != 'blocked'
                """,
                (team, kind, created_on),
            ).fetchone()
        return int(row["n"])

    def list_deliveries(self) -> list[DeliveryRow]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM deliveries ORDER BY id"
            ).fetchall()
        return [_delivery(row) for row in rows]

    def get_job(self, finding_key: str) -> JobRow | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM jobs WHERE finding_key = ?",
                (finding_key,),
            ).fetchone()
        return _job(row) if row is not None else None

    def save_job(self, job: JobRow) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO jobs (
                    finding_key, status, branch, repository, task, pr_url, checks_passed
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(finding_key) DO UPDATE SET
                    status = excluded.status,
                    branch = excluded.branch,
                    repository = excluded.repository,
                    task = excluded.task,
                    pr_url = excluded.pr_url,
                    checks_passed = excluded.checks_passed
                """,
                (
                    job.finding_key,
                    job.status,
                    job.branch,
                    job.repository,
                    job.task,
                    job.pr_url,
                    None if job.checks_passed is None else int(job.checks_passed),
                ),
            )

    def list_jobs(self) -> list[JobRow]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM jobs ORDER BY finding_key").fetchall()
        return [_job(row) for row in rows]

    def add_event(self, event: EventRow) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO events (step, finding_key, level, actions, suppressed, reason)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    event.step,
                    event.finding_key,
                    event.level,
                    event.actions,
                    int(event.suppressed),
                    event.reason,
                ),
            )

    def list_findings(self) -> list[FindingRow]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM findings ORDER BY finding_key").fetchall()
        return [_finding(row) for row in rows]


def today_utc() -> str:
    return datetime.now(UTC).date().isoformat()


def _finding(row: sqlite3.Row) -> FindingRow:
    return FindingRow(
        finding_key=row["finding_key"],
        cve_id=row["cve_id"],
        asset_id=row["asset_id"],
        level=row["level"],
        jira_issue_key=row["jira_issue_key"],
        urgent_notified=bool(row["urgent_notified"]),
        review_notified=bool(row["review_notified"]),
        evidence_hash=row["evidence_hash"],
        team=row["team"],
        route=row["route"],
        urgent=bool(row["urgent"]),
    )


def _delivery(row: sqlite3.Row) -> DeliveryRow:
    return DeliveryRow(
        kind=row["kind"],
        finding_key=row["finding_key"],
        team=row["team"],
        delivered=bool(row["delivered"]),
        mode=row["mode"],
        external_id=row["external_id"],
        body=row["body"],
        detail=row["detail"],
        created_on=row["created_on"],
    )


def _job(row: sqlite3.Row) -> JobRow:
    checks = row["checks_passed"]
    return JobRow(
        finding_key=row["finding_key"],
        status=row["status"],
        branch=row["branch"],
        repository=row["repository"],
        task=row["task"],
        pr_url=row["pr_url"],
        checks_passed=None if checks is None else bool(checks),
    )
