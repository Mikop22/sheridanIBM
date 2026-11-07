from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from app.domain.contracts import (
    DecisionAction,
    EventProcessingOutcome,
    RecommendationDecision,
    RecommendationStatus,
    RemediationRecommendation,
)
from app.domain.errors import (
    EventAlreadyExistsError,
    EventNotFoundError,
    InvalidRecommendationTransitionError,
    RecommendationNotFoundError,
)


@dataclass(frozen=True)
class StoredEvent:
    fingerprint: str
    outcome: EventProcessingOutcome


class SecurityEventRepository:
    """Minimal SQLite persistence for idempotency, workflow state, and audit history."""

    def __init__(self, database_path: Path) -> None:
        self._database_path = database_path
        database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    fingerprint TEXT NOT NULL,
                    prediction_id TEXT NOT NULL,
                    outcome_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS recommendations (
                    recommendation_id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL UNIQUE REFERENCES events(event_id),
                    prediction_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    recommendation_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS recommendations_prediction_idx
                    ON recommendations(prediction_id);
                CREATE TABLE IF NOT EXISTS recommendation_audit (
                    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recommendation_id TEXT NOT NULL REFERENCES recommendations(recommendation_id),
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    recorded_at TEXT NOT NULL
                );
                """
            )

    def find_event(self, event_id: str) -> StoredEvent | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT fingerprint, outcome_json FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
        if row is None:
            return None
        return StoredEvent(
            fingerprint=row["fingerprint"],
            outcome=EventProcessingOutcome.model_validate_json(row["outcome_json"]),
        )

    def get_event(self, event_id: str) -> EventProcessingOutcome:
        stored = self.find_event(event_id)
        if stored is None:
            raise EventNotFoundError(event_id)
        return stored.outcome

    def record_event(
        self,
        fingerprint: str,
        outcome: EventProcessingOutcome,
        recommendation: RemediationRecommendation | None,
    ) -> EventProcessingOutcome:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT fingerprint, outcome_json FROM events WHERE event_id = ?",
                (outcome.event_id,),
            ).fetchone()
            if existing is not None:
                if existing["fingerprint"] != fingerprint:
                    raise EventAlreadyExistsError(outcome.event_id)
                return EventProcessingOutcome.model_validate_json(existing["outcome_json"])

            connection.execute(
                """
                INSERT INTO events(event_id, fingerprint, prediction_id, outcome_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    outcome.event_id,
                    fingerprint,
                    outcome.prediction_id,
                    outcome.model_dump_json(),
                    outcome.processed_at.isoformat(),
                ),
            )
            if recommendation is not None:
                connection.execute(
                    """
                    INSERT INTO recommendations(
                        recommendation_id, event_id, prediction_id, status, recommendation_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        recommendation.recommendation_id,
                        recommendation.event_id,
                        recommendation.prediction_id,
                        recommendation.workflow_status.value,
                        recommendation.model_dump_json(),
                    ),
                )
            return outcome

    def list_recommendations(self, prediction_id: str) -> list[RemediationRecommendation]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT recommendation_json FROM recommendations
                WHERE prediction_id = ? ORDER BY recommendation_id
                """,
                (prediction_id,),
            ).fetchall()
        return [
            RemediationRecommendation.model_validate_json(row["recommendation_json"])
            for row in rows
        ]

    def decide(
        self, recommendation_id: str, decision: RecommendationDecision
    ) -> RemediationRecommendation:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT status, recommendation_json FROM recommendations
                WHERE recommendation_id = ?
                """,
                (recommendation_id,),
            ).fetchone()
            if row is None:
                raise RecommendationNotFoundError(recommendation_id)
            if row["status"] != RecommendationStatus.PENDING_APPROVAL.value:
                raise InvalidRecommendationTransitionError(recommendation_id, row["status"])

            recommendation = RemediationRecommendation.model_validate_json(
                row["recommendation_json"]
            )
            decided_at = datetime.now(UTC)
            status = (
                RecommendationStatus.APPROVED
                if decision.action is DecisionAction.APPROVE
                else RecommendationStatus.REJECTED
            )
            updated = recommendation.model_copy(
                update={
                    "workflow_status": status,
                    "decided_at": decided_at,
                    "decided_by": decision.actor,
                    "decision_reason": decision.reason,
                }
            )
            connection.execute(
                """
                UPDATE recommendations SET status = ?, recommendation_json = ?
                WHERE recommendation_id = ?
                """,
                (status.value, updated.model_dump_json(), recommendation_id),
            )
            connection.execute(
                """
                INSERT INTO recommendation_audit(
                    recommendation_id, action, actor, reason, recorded_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    recommendation_id,
                    decision.action.value,
                    decision.actor,
                    decision.reason,
                    decided_at.isoformat(),
                ),
            )
            return updated
