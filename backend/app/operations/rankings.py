from __future__ import annotations

import html
import json
from dataclasses import dataclass
from pathlib import Path

SCOREBOARD_ROWS = 72_670
SUMMARY_KEY = "top_25_predictions_2026"


def default_summary_path() -> Path:
    return Path(__file__).resolve().parents[3] / "model" / "results" / "submission_v1_summary.json"


def format_score(score: float) -> str:
    return f"{score:.6f}".rstrip("0").rstrip(".")


@dataclass(frozen=True)
class RankingRow:
    cve_id: str
    published: str
    snapshot_month: str
    ranking_score: float
    rank: int
    description: str | None = None

    @property
    def population_percentile(self) -> float:
        """Share of the scoreboard ranked strictly below this row.

        The saved file is the head of the full scoreboard sort, so this rank is
        the rank among all 72,670 rows. It is not a within-month percentile.
        """

        return (SCOREBOARD_ROWS - self.rank) / SCOREBOARD_ROWS


class RankingCatalog:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_summary_path()

    def load(self) -> list[RankingRow]:
        if not self.path.is_file():
            raise FileNotFoundError(f"ranking summary not found: {self.path}")
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        rows = payload[SUMMARY_KEY]
        return [
            RankingRow(
                cve_id=row["cve_id"],
                published=row["published"],
                snapshot_month=row["snapshot_month"],
                ranking_score=float(row["score_v1_ensemble"]),
                rank=index,
                description=(
                    html.unescape(str(row["description"])).replace("\xa0", " ").strip()
                    if row.get("description")
                    else None
                ),
            )
            for index, row in enumerate(rows, start=1)
        ]

    def get(self, cve_id: str) -> RankingRow:
        matches = [row for row in self.load() if row.cve_id == cve_id]
        if not matches:
            raise KeyError(cve_id)
        return matches[0]
