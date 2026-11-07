from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from typing import Any

from scipy.sparse import csr_matrix
from sklearn import __version__ as sklearn_version
from sklearn.feature_extraction.text import HashingVectorizer

SUPPORTED_TEXT_FIELDS = (
    "vulnerability_description",
    "vendor_description",
    "product_description",
)

PROHIBITED_FIELDS = frozenset(
    {
        "exploitation_observed",
        "exploitation_status",
        "exploited",
        "future_exploitation",
        "known_exploited",
        "label",
        "outcome",
        "post_snapshot_data",
        "post_snapshot_observations",
        "prediction_label",
        "rank",
        "remediation",
        "remediation_outcome",
        "risk_score",
        "score",
        "target",
    }
)

_TOKEN_PATTERN = re.compile(r"(?u)\b\w\w+\b")


class ProhibitedFeatureFieldError(ValueError):
    def __init__(self, record_index: int, fields: list[str]) -> None:
        self.record_index = record_index
        self.fields = fields
        super().__init__(
            f"record {record_index} contains prohibited feature fields: {', '.join(fields)}"
        )


@dataclass(frozen=True)
class TextHashingConfig:
    n_features: int = 4096

    def __post_init__(self) -> None:
        if self.n_features < 1:
            raise ValueError("n_features must be positive")


@dataclass(frozen=True)
class FeatureMetadata:
    feature_kind: str
    algorithm: str
    library_version: str
    feature_version: str
    dimensions: int
    supported_fields: tuple[str, ...]
    ngram_range: tuple[int, int]
    normalization: str
    alternate_sign: bool
    dtype: str
    requires_fit: bool

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _split_prepared_tokens(document: str) -> list[str]:
    return document.split()


class TextHashingTransformer:
    """Deterministic, stateless sparse text features for pre-prediction fields."""

    def __init__(self, config: TextHashingConfig | None = None) -> None:
        self.config = config or TextHashingConfig()
        self.metadata = FeatureMetadata(
            feature_kind="hashed_text_features",
            algorithm="sklearn.feature_extraction.text.HashingVectorizer",
            library_version=sklearn_version,
            feature_version="1.0",
            dimensions=self.config.n_features,
            supported_fields=SUPPORTED_TEXT_FIELDS,
            ngram_range=(1, 2),
            normalization="l2",
            alternate_sign=False,
            dtype="float64",
            requires_fit=False,
        )
        self._vectorizer = HashingVectorizer(
            n_features=self.config.n_features,
            analyzer=_split_prepared_tokens,
            alternate_sign=False,
            norm="l2",
            lowercase=False,
        )

    def transform(self, records: Iterable[Mapping[str, object]]) -> csr_matrix:
        prepared = [self._prepare_record(record, index) for index, record in enumerate(records)]
        if not prepared:
            return self._vectorizer.transform([""])[:0].tocsr()
        return self._vectorizer.transform(prepared).tocsr()

    @staticmethod
    def _prepare_record(record: Mapping[str, object], index: int) -> str:
        if not isinstance(record, Mapping):
            raise TypeError(f"record {index} must be a mapping")

        prohibited = sorted(
            str(field) for field in record if str(field).casefold() in PROHIBITED_FIELDS
        )
        if prohibited:
            raise ProhibitedFeatureFieldError(index, prohibited)

        prepared_tokens: list[str] = []
        for field in SUPPORTED_TEXT_FIELDS:
            value = record.get(field)
            if value is None:
                continue
            if not isinstance(value, str):
                raise TypeError(f"record {index} field {field!r} must be text or null")
            normalized = unicodedata.normalize("NFKC", value).casefold()
            tokens = _TOKEN_PATTERN.findall(normalized)
            prepared_tokens.extend(f"{field}__{token}" for token in tokens)
            prepared_tokens.extend(
                f"{field}__{left}_{right}" for left, right in zip(tokens, tokens[1:], strict=False)
            )
        return " ".join(prepared_tokens)
