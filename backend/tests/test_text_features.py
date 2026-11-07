from __future__ import annotations

import json
from pathlib import Path

import pytest
from scipy.sparse import vstack

from app.features import (
    ProhibitedFeatureFieldError,
    TextHashingConfig,
    TextHashingTransformer,
)

BACKEND_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def text_records() -> list[dict]:
    path = BACKEND_ROOT / "tests/fixtures/text-feature-records.synthetic.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_feature_generation_is_deterministic_and_fixed_dimension(text_records: list[dict]) -> None:
    transformer = TextHashingTransformer(TextHashingConfig(n_features=256))

    first = transformer.transform(text_records)
    second = transformer.transform(text_records)

    assert first.shape == (2, 256)
    assert (first != second).nnz == 0
    assert transformer.metadata.dimensions == 256
    assert transformer.metadata.feature_kind == "hashed_text_features"
    assert transformer.metadata.requires_fit is False
    assert transformer.metadata.library_version
    assert TextHashingTransformer().metadata.dimensions == 4096


def test_known_configuration_has_stable_feature_positions() -> None:
    transformer = TextHashingTransformer(TextHashingConfig(n_features=64))

    matrix = transformer.transform([{"vulnerability_description": "synthetic token"}])

    assert matrix.indices.tolist() == [7, 15, 48]
    assert matrix.data.tolist() == pytest.approx([1 / 3**0.5] * 3)


def test_input_order_is_preserved(text_records: list[dict]) -> None:
    transformer = TextHashingTransformer(TextHashingConfig(n_features=128))

    forward = transformer.transform(text_records)
    reverse = transformer.transform(reversed(text_records))

    assert (forward[0] != reverse[1]).nnz == 0
    assert (forward[1] != reverse[0]).nnz == 0


def test_missing_and_empty_text_produce_zero_rows() -> None:
    transformer = TextHashingTransformer(TextHashingConfig(n_features=64))

    matrix = transformer.transform(
        [
            {},
            {"vulnerability_description": None},
            {
                "vulnerability_description": "  ",
                "vendor_description": "",
                "product_description": "\t",
            },
        ]
    )

    assert matrix.shape == (3, 64)
    assert matrix.nnz == 0
    assert transformer.transform([]).shape == (0, 64)


def test_batched_and_individual_transformations_match(text_records: list[dict]) -> None:
    transformer = TextHashingTransformer(TextHashingConfig(n_features=128))

    batched = transformer.transform(text_records)
    individual = vstack([transformer.transform([record]) for record in text_records]).tocsr()

    assert (batched != individual).nnz == 0


def test_configuration_is_reproducible_across_instances(text_records: list[dict]) -> None:
    config = TextHashingConfig(n_features=512)

    first = TextHashingTransformer(config)
    second = TextHashingTransformer(config)

    assert (first.transform(text_records) != second.transform(text_records)).nnz == 0
    assert first.metadata.as_dict() == second.metadata.as_dict()


@pytest.mark.parametrize(
    "field",
    [
        "label",
        "score",
        "future_exploitation",
        "exploitation_observed",
        "remediation_outcome",
        "post_snapshot_data",
    ],
)
def test_prohibited_leakage_fields_are_rejected(field: str) -> None:
    transformer = TextHashingTransformer()

    with pytest.raises(ProhibitedFeatureFieldError, match=field):
        transformer.transform(
            [{"vulnerability_description": "Synthetic description.", field: "synthetic-target"}]
        )


def test_unknown_non_feature_fields_are_ignored() -> None:
    transformer = TextHashingTransformer(TextHashingConfig(n_features=128))
    baseline = {"vulnerability_description": "Synthetic description."}

    first = transformer.transform([baseline])
    second = transformer.transform([{**baseline, "record_id": "synthetic-record-001"}])

    assert (first != second).nnz == 0


def test_supported_fields_are_field_namespaced() -> None:
    transformer = TextHashingTransformer(TextHashingConfig(n_features=1024))

    vulnerability = transformer.transform([{"vulnerability_description": "synthetic token"}])
    product = transformer.transform([{"product_description": "synthetic token"}])

    assert (vulnerability != product).nnz > 0


def test_non_text_supported_value_is_rejected() -> None:
    transformer = TextHashingTransformer()

    with pytest.raises(TypeError, match="must be text or null"):
        transformer.transform([{"vendor_description": 42}])
