from __future__ import annotations

from pathlib import Path

import pytest

from portal.config_loader import ConfigLoadError, load_profile, resolve_config_path

ROOT = Path(__file__).resolve().parents[1] / "configs"


def test_valid_profile_loads_default_yaml() -> None:
    text = load_profile(ROOT, "default")
    assert "customer-portal" in text
    assert "billing: false" in text


def test_valid_profile_loads_prod_yaml() -> None:
    text = load_profile(ROOT, "prod")
    assert "billing: true" in text


def test_traversal_with_parent_segments_is_rejected() -> None:
    with pytest.raises(ConfigLoadError):
        resolve_config_path(ROOT, "../outside")


def test_traversal_that_targets_secret_fixture_cannot_be_read() -> None:
    with pytest.raises(ConfigLoadError):
        load_profile(ROOT, "../outside")


def test_absolute_profile_is_rejected() -> None:
    with pytest.raises(ConfigLoadError):
        resolve_config_path(ROOT, str(ROOT / "default"))


def test_null_byte_profile_is_rejected() -> None:
    with pytest.raises(ConfigLoadError):
        resolve_config_path(ROOT, "default\x00../outside")


def test_resolved_path_stays_inside_config_root(tmp_path: Path) -> None:
    config_root = tmp_path / "configs"
    config_root.mkdir()
    (config_root / "default.yml").write_text("ok: true\n", encoding="utf-8")
    outside = tmp_path / "outside.yml"
    outside.write_text("leak\n", encoding="utf-8")

    path = resolve_config_path(config_root, "default")
    assert path.resolve().is_relative_to(config_root.resolve())
    assert path.read_text(encoding="utf-8") == "ok: true\n"

    with pytest.raises(ConfigLoadError):
        load_profile(config_root, "../outside")
