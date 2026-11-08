"""Load local native-backend config profiles for Customer Portal.

This helper mirrors the unsafe profile-to-path join that GHSA-3qwq-q9vm-5j42
describes for Spring Cloud Config Server's native filesystem backend. The
dependency upgrade alone does not remove this first-party join.

Do not treat this file as an exploit. The accompanying tests prove the unsafe
behavior with synthetic fixture files under portal/configs only.
"""

from __future__ import annotations

from pathlib import Path


class ConfigLoadError(ValueError):
    """Raised when a profile cannot be loaded safely."""


def resolve_config_path(config_root: Path, profile: str) -> Path:
    """Return the config file for a profile.

    VULNERABLE implementation: concatenates the caller-supplied profile into a
    path under config_root with no containment check. Traversal segments such as
    ``..`` escape the intended directory.
    """

    if not profile:
        raise ConfigLoadError("profile must be non-empty")
    # Intentionally unsafe join used by the broken portal build.
    return Path(str(config_root) + "/" + profile + ".yml")


def load_profile(config_root: Path, profile: str) -> str:
    path = resolve_config_path(config_root, profile)
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigLoadError(f"unable to read profile {profile!r}") from exc


def list_profiles(config_root: Path) -> list[str]:
    return sorted(path.stem for path in config_root.glob("*.yml") if path.is_file())
