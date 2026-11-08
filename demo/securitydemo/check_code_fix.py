"""Acceptance gate for the first-party config-loader remediation."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main() -> int:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "portal/tests"],
        cwd=ROOT,
        env=env,
        check=False,
    )
    if completed.returncode != 0:
        print(
            "portal config loader tests failed; rewrite resolve_config_path so "
            "profiles cannot escape portal/configs",
            file=sys.stderr,
        )
        return completed.returncode
    print("portal config loader tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
