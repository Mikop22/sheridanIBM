"""Fail until spring-cloud-config-server is pinned to the patched 4.3 line."""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

REQUIRED = "4.3.2"
ARTIFACT = "spring-cloud-config-server"


def dependency_version(pom: Path) -> str:
    root = ET.parse(pom).getroot()
    for dependency in root.iter():
        if not dependency.tag.endswith("dependency"):
            continue
        artifact = ""
        version = ""
        for child in list(dependency):
            if child.tag.endswith("artifactId"):
                artifact = (child.text or "").strip()
            if child.tag.endswith("version"):
                version = (child.text or "").strip()
        if artifact == ARTIFACT:
            return version
    return ""


def main() -> int:
    pom = Path(__file__).resolve().parent / "pom.xml"
    version = dependency_version(pom)
    if version != REQUIRED:
        print(
            f"{ARTIFACT} is {version or 'missing'}; advisory GHSA-3qwq-q9vm-5j42 requires {REQUIRED}",
            file=sys.stderr,
        )
        return 1
    print(f"{ARTIFACT} is {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
