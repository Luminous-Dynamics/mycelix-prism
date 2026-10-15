#!/usr/bin/env python3
"""Fail on explicit Cargo wildcard version requirements (CI policy helper).

Path-only workspace dependencies have no version requirement; they are not an
explicit wildcard. cargo-deny's native wildcard rule cannot distinguish that case
for this workspace, so this small stdlib-only check enforces the intended policy.
"""
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path
from typing import Any

DEPENDENCY_TABLES = {"dependencies", "dev-dependencies", "build-dependencies"}
WILDCARD_VERSION = re.compile(r"(?:^|[.\s])(?:\*|[xX])(?=$|[.\s])")


def collect_wildcards(value: Any, location: str = "") -> list[str]:
    findings: list[str] = []
    if not isinstance(value, dict):
        return findings

    for table_name, table in value.items():
        child_location = f"{location}.{table_name}" if location else table_name
        if table_name in DEPENDENCY_TABLES and isinstance(table, dict):
            for dependency_name, specification in table.items():
                version: str | None
                if isinstance(specification, str):
                    version = specification
                elif isinstance(specification, dict):
                    candidate = specification.get("version")
                    version = candidate if isinstance(candidate, str) else None
                else:
                    version = None

                if version is not None and WILDCARD_VERSION.search(version.strip()):
                    findings.append(
                        f"{child_location}.{dependency_name}: wildcard version {version!r}"
                    )

        if isinstance(table, dict):
            findings.extend(collect_wildcards(table, child_location))

    return findings


def self_test() -> None:
    accepted = {
        "dependencies": {
            "serde": "1",
            "local-crate": {"path": "../local-crate"},
            "workspace-crate": {"workspace": True},
        },
        "workspace": {"dependencies": {"tokio": "1"}},
    }
    rejected = {
        "dependencies": {
            "any-version": "*",
            "minor-wildcard": {"version": "1.*"},
            "x-wildcard": {"version": "0.4.x"},
        }
    }
    assert collect_wildcards(accepted) == [], "valid fixture was rejected"
    assert len(collect_wildcards(rejected)) == 3, "negative fixture was not rejected"


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        self_test()
        print("Cargo wildcard policy positive/negative fixtures passed.")
        return 0

    root = Path.cwd()
    manifests = sorted(path for path in root.rglob("Cargo.toml")
                       if not {".git", "target", ".direnv"}.intersection(path.parts))
    findings: list[str] = []
    for manifest in manifests:
        try:
            data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as error:
            print(f"unable to parse {manifest}: {error}", file=sys.stderr)
            return 2
        relative = manifest.relative_to(root).as_posix()
        findings.extend(f"{relative}: {finding}" for finding in collect_wildcards(data))

    if findings:
        print("Explicit wildcard Cargo version requirements are forbidden:", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding}", file=sys.stderr)
        return 1

    print(f"Cargo wildcard policy passed: inspected {len(manifests)} Cargo.toml manifests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
