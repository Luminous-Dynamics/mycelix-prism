#!/usr/bin/env python3
"""Fail-closed static policy checks for GitHub Actions workflow files.

Uses only Python's standard library so this guard runs before Nix or Cargo.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

USES_RE = re.compile(r"^\s*(?:-\s*)?uses\s*:\s*([^\s#]+)")
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
DOCKER_DIGEST_RE = re.compile(r"^.+@sha256:[0-9a-fA-F]{64}$")
VERSION_COMMENT_RE = re.compile(r"#\s*v\d[^\s]*\s*$")


def validate_action_reference(reference: str, source_line: str) -> list[str]:
    """Validate a single action reference; local actions are tied to this tree."""
    if reference.startswith("./"):
        return []

    if reference.startswith("docker://"):
        image = reference[len("docker://") :]
        if not DOCKER_DIGEST_RE.fullmatch(image):
            return [f"Docker action must be pinned by sha256 digest: {reference}"]
        return []

    if "@" not in reference:
        return [f"action reference has no immutable commit SHA: {reference}"]

    _action, revision = reference.rsplit("@", 1)
    if not SHA_RE.fullmatch(revision):
        return [f"action revision must be a full 40-character commit SHA: {reference}"]

    if not VERSION_COMMENT_RE.search(source_line):
        return [
            f"pinned action must include a trailing human-readable version comment: {reference}"
        ]
    return []


def parse_top_level_permissions(content: str) -> dict[str, str] | None:
    """Read a simple top-level YAML permissions mapping without third-party deps."""
    lines = content.splitlines()
    for index, line in enumerate(lines):
        if line != "permissions:":
            continue

        permissions: dict[str, str] = {}
        for child in lines[index + 1 :]:
            if not child.strip():
                continue
            if not child.startswith(" "):
                break
            match = re.fullmatch(r"  ([a-z][a-z0-9_-]*):\s*([a-z]+)\s*(?:#.*)?", child)
            if not match:
                return None
            key, value = match.groups()
            if key in permissions:
                return None
            permissions[key] = value
        return permissions
    return None


def validate_workflow_text(path_label: str, content: str) -> list[str]:
    errors: list[str] = []
    found_actions = 0

    for line_number, line in enumerate(content.splitlines(), start=1):
        match = USES_RE.match(line)
        if not match:
            continue
        found_actions += 1
        for error in validate_action_reference(match.group(1), line):
            errors.append(f"{path_label}:{line_number}: {error}")

    if found_actions == 0:
        errors.append(f"{path_label}: no uses: references found; refusing an empty policy scan")

    permissions = parse_top_level_permissions(content)
    if permissions != {"contents": "read"}:
        errors.append(
            f"{path_label}: top-level permissions must be exactly "
            f"'contents: read'; found {permissions!r}"
        )

    return errors


def check_tree(root: Path) -> list[str]:
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.is_dir():
        return [f"{workflow_dir}: workflow directory does not exist"]

    workflows = sorted(
        path
        for path in workflow_dir.iterdir()
        if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}
    )
    if not workflows:
        return [f"{workflow_dir}: no workflow YAML files found"]

    errors: list[str] = []
    for path in workflows:
        try:
            content = path.read_text(encoding="utf-8")
        except OSError as error:
            errors.append(f"{path}: cannot read workflow: {error}")
            continue
        errors.extend(validate_workflow_text(str(path.relative_to(root)), content))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="repository root")
    args = parser.parse_args()

    errors = check_tree(args.root.resolve())
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"Workflow policy failed with {len(errors)} finding(s).", file=sys.stderr)
        return 1

    print("Workflow policy passed: all action references are immutable and permissions are least-privilege.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
