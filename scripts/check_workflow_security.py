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
JOB_RE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
UNSAFE_TRIGGER_PATTERNS = (
    re.compile(r"^\s*(?:-\s*)?['\"]?pull_request_target['\"]?\s*(?::|,|\]|$)"),
    re.compile(r"^\s*on\s*:\s*.*\bpull_request_target\b"),
)
KEY_VALUE_RE = re.compile(r"^\s*([a-z][a-z0-9_-]*):\s*([a-z]+)\s*(?:#.*)?$")

# The one temporary writer lane is intentionally exceptional and tightly gated.
LOCK_RECOVERY_JOB = "generate_lockfile"
LOCK_RECOVERY_PERMISSIONS = {"contents": "write", "statuses": "write"}
LOCK_RECOVERY_GATES = (
    "github.event_name == 'pull_request'",
    "github.head_ref == 'fix/proxy-dns-pinning-redirects-20261010'",
    "github.event.pull_request.head.repo.full_name == github.repository",
    "github.event_name == 'push'",
    "github.ref == 'refs/heads/fix/proxy-dns-pinning-redirects-20261010'",
)


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


def parse_permissions_mapping(lines: list[str], index: int, indent: int) -> dict[str, str] | None:
    """Parse a simple permissions mapping at an exact YAML indentation."""
    permissions: dict[str, str] = {}
    child_indent = indent + 2

    for child in lines[index + 1 :]:
        if not child.strip():
            continue
        current_indent = len(child) - len(child.lstrip(" "))
        if current_indent <= indent:
            break
        if current_indent != child_indent:
            return None
        match = KEY_VALUE_RE.fullmatch(child)
        if not match:
            return None
        key, value = match.groups()
        if key in permissions:
            return None
        permissions[key] = value

    return permissions


def parse_top_level_permissions(content: str) -> dict[str, str] | None:
    lines = content.splitlines()
    for index, line in enumerate(lines):
        if line == "permissions:":
            return parse_permissions_mapping(lines, index, indent=0)
    return None


def iter_job_blocks(lines: list[str]) -> list[tuple[str, list[str]]]:
    """Return simple top-level job blocks without needing a third-party YAML parser."""
    jobs_index = next((i for i, line in enumerate(lines) if line == "jobs:"), None)
    if jobs_index is None:
        return []

    blocks: list[tuple[str, list[str]]] = []
    active_name: str | None = None
    active_lines: list[str] = []

    for line in lines[jobs_index + 1 :]:
        if line.strip() and not line.startswith(" "):
            break
        match = JOB_RE.fullmatch(line)
        if match:
            if active_name is not None:
                blocks.append((active_name, active_lines))
            active_name = match.group(1)
            active_lines = [line]
        elif active_name is not None:
            active_lines.append(line)

    if active_name is not None:
        blocks.append((active_name, active_lines))
    return blocks


def validate_job_permissions(path_label: str, content: str) -> list[str]:
    lines = content.splitlines()
    errors: list[str] = []

    for job_name, block in iter_job_blocks(lines):
        permission_indices = [
            i for i, line in enumerate(block)
            if re.match(r"^ {4}permissions\s*:", line)
        ]
        if not permission_indices:
            continue
        if len(permission_indices) > 1:
            errors.append(f"{path_label}: job {job_name!r} declares permissions more than once")
            continue

        index = permission_indices[0]
        if block[index] != "    permissions:":
            errors.append(f"{path_label}: inline/malformed job permissions are forbidden in {job_name!r}")
            continue

        permission_map = parse_permissions_mapping(block, index, indent=4)
        if permission_map == {"contents": "read"}:
            continue

        if job_name != LOCK_RECOVERY_JOB:
            errors.append(
                f"{path_label}: job-level permissions are forbidden for {job_name!r}; "
                f"only the exact lock-recovery job may request scoped write permissions"
            )
            continue

        if permission_map != LOCK_RECOVERY_PERMISSIONS:
            errors.append(
                f"{path_label}: {LOCK_RECOVERY_JOB!r} permissions must be exactly "
                f"{LOCK_RECOVERY_PERMISSIONS!r}; found {permission_map!r}"
            )

        joined_block = "\n".join(block)
        missing_gates = [gate for gate in LOCK_RECOVERY_GATES if gate not in joined_block]
        if missing_gates:
            errors.append(
                f"{path_label}: {LOCK_RECOVERY_JOB!r} lacks required same-repository/event/ref gates: "
                + "; ".join(missing_gates)
            )

    return errors


def validate_workflow_text(path_label: str, content: str) -> list[str]:
    errors: list[str] = []
    found_actions = 0

    for line_number, line in enumerate(content.splitlines(), start=1):
        if any(pattern.match(line) for pattern in UNSAFE_TRIGGER_PATTERNS):
            errors.append(
                f"{path_label}:{line_number}: pull_request_target trigger is forbidden; "
                "use pull_request unless a separately reviewed privileged-event design is required"
            )

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

    errors.extend(validate_job_permissions(path_label, content))
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

    print("Workflow policy passed: action refs are immutable and token permissions are constrained.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
