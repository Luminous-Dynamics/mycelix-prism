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
CHECKOUT_RE = re.compile(r"^(?P<indent> *)-\s*uses\s*:\s*actions/checkout@")
STEP_START_RE = re.compile(r"^(?P<indent> *)-\s+(?:uses|name)\s*:")
CHECKOUT_REF_ALLOWLIST = {
    "${{ github.event.pull_request.head.sha || github.sha }}",
    "${{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.sha }}",
}

# The one temporary writer lane is intentionally exceptional and tightly gated.
LOCK_RECOVERY_JOB = "generate_lockfile"
LOCK_RECOVERY_PERMISSIONS = {"contents": "write", "statuses": "write"}
LOCK_RECOVERY_CONDITION = "${{ (github.event_name == 'pull_request' && github.head_ref == 'fix/proxy-dns-pinning-redirects-20261010' && github.event.pull_request.head.repo.full_name == github.repository) || (github.event_name == 'push' && github.ref == 'refs/heads/fix/proxy-dns-pinning-redirects-20261010') }}"
LOCK_RECOVERY_TOKEN_STEPS = {
    "Commit generated lockfile to PR branch",
    "Publish result for the exact validated commit",
}
TOKEN_ACCESS_RE = re.compile(
    r"\$\{\{[^}]*?(?:secrets\s*\.\s*GITHUB_TOKEN|"
    r"secrets\s*\[\s*['\"]GITHUB_TOKEN['\"]\s*\]|github\s*\.\s*token)[^}]*?\}\}",
    re.IGNORECASE,
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

        condition_lines = [line for line in block if re.match(r"^ {4}if\s*:", line)]
        expected_condition_line = f"    if: {LOCK_RECOVERY_CONDITION}"
        if condition_lines != [expected_condition_line]:
            errors.append(
                f"{path_label}: {LOCK_RECOVERY_JOB!r} if condition must exactly match "
                "the gated same-repository/event/ref expression"
            )

    return errors


def validate_checkout_refs(path_label: str, content: str) -> list[str]:
    """Require source-head-aware checkout refs and forbid persisted checkout credentials."""
    lines = content.splitlines()
    errors: list[str] = []
    for index, line in enumerate(lines):
        checkout = CHECKOUT_RE.match(line)
        if not checkout:
            continue

        step_indent = len(checkout.group("indent"))
        block = [line]
        for candidate in lines[index + 1 :]:
            next_step = STEP_START_RE.match(candidate)
            if next_step and len(next_step.group("indent")) == step_indent:
                break
            block.append(candidate)

        ref_values: list[str] = []
        credential_values: list[str] = []
        for block_line in block[1:]:
            ref_match = re.match(r"^\s*ref\s*:\s*(.*?)\s*(?:#.*)?$", block_line)
            if ref_match:
                value = ref_match.group(1).strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                    value = value[1:-1]
                ref_values.append(value)

            credential_match = re.match(
                r"^\s*persist-credentials\s*:\s*(.*?)\s*(?:#.*)?$", block_line
            )
            if credential_match:
                credential_value = credential_match.group(1).strip().lower()
                if len(credential_value) >= 2 and credential_value[0] == credential_value[-1] and credential_value[0] in {"'", '"'}:
                    credential_value = credential_value[1:-1]
                credential_values.append(credential_value)

        line_number = index + 1
        if len(ref_values) != 1:
            errors.append(
                f"{path_label}:{line_number}: actions/checkout must declare exactly one immutable ref"
            )
        elif ref_values[0] not in CHECKOUT_REF_ALLOWLIST:
            errors.append(
                f"{path_label}:{line_number}: actions/checkout ref must be an approved source-head-aware "
                f"event SHA expression; found {ref_values[0]!r}"
            )

        if credential_values != ["false"]:
            errors.append(
                f"{path_label}:{line_number}: actions/checkout must explicitly set "
                "persist-credentials: false; no checkout may persist the workflow token"
            )

    return errors

def validate_token_scope(path_label: str, content: str) -> list[str]:
    """Keep the workflow token scoped to explicit shell-only publication steps."""
    lines = content.splitlines()
    errors: list[str] = []
    in_jobs = False
    current_job: str | None = None
    current_step: str | None = None
    current_step_start: int | None = None
    token_lines: list[tuple[int, str | None, str | None, int | None, str]] = []
    allowed_token_line = "          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}"

    for index, line in enumerate(lines):
        if line == "jobs:":
            in_jobs = True
            current_job = None
            current_step = None
            current_step_start = None
            continue
        if in_jobs and line.strip() and not line.startswith(" "):
            in_jobs = False
            current_job = None
            current_step = None
            current_step_start = None

        if in_jobs:
            job_match = JOB_RE.fullmatch(line)
            if job_match:
                current_job = job_match.group(1)
                current_step = None
                current_step_start = None

            step_match = STEP_START_RE.match(line)
            if step_match and len(step_match.group("indent")) == 6:
                current_step_start = index
                name_match = re.match(r"^      - name\s*:\s*(.*?)\s*$", line)
                current_step = name_match.group(1).strip() if name_match else None

        if TOKEN_ACCESS_RE.search(line):
            token_lines.append((index, current_job, current_step, current_step_start, line))

    for index, job_name, step_name, step_start, line in token_lines:
        allowed_step_shape = False
        if step_start is not None:
            step_lines = [lines[step_start]]
            for candidate in lines[step_start + 1 :]:
                next_step = STEP_START_RE.match(candidate)
                if (
                    (next_step and len(next_step.group("indent")) == 6)
                    or JOB_RE.fullmatch(candidate)
                    or (candidate.strip() and not candidate.startswith(" "))
                ):
                    break
                step_lines.append(candidate)

            step_starts_with_uses = bool(re.match(r"^ {6}-\s*uses\s*:", step_lines[0]))
            nested_uses = any(re.match(r"^ {8}uses\s*:", item) for item in step_lines[1:])
            has_run = any(re.match(r"^ {8}run\s*:", item) for item in step_lines[1:])
            allowed_step_shape = has_run and not step_starts_with_uses and not nested_uses

        if (
            job_name != LOCK_RECOVERY_JOB
            or step_name not in LOCK_RECOVERY_TOKEN_STEPS
            or line != allowed_token_line
            or not allowed_step_shape
        ):
            errors.append(
                f"{path_label}:{index + 1}: workflow token may only be exposed as GH_TOKEN "
                "inside the two named shell-only lock-publication steps"
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

    errors.extend(validate_checkout_refs(path_label, content))
    errors.extend(validate_job_permissions(path_label, content))
    errors.extend(validate_token_scope(path_label, content))
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
