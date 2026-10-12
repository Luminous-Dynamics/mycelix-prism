#!/usr/bin/env python3
"""Unit tests for the standalone workflow-policy guard."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_workflow_security import check_tree, validate_action_reference, validate_workflow_text

VALID_SHA = "a" * 40


class ActionReferenceTests(unittest.TestCase):
    def test_accepts_full_sha_and_version_comment(self) -> None:
        self.assertEqual(
            validate_action_reference(
                f"actions/checkout@{VALID_SHA}",
                f"- uses: actions/checkout@{VALID_SHA} # v7.0.1",
            ),
            [],
        )

    def test_rejects_mutable_tag(self) -> None:
        errors = validate_action_reference(
            "actions/checkout@v7",
            "- uses: actions/checkout@v7 # v7.0.1",
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("full 40-character commit SHA", errors[0])

    def test_rejects_sha_without_human_version_comment(self) -> None:
        errors = validate_action_reference(
            f"actions/checkout@{VALID_SHA}",
            f"- uses: actions/checkout@{VALID_SHA}",
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("version comment", errors[0])

    def test_local_action_is_allowed(self) -> None:
        self.assertEqual(
            validate_action_reference("./.github/actions/check", "- uses: ./.github/actions/check"),
            [],
        )

    def test_docker_action_requires_digest(self) -> None:
        self.assertEqual(
            validate_action_reference(
                "docker://example/image@sha256:" + "b" * 64,
                "uses: docker://example/image@sha256:" + "b" * 64,
            ),
            [],
        )
        errors = validate_action_reference(
            "docker://example/image:latest",
            "uses: docker://example/image:latest",
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("sha256 digest", errors[0])


class WorkflowPolicyTests(unittest.TestCase):
    def test_accepts_pinned_workflow_with_minimal_permissions(self) -> None:
        content = f"""name: test

permissions:
  contents: read

on:
  pull_request:

jobs:
  policy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{VALID_SHA} # v7.0.1
        with:
          ref: ${{{{ github.event.pull_request.head.sha || github.sha }}}}
"""
        self.assertEqual(validate_workflow_text("ci.yml", content), [])

    def test_rejects_pull_request_target_trigger(self) -> None:
        content = f"""name: test

permissions:
  contents: read

on:
  pull_request_target:

jobs:
  policy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{VALID_SHA} # v7.0.1
        with:
          ref: ${{{{ github.event.pull_request.head.sha || github.sha }}}}
"""
        errors = validate_workflow_text("ci.yml", content)
        self.assertTrue(
            any("pull_request_target trigger is forbidden" in error for error in errors)
        )

    def test_rejects_pull_request_target_shorthand_forms(self) -> None:
        trigger_forms = (
            "on: pull_request_target",
            "on: [push, pull_request_target]",
            "on: { push: {}, pull_request_target: {} }",
            "on:\n  - push\n  - pull_request_target",
        )
        for trigger in trigger_forms:
            with self.subTest(trigger=trigger):
                content = f"""name: test

permissions:
  contents: read

{trigger}

jobs:
  policy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{VALID_SHA} # v7.0.1
        with:
          ref: ${{{{ github.event.pull_request.head.sha || github.sha }}}}
"""
                errors = validate_workflow_text("ci.yml", content)
                self.assertTrue(
                    any("pull_request_target trigger is forbidden" in error for error in errors),
                    msg=f"did not reject trigger form: {trigger}",
                )

    def test_rejects_missing_permissions_baseline(self) -> None:
        content = f"""name: test
on:
  pull_request:
jobs:
  policy:
    steps:
      - uses: actions/checkout@{VALID_SHA} # v7.0.1
        with:
          ref: ${{{{ github.event.pull_request.head.sha || github.sha }}}}
"""
        errors = validate_workflow_text("ci.yml", content)
        self.assertTrue(any("top-level permissions" in error for error in errors))

    def test_rejects_write_all_permissions(self) -> None:
        content = f"""name: test

permissions: write-all

on:
  pull_request:
jobs:
  policy:
    steps:
      - uses: actions/checkout@{VALID_SHA} # v7.0.1
        with:
          ref: ${{{{ github.event.pull_request.head.sha || github.sha }}}}
"""
        errors = validate_workflow_text("ci.yml", content)
        self.assertTrue(any("top-level permissions" in error for error in errors))

    def test_accepts_explicit_read_only_job_permissions(self) -> None:
        content = f"""name: test

permissions:
  contents: read

on:
  pull_request:

jobs:
  policy:
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{VALID_SHA} # v7.0.1
        with:
          ref: ${{{{ github.event.pull_request.head.sha || github.sha }}}}
"""
        self.assertEqual(validate_workflow_text("ci.yml", content), [])

    def test_rejects_unapproved_job_write_permissions(self) -> None:
        content = f"""name: test

permissions:
  contents: read

on:
  pull_request:

jobs:
  dangerous:
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@{VALID_SHA} # v7.0.1
        with:
          ref: ${{{{ github.event.pull_request.head.sha || github.sha }}}}
"""
        errors = validate_workflow_text("ci.yml", content)
        self.assertTrue(any("job-level permissions are forbidden" in error for error in errors))

    def test_allows_only_exact_gated_lock_recovery_permissions(self) -> None:
        content = f"""name: test

permissions:
  contents: read

on:
  pull_request:

jobs:
  generate_lockfile:
    if: ${{{{ (github.event_name == 'pull_request' && github.head_ref == 'fix/proxy-dns-pinning-redirects-20261010' && github.event.pull_request.head.repo.full_name == github.repository) || (github.event_name == 'push' && github.ref == 'refs/heads/fix/proxy-dns-pinning-redirects-20261010') }}}}
    permissions:
      contents: write
      statuses: write
    steps:
      - uses: actions/checkout@{VALID_SHA} # v7.0.1
        with:
          ref: ${{{{ github.event.pull_request.head.sha || github.sha }}}}
"""
        self.assertEqual(validate_workflow_text("ci.yml", content), [])

    def test_recovery_permission_without_same_repo_gate_is_rejected(self) -> None:
        content = f"""name: test

permissions:
  contents: read

on:
  pull_request:

jobs:
  generate_lockfile:
    if: ${{{{ github.event_name == 'pull_request' }}}}
    permissions:
      contents: write
      statuses: write
    steps:
      - uses: actions/checkout@{VALID_SHA} # v7.0.1
        with:
          ref: ${{{{ github.event.pull_request.head.sha || github.sha }}}}
"""
        errors = validate_workflow_text("ci.yml", content)
        self.assertTrue(any("lacks required same-repository/event/ref gates" in error for error in errors))

    def test_tree_scan_rejects_action_tag(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflow_dir = root / ".github" / "workflows"
            workflow_dir.mkdir(parents=True)
            (workflow_dir / "ci.yml").write_text(
                """name: test

permissions:
  contents: read

on:
  pull_request:
jobs:
  policy:
    steps:
      - uses: actions/checkout@v7 # v7.0.1
""",
                encoding="utf-8",
            )
            errors = check_tree(root)
            self.assertTrue(any("full 40-character commit SHA" in error for error in errors))


if __name__ == "__main__":
    unittest.main(verbosity=2)
