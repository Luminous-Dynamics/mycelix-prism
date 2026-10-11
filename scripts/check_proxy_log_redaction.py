#!/usr/bin/env python3
"""Static regression guard for sensitive data in Prism proxy/bridge logs.

This is deliberately stdlib-only and conservative; it is not a Rust parser or
proof that every possible logging path is safe.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

LOG_MACRO_RE = re.compile(r"\blog::(?:trace|debug|info|warn|error)!\s*\(")
SENSITIVE_LOG_VALUE_RE = re.compile(
    r"\bparams\s*\.\s*(?:q|url)\b|\bvalidated\b|\bapi_key\b|"
    r"\bbearer_token\b|\b(?:request_)?body\b|\bmsg\b",
    re.IGNORECASE,
)
UPSTREAM_ERROR_ECHO_RE = re.compile(
    r'format!\s*\([^\n]*(?:fetch failed|upstream request failed)[^\n]*'
    r'(?:\{\}|\{(?:e|err|error)\})',
    re.IGNORECASE,
)

DEFAULT_FILES = (
    Path("prism-proxy/src/main.rs"),
    Path("prism-serve/src/main.rs"),
)


def find_sensitive_logging(path: str, source: str) -> list[str]:
    findings: list[str] = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        if LOG_MACRO_RE.search(line) and SENSITIVE_LOG_VALUE_RE.search(line):
            findings.append(
                f"{path}:{line_number}: log macro interpolates a sensitive request/value field"
            )

    for line_number, line in enumerate(source.splitlines(), start=1):
        if UPSTREAM_ERROR_ECHO_RE.search(line):
            findings.append(
                f"{path}:{line_number}: upstream error detail is interpolated into a response"
            )
    return findings


def check_tree(root: Path) -> list[str]:
    findings: list[str] = []
    for relative in DEFAULT_FILES:
        path = root / relative
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as error:
            findings.append(f"{relative}: cannot read source: {error}")
            continue
        findings.extend(find_sensitive_logging(str(relative), source))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="repository root")
    args = parser.parse_args()
    findings = check_tree(args.root.resolve())
    if findings:
        for finding in findings:
            print(f"ERROR: {finding}", file=sys.stderr)
        print(f"Sensitive logging policy failed with {len(findings)} finding(s).", file=sys.stderr)
        return 1
    print("Sensitive logging policy passed for proxy and server handlers.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
