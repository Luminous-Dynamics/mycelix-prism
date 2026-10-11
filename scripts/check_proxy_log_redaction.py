#!/usr/bin/env python3
"""Static regression guard for sensitive data in Prism proxy/bridge logs.

This is deliberately stdlib-only and conservative. It recognizes balanced
logging/format macro invocations across lines, but it is not a Rust parser or
proof that every possible logging path is safe.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

LOG_MACRO_RE = re.compile(r"\blog::(?:trace|debug|info|warn|error)!\s*\(")
FORMAT_MACRO_RE = re.compile(r"\bformat!\s*\(")
SENSITIVE_LOG_VALUE_RE = re.compile(
    r"\bparams\s*\.\s*(?:q|url)\b|\bvalidated\b|\bapi_key\b|"
    r"\bbearer_token\b|\b(?:request_)?body\b|\bmsg\b",
    re.IGNORECASE,
)
UPSTREAM_ERROR_ECHO_RE = re.compile(
    r'format!\s*\(.*?(?:fetch failed|upstream request failed).*?'
    r'(?:\{\}|\{(?:e|err|error)\})',
    re.IGNORECASE | re.DOTALL,
)

DEFAULT_FILES = (
    Path("prism-proxy/src/main.rs"),
    Path("prism-serve/src/main.rs"),
)


def iter_macro_invocations(source: str, macro_pattern: re.Pattern[str]):
    """Yield (offset, source) for balanced macro invocations, including multiline ones.

    The scanner accounts for nested parentheses, escaped quotes and comments.
    It is intentionally narrow and does not implement the full Rust grammar.
    """
    for match in macro_pattern.finditer(source):
        start = match.start()
        # The selected macro pattern consumes the opening parenthesis.
        index = match.end()
        depth = 1
        in_string = False
        escaped = False
        line_comment = False
        block_comment = False

        while index < len(source):
            char = source[index]
            following = source[index + 1] if index + 1 < len(source) else ""

            if line_comment:
                if char == "\n":
                    line_comment = False
                index += 1
                continue
            if block_comment:
                if char == "*" and following == "/":
                    block_comment = False
                    index += 2
                else:
                    index += 1
                continue
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                index += 1
                continue

            if char == "/" and following == "/":
                line_comment = True
                index += 2
                continue
            if char == "/" and following == "*":
                block_comment = True
                index += 2
                continue
            if char == '"':
                in_string = True
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    yield start, source[start : index + 1]
                    break
            index += 1


def find_sensitive_logging(path: str, source: str) -> list[str]:
    findings: list[str] = []
    for offset, invocation in iter_macro_invocations(source, LOG_MACRO_RE):
        if SENSITIVE_LOG_VALUE_RE.search(invocation):
            line_number = source.count("\n", 0, offset) + 1
            findings.append(
                f"{path}:{line_number}: log macro interpolates a sensitive request/value field"
            )

    for offset, invocation in iter_macro_invocations(source, FORMAT_MACRO_RE):
        if UPSTREAM_ERROR_ECHO_RE.search(invocation):
            line_number = source.count("\n", 0, offset) + 1
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
