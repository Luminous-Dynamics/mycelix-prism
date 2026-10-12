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

LOG_MACRO_RE = re.compile(r"\b(?:log|tracing)::(?:trace|debug|info|warn|error|log|event)!\s*\(")
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
    """Yield balanced macro invocations while skipping common Rust lexical forms.

    This narrow scanner handles ordinary/raw strings, character literals,
    line comments, and nested block comments. It is not a complete Rust parser;
    it exists to catch common logging regressions without external dependencies.
    """
    raw_string_re = re.compile(r"(?:br|cr|r)(?P<hashes>#{0,})\"")
    char_literal_re = re.compile(
        r"""'(?:[^'\\\n]|\\(?:[nrt0\\'"]|x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]+\}))'"""
    )

    for match in macro_pattern.finditer(source):
        start = match.start()
        # The selected macro pattern consumes the opening parenthesis.
        index = match.end()
        depth = 1
        in_string = False
        escaped = False
        line_comment = False
        block_comment_depth = 0

        while index < len(source):
            char = source[index]
            following = source[index + 1] if index + 1 < len(source) else ""

            if line_comment:
                if char == "\n":
                    line_comment = False
                index += 1
                continue

            if block_comment_depth:
                if char == "/" and following == "*":
                    block_comment_depth += 1
                    index += 2
                elif char == "*" and following == "/":
                    block_comment_depth -= 1
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

            # Rust raw strings can contain quotes, parentheses, and comment
            # delimiters without escaping. Require a token boundary so an
            # identifier containing "br" cannot start a raw string by accident.
            token_boundary = index == 0 or not (
                source[index - 1].isalnum() or source[index - 1] == "_"
            )
            raw_match = raw_string_re.match(source, index) if token_boundary else None
            if raw_match:
                terminator = '"' + ("#" * len(raw_match.group("hashes")))
                closing = source.find(terminator, raw_match.end())
                if closing < 0:
                    break
                index = closing + len(terminator)
                continue

            # Character literals may include ')' or other syntax characters.
            # Do not confuse Rust lifetimes ('a, 'static) with char literals.
            char_match = char_literal_re.match(source, index) if char == "'" else None
            if char_match:
                index = char_match.end()
                continue

            if char == "/" and following == "/":
                line_comment = True
                index += 2
                continue
            if char == "/" and following == "*":
                block_comment_depth = 1
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
