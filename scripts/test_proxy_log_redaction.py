#!/usr/bin/env python3
"""Regression tests for the proxy sensitive-logging guard."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_proxy_log_redaction import check_tree, find_sensitive_logging


class SensitiveLogPatternTests(unittest.TestCase):
    def test_rejects_raw_search_query_logging(self) -> None:
        source = 'log::info!("Searching for {}", params.q);'
        findings = find_sensitive_logging("proxy.rs", source)
        self.assertEqual(len(findings), 1)
        self.assertIn("sensitive request/value field", findings[0])

    def test_rejects_full_url_logging(self) -> None:
        source = 'log::warn!("Blocked URL {}", params.url);'
        self.assertEqual(len(find_sensitive_logging("proxy.rs", source)), 1)

    def test_rejects_validated_url_and_request_body_logging(self) -> None:
        for source in (
            'log::debug!("proxying {}", validated);',
            'log::trace!("provider request {}", body);',
            'log::warn!("provider key {}", api_key);',
            'log::warn!("upstream said {}", msg);',
        ):
            with self.subTest(source=source):
                self.assertTrue(find_sensitive_logging("proxy.rs", source))

    def test_rejects_generic_and_tracing_logging_macros(self) -> None:
        for source in (
            'log::log!(target: "proxy", log::Level::Info, "query {}", params.q);',
            'tracing::event!(tracing::Level::INFO, "request body {}", body);',
        ):
            with self.subTest(source=source):
                self.assertTrue(find_sensitive_logging("proxy.rs", source))

    def test_rejects_multiline_log_invocations(self) -> None:
        source = """log::info!(
            "Searching for {}",
            params
                .q
        );
        log::debug!(
            "destination {}",
            sanitize(
                validated
            )
        );
        """
        findings = find_sensitive_logging("proxy.rs", source)
        self.assertEqual(len(findings), 2)
        self.assertTrue(all("sensitive request/value field" in item for item in findings))

    def test_rejects_sensitive_argument_after_raw_string_with_parentheses(self) -> None:
        source = '''log::info!(r#"literal includes ) and " quote"#, params.q);'''
        findings = find_sensitive_logging("proxy.rs", source)
        self.assertEqual(len(findings), 1)
        self.assertIn("sensitive request/value field", findings[0])

    def test_rejects_sensitive_argument_after_nested_block_comment(self) -> None:
        source = '''log::info!("query {}", /* outer /* nested ) */ still outer ) */ params.q);'''
        findings = find_sensitive_logging("proxy.rs", source)
        self.assertEqual(len(findings), 1)
        self.assertIn("sensitive request/value field", findings[0])

    def test_rejects_sensitive_argument_after_char_literal(self) -> None:
        source = """log::info!("query {}", { let close = ')'; params.q });"""
        findings = find_sensitive_logging("proxy.rs", source)
        self.assertEqual(len(findings), 1)
        self.assertIn("sensitive request/value field", findings[0])

    def test_scanner_ignores_parentheses_inside_format_strings(self) -> None:
        source = 'log::warn!("provider body (length={})", summarize(body));'
        findings = find_sensitive_logging("proxy.rs", source)
        self.assertEqual(len(findings), 1)
        self.assertIn("sensitive request/value field", findings[0])

    def test_rejects_echoing_upstream_error_details(self) -> None:
        source = 'Err(e) => format!("provider fetch failed: {}", e),'
        findings = find_sensitive_logging("proxy.rs", source)
        self.assertEqual(len(findings), 1)
        self.assertIn("upstream error detail", findings[0])

    def test_rejects_multiline_upstream_error_echo(self) -> None:
        source = """Err(error) => format!(
            "upstream request failed: {}",
            error
        ),"""
        findings = find_sensitive_logging("proxy.rs", source)
        self.assertEqual(len(findings), 1)
        self.assertIn("upstream error detail", findings[0])

    def test_accepts_redacted_operational_events(self) -> None:
        source = '\n'.join((
            'log::info!("DuckDuckGo proxy request");',
            'log::info!("Proxy request for host {}", host);',
            'log::warn!("Blocked proxy destination: {}", reason);',
            'log::warn!("Symthaea bridge request failed");',
        ))
        self.assertEqual(find_sensitive_logging("proxy.rs", source), [])

    def test_accepts_multiline_redacted_operational_event(self) -> None:
        source = """log::warn!(
            "Blocked proxy destination: {}",
            reason
        );"""
        self.assertEqual(find_sensitive_logging("proxy.rs", source), [])

    def test_current_proxy_sources_pass(self) -> None:
        root = Path(__file__).resolve().parents[1]
        self.assertEqual(check_tree(root), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
