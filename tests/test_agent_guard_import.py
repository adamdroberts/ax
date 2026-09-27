"""Import accounting, deduplication, and policy preservation regressions."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("import_agent_guard", ROOT / "tools/import_agent_guard.py")
importer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(importer)
ax = importer.ax


class TestAgentGuardImport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = json.loads((importer.IMPORT_DIR / "source-catalog.json").read_text())["rules"]
        cls.report = json.loads((importer.IMPORT_DIR / "import-report.json").read_text())
        cls.default, cls.strict = ax.SnortEngine(), ax.SnortEngine()
        ax.load_profile(cls.default, "default")
        ax.load_profile(cls.strict, "strict")
        cls.default_by_sid = {r.sid: r for r in cls.default.rules}
        cls.strict_by_sid = {r.sid: r for r in cls.strict.rules}

    def test_every_source_sid_has_exactly_one_disposition(self):
        records = self.report["rules"]
        self.assertEqual(len(records), 825)
        self.assertEqual(len({r["source_sid"] for r in records}), len(records))
        self.assertEqual({r["source_sid"] for r in records}, {r["sid"] for r in self.source})
        for status, expected in self.report["counts"].items():
            self.assertEqual(sum(r["status"] == status for r in records), expected)
        self.assertEqual(sum(self.report["counts"].values()), 825)
        self.assertEqual(hashlib.sha256((importer.IMPORT_DIR / "source-catalog.json").read_bytes()).hexdigest(),
                         self.report["source_catalog_sha256"])

    def test_no_duplicate_sids_or_detection_predicates(self):
        for engine in (self.default, self.strict):
            with self.subTest(rules=len(engine.rules)):
                self.assertEqual(len({r.sid for r in engine.rules}), len(engine.rules))
                fingerprints = {}
                for rule in engine.rules:
                    key = importer.detection_key(rule)
                    self.assertNotIn(key, fingerprints, f"Duplicate predicates: {rule.sid} and {fingerprints.get(key)}")
                    fingerprints[key] = rule.sid
        for retired in self.report["baseline_aliases"]:
            self.assertNotIn(int(retired), self.strict_by_sid)

    def test_reported_profile_actions_and_aliases_match_runtime(self):
        self.assertEqual(len(self.default.rules), self.report["default_rules"])
        self.assertEqual(len(self.strict.rules), self.report["active_unique_rules"])
        self.assertEqual(len(self.strict.rules) - len(self.default.rules), self.report["strict_additional_rules"])
        for record in self.report["rules"]:
            if record["status"] not in ("imported", "deduplicated"):
                self.assertNotIn(record["source_sid"], self.strict_by_sid)
                continue
            with self.subTest(source_sid=record["source_sid"]):
                sid = record["ax_sid"]
                self.assertEqual(self.default_by_sid[sid].action, record["effective_action"])
                self.assertEqual(self.strict_by_sid[sid].action, record["effective_strict_action"])
                if record["status"] == "deduplicated":
                    self.assertNotIn(record["source_sid"], self.strict_by_sid)
                    self.assertTrue(record["reason"])
                if record["source_action"] in importer.BLOCKING:
                    self.assertIn(self.default_by_sid[sid].action, importer.BLOCKING)
                if record["source_strict_action"] in importer.BLOCKING and record["source_sid"] not in importer.POLICY_ADAPTATIONS:
                    self.assertIn(self.strict_by_sid[sid].action, importer.BLOCKING)
        overrides = json.loads((importer.RULE_DIR / "strict-actions.json").read_text())
        self.assertEqual(len(overrides), self.report["strict_action_promotions"])
        for sid, action in overrides.items():
            self.assertEqual(self.default_by_sid[int(sid)].action, "alert")
            self.assertEqual(self.strict_by_sid[int(sid)].action, action)

    def test_native_rules_are_separate_and_uniquely_accounted(self):
        native = (importer.IMPORT_DIR / "native-only.rules").read_text()
        sids = [int(x) for x in re.findall(r"\bsid:(\d+);", native)]
        expected = {r["source_sid"] for r in self.report["rules"] if r["status"] == "native_only"}
        self.assertEqual(set(sids), expected)
        self.assertEqual(len(sids), len(expected))
        self.assertFalse(set(sids) & set(self.strict_by_sid))
        for source in self.source:
            if source["sid"] in expected:
                self.assertIn(importer.render_native(source), native)

    def test_translated_terminal_lookaheads_preserve_match_existence(self):
        checked = 0
        for source in self.source:
            patterns = [m for m in source["matches"] if m["kind"] == "pcre" and "(?=" in m["value"]]
            if not patterns:
                continue
            converted, _ = importer.translate(source)
            parsed = ax.SnortEngine().parse_rule(converted)
            for original, translated in zip(patterns, parsed.pcres):
                before = re.compile(original["value"], re.I | re.ASCII)
                for value in (source["sample"], source["sample"] + "X", "http://localhost", "http://localhostX",
                              "http://127.3.4.5/", "http://10.0.0.1:443", 'http://10.0.0.1"',
                              "http://10.0.0.1X", "http://2130706433/", "http://0x7f000001", "ordinary-report"):
                    with self.subTest(sid=source["sid"], value=value):
                        self.assertEqual(bool(before.search(value)), bool(translated.regex.search(value)))
                checked += 1
        self.assertEqual(checked, 18)

    def test_authentication_stays_advisory_while_body_and_uri_leaks_block(self):
        token = "ghp_" + "A" * 36
        for engine in (self.default, self.strict):
            blocked, rule, _ = engine.inspect("GET", "https://api.example.test/", {"Authorization": "Bearer " + token}, "")
            self.assertFalse(blocked)
            self.assertEqual(rule.sid, 9114035)
            self.assertEqual(rule.action, "alert")
            self.assertTrue(engine.inspect("POST", "https://api.example.test/", {}, token)[0])
            self.assertTrue(engine.inspect("GET", "https://api.example.test/?x=" + token, {}, "")[0])

    def test_generation_is_idempotent(self):
        result = subprocess.run([sys.executable, str(ROOT / "tools/import_agent_guard.py"), "--check"],
                                cwd=ROOT, text=True, capture_output=True, timeout=30,
                                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
