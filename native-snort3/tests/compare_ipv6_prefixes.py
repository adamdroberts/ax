#!/usr/bin/env python3
"""Bind the paired IPv6 prefix evidence to one engine change and unchanged plugin."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if not __debug__:
    raise RuntimeError("comparison requires assertions")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compare(native):
    paths = {"build": native / "ipv6-prefix-build-validation.json",
             "parser": native / "ipv6-prefix-parser-validation.json"}
    build, parser = (json.loads(paths[name].read_text()) for name in ("build", "parser"))
    assert build["comparison"]["same_configuration"] and build["comparison"]["only_ipv6_prefix_repair_changes"]
    assert parser["sanitizers"] == ["address", "undefined"]
    assert parser["summary"]["random_spans"] == parser["summary"]["random_geometry"] == 100000
    for name, expected in parser["sha256"].items():
        assert digest(ROOT / name) == expected
    definitions = {
        "prefix_ecn_size": ("ipv6-prefix-baseline-validation.json", "ipv6-prefix-validation.json"),
        "header_policy": ("ipv6-fragment-header-audit.json", "ipv6-prefix-repaired-engine/header-retention-validation.json"),
        "home_wire_oracle": ("ipv6-fragment-prefix-audit.json", "ipv6-prefix-repaired-engine/home-wire-prefix-validation.json"),
    }
    summaries, plugin_hashes = {}, None
    for label, names in definitions.items():
        before, after = (json.loads((native / name).read_text()) for name in names)
        for version, report, name in (("baseline", before, names[0]), ("repaired", after, names[1])):
            paths[label + "_" + version] = native / name
            assert report["snort_binary_sha256"] == build["binary_sha256"][version]
        assert before["configuration"] == after["configuration"]
        assert before["fixture_source_sha256"] == after["fixture_source_sha256"]
        if plugin_hashes is None:
            plugin_hashes = after["configuration"]["plugin_sha256"]
        assert plugin_hashes == after["configuration"]["plugin_sha256"]
        for name, expected in after["fixture_source_sha256"].items() | after["configuration"]["sha256"].items():
            assert digest(ROOT / name) == expected, name
        for field in ("observer_configuration_sha256", "test_configuration_sha256", "normalizer_configuration_sha256"):
            assert before.get(field) == after.get(field)
        previous, current = ({item["name"]: item for item in report["cases"]} for report in (before, after))
        assert len(previous) == len(before["cases"]) == len(current) == len(after["cases"])
        assert previous.keys() == current.keys()
        strengthened, restored, corrected_bytes = [], [], []
        for name, item in current.items():
            old = previous[name]
            for field in ("protocol", "input_pcap_sha256", "input_packet_sha256", "expected_output_packet_sha256",
                          "expected_rebuilt_packet_sha256", "expected_reassemblies", "reason", "retry", "ecn",
                          "payload_bytes", "arrival_order", "expected_reason_drops", "checksum_source", "checksum_destination"):
                assert old.get(field) == item.get(field), (label, name, field)
            assert item["passed"] and item["enforcement_passed"] and item["counter_passed"], (label, name)
            if not old["enforcement_passed"]:
                if item["expected_verdicts"].get("block", 0):
                    strengthened.append(name)
                else:
                    restored.append(name)
            if "rebuilt_bytes_passed" in item and not old["rebuilt_bytes_passed"]:
                assert item["rebuilt_bytes_passed"]
                corrected_bytes.append(name)
        summaries[label] = {"paired_cases": len(current), "native_runs": 2 * len(current),
                            "baseline_passed": before["summary"]["passed"], "repaired_passed": after["summary"]["passed"],
                            "stronger_rejection_cases": len(strengthened), "valid_forwarding_restored": len(restored),
                            "reconstructed_byte_expectations_restored": len(corrected_bytes),
                            "strengthened_cases": strengthened, "restored_cases": restored}
    assert summaries["header_policy"]["stronger_rejection_cases"] == 18
    return {"scope": "Paired file-only release-engine evidence. The 48 Home Address wire-oracle cases do not establish endpoint binding or logical-source grouping.",
            "reports_sha256": {path.relative_to(ROOT).as_posix(): digest(path) for path in paths.values()},
            "comparison_source_sha256": digest(Path(__file__)), "binary_sha256": build["binary_sha256"],
            "unchanged_plugin_sha256": plugin_hashes,
            "summary": {"paired_cases": sum(item["paired_cases"] for item in summaries.values()),
                        "native_runs": sum(item["native_runs"] for item in summaries.values()),
                        "header_policy_bypasses_closed": 18},
            "suites": summaries}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-dir", type=Path, default=ROOT / "native-snort3")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = compare(args.native_dir.resolve())
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["summary"], indent=2))


if __name__ == "__main__":
    main()
