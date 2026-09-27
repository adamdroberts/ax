#!/usr/bin/env python3
"""Bind the paired IPv4 prefix replay to matched engine builds and one plugin."""
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
    paths = {name: native / ("ipv4-prefix-" + name + ".json") for name in
             ("build-validation", "parser-validation", "baseline-validation", "validation")}
    build, parser, before, after = (json.loads(paths[name].read_text()) for name in paths)
    assert build["comparison"]["same_configuration"] and build["comparison"]["only_ipv4_prefix_repair_changes"]
    assert parser["sanitizers"] == ["address", "undefined"]
    assert parser["summary"]["random_spans"] == parser["summary"]["random_geometry"] == 100000
    assert before["snort_binary_sha256"] == build["binary_sha256"]["baseline"]
    assert after["snort_binary_sha256"] == build["binary_sha256"]["repaired"]
    assert before["configuration"] == after["configuration"]
    assert before["fixture_source_sha256"] == after["fixture_source_sha256"]
    assert before["test_configuration_sha256"] == after["test_configuration_sha256"]
    for name, expected in (parser["sha256"].items() | after["fixture_source_sha256"].items() |
                           after["configuration"]["sha256"].items()):
        assert digest(ROOT / name) == expected, name
    previous, current = ({item["name"]: item for item in report["cases"]} for report in (before, after))
    assert len(previous) == len(before["cases"]) == len(current) == len(after["cases"])
    assert previous.keys() == current.keys()
    strengthened, corrected, policies = [], [], []
    for name, item in current.items():
        old = previous[name]
        for field in ("protocol", "input_pcap_sha256", "input_packet_sha256", "expected_output_packet_sha256",
                      "expected_rebuilt_packet_sha256", "expected_reassemblies", "reason", "retry", "ecn",
                      "payload_bytes", "arrival_order", "expected_reason_drops", "first_header_bytes", "policy"):
            assert old.get(field) == item.get(field), (name, field)
        assert item["passed"] and item["enforcement_passed"] and item["counter_passed"] and item["rebuilt_bytes_passed"], name
        if not old["enforcement_passed"]:
            assert item["expected_verdicts"].get("block", 0)
            strengthened.append(name)
            if item["policy"] == "enforce":
                policies.append(name)
        if not old["rebuilt_bytes_passed"]:
            corrected.append(name)
    assert len(policies) == before["summary"]["local_policy_bypass_cases"] == 16
    assert not after["summary"]["local_policy_bypass_cases"]
    return {"scope": "Paired file-only inline DAQ and complete reconstructed bytes; no live endpoint, deployment or universal compliance proof.",
            "reports_sha256": {path.relative_to(ROOT).as_posix(): digest(path) for path in paths.values()},
            "comparison_source_sha256": digest(Path(__file__)), "binary_sha256": build["binary_sha256"],
            "unchanged_plugin_sha256": after["configuration"]["plugin_sha256"],
            "summary": {"paired_cases": len(current), "native_runs": 2 * len(current),
                        "baseline_passed": before["summary"]["passed"], "repaired_passed": after["summary"]["passed"],
                        "stronger_rejection_cases": len(strengthened), "header_policy_bypasses_closed": len(policies),
                        "reconstructed_byte_expectations_restored": len(corrected)},
            "strengthened_cases": strengthened, "policy_bypasses_closed": policies,
            "reconstructed_byte_cases_corrected": corrected}


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
