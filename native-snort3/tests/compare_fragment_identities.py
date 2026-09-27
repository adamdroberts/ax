#!/usr/bin/env python3
"""Compare fragment identity inspection and isolation with matched builds."""
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
    paths = {name: native / ("fragment-identity-" + name + ".json")
             for name in ("build-validation", "baseline-validation", "validation")}
    build, before, after = (json.loads(paths[name].read_text()) for name in paths)
    assert build["comparison"]["same_configuration"] and build["comparison"]["only_fragment_identity_repair_changes"]
    assert before["snort_binary_sha256"] == build["binary_sha256"]["baseline"]
    assert after["snort_binary_sha256"] == build["binary_sha256"]["repaired"]
    assert before["configuration"] == after["configuration"]
    assert before["fixture_source_sha256"] == after["fixture_source_sha256"]
    assert before["test_configuration_sha256"] == after["test_configuration_sha256"]
    for name, expected in after["fixture_source_sha256"].items() | after["configuration"]["sha256"].items():
        assert digest(ROOT / name) == expected, name
    previous, current = ({case["name"]: case for case in report["cases"]} for report in (before, after))
    assert len(previous) == len(before["cases"]) == len(current) == len(after["cases"])
    assert previous.keys() == current.keys()
    fixed, policy, checksum, restored, inspected = [], [], [], [], []
    for name, item in current.items():
        old = previous[name]
        for field in ("version", "protocol", "valid", "policy", "input_pcap_sha256", "input_packet_sha256",
                      "expected_output_packet_sha256", "expected_counters", "expected_indices",
                      "arrival_order", "datagrams", "metadata", "expected_checksum_errors", "max_frags"):
            assert old.get(field) == item.get(field), (name, field)
        assert item["passed"] and item["enforcement_passed"] and item["counter_passed"], name
        if not old["enforcement_passed"]:
            fixed.append(name)
        if old["counters"]["reassembled"] < item["expected_counters"]["reassembled"]:
            inspected.append(name)
        old_size, new_size = len(old["output_packet_sha256"]), len(item["output_packet_sha256"])
        if old_size > new_size:
            if item["policy"] == "deny":
                policy.append(name)
            elif not item["valid"]:
                checksum.append(name)
        if item["valid"] and item["policy"] == "observe" and old_size < new_size:
            restored.append(name)
    return {"scope": "Matched file-only inline DAQ: full fragment identity, reassembly inspection and independent contexts. Temporary policy rules are test-only; counts are cases, not distinct vulnerabilities or deployed prevention.",
            "reports_sha256": {path.relative_to(ROOT).as_posix(): digest(path) for path in paths.values()},
            "comparison_source_sha256": digest(Path(__file__)), "binary_sha256": build["binary_sha256"],
            "unchanged_plugin_sha256": after["configuration"]["plugin_sha256"],
            "summary": {"paired_cases": len(current), "native_runs": 2 * len(current),
                        "baseline_passed": before["summary"]["passed"], "repaired_passed": after["summary"]["passed"],
                        "forwarding_failures_fixed": len(fixed), "temporary_policy_bypasses_fixed": len(policy),
                        "checksum_rejection_restored": len(checksum), "valid_forwarding_restored": len(restored),
                        "reassembly_inspection_restored": len(inspected)},
            "forwarding_failures_fixed": fixed, "temporary_policy_bypasses_fixed": policy,
            "checksum_rejection_restored": checksum, "valid_forwarding_restored": restored,
            "reassembly_inspection_restored": inspected}


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
