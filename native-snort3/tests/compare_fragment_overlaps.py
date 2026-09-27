#!/usr/bin/env python3
"""Compare identical overlap captures against matched cumulative engine builds."""
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
    paths = {name: native / ("fragment-overlap-" + name + ".json")
             for name in ("build-validation", "baseline-validation", "validation")}
    build, before, after = (json.loads(paths[name].read_text()) for name in paths)
    assert build["comparison"]["same_configuration"] and build["comparison"]["only_fragment_overlap_repair_changes"]
    assert before["snort_binary_sha256"] == build["binary_sha256"]["baseline"]
    assert after["snort_binary_sha256"] == build["binary_sha256"]["repaired"]
    assert before["configuration"] == after["configuration"]
    assert before["fixture_source_sha256"] == after["fixture_source_sha256"]
    assert before["test_configuration_sha256"] == after["test_configuration_sha256"]
    for name, expected in after["fixture_source_sha256"].items() | after["configuration"]["sha256"].items():
        assert digest(ROOT / name) == expected, name
    previous, current = ({item["name"]: item for item in report["cases"]} for report in (before, after))
    assert len(previous) == len(before["cases"]) == len(current) == len(after["cases"])
    assert previous.keys() == current.keys()
    rejected, restored, strict = [], [], []
    for name, item in current.items():
        old = previous[name]
        for field in ("version", "protocol", "input_pcap_sha256", "input_packet_sha256", "expected_output_packet_sha256",
                      "expected_counters", "expected_indices", "arrival_order", "first_overlap_index", "policy",
                      "max_overlaps", "max_frags", "changed_payload", "padding", "retry", "cleanup_control", "payload_bytes"):
            assert old.get(field) == item.get(field), (name, field)
        assert item["passed"] and item["enforcement_passed"] and item["counter_passed"], name
        if item["max_overlaps"] == 1 and not item["cleanup_control"]:
            assert old["enforcement_passed"], name
            strict.append(name)
        if not old["enforcement_passed"]:
            if item["cleanup_control"]:
                assert item["expected_counters"]["reassembled"] == 1 and old["counters"]["resource_drops"] > 0
                restored.append(name)
            else:
                assert item["version"] == 6 and item["max_overlaps"] in (0, 8)
                rejected.append(name)
    assert len(restored) == 24 and len(rejected) == 348
    return {"scope": "Paired file-only inline DAQ. The original strict profile already blocked overlap cases; changes make IPv6 enforcement independent of overlap-limit configuration and release abandoned buffers promptly.",
            "reports_sha256": {path.relative_to(ROOT).as_posix(): digest(path) for path in paths.values()},
            "comparison_source_sha256": digest(Path(__file__)), "binary_sha256": build["binary_sha256"],
            "unchanged_plugin_sha256": after["configuration"]["plugin_sha256"],
            "summary": {"paired_cases": len(current), "native_runs": 2 * len(current),
                        "baseline_all_checks_passed": before["summary"]["passed"],
                        "baseline_forwarding_checks_passed": sum(item["enforcement_passed"] for item in previous.values()),
                        "repaired_passed": after["summary"]["passed"],
                        "stronger_ipv6_rejection_cases": len(rejected), "valid_forwarding_restored": len(restored),
                        "unchanged_strict_forwarding_cases": len(strict)},
            "stronger_rejection_cases": rejected, "restored_cleanup_controls": restored}


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
