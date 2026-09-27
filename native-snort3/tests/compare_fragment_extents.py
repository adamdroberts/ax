#!/usr/bin/env python3
"""Compare final-length enforcement with identical captures and configuration."""
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
    paths = {name: native / ("fragment-extent-" + name + ".json")
             for name in ("build-validation", "baseline-validation", "validation")}
    build, before, after = (json.loads(paths[name].read_text()) for name in paths)
    assert build["comparison"]["same_configuration"] and build["comparison"]["only_fragment_extent_repair_changes"]
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
    forwarding, reconstruction, controls = [], [], []
    for name, item in current.items():
        old = previous[name]
        for field in ("version", "protocol", "input_pcap_sha256", "input_packet_sha256", "expected_output_packet_sha256",
                      "expected_counters", "expected_indices", "arrival_order", "spans", "first_conflict_index",
                      "policy", "max_overlaps", "max_frags", "padding", "retry", "fresh_control", "payload_bytes", "next_header"):
            assert old.get(field) == item.get(field), (name, field)
        assert item["passed"] and item["enforcement_passed"] and item["counter_passed"], name
        if item["valid_control"]:
            assert old["passed"], name
            controls.append(name)
        if not old["enforcement_passed"]:
            assert item["first_conflict_index"] is not None, name
            forwarding.append(name)
        if old["counters"]["reassembled"] > item["expected_counters"]["reassembled"]:
            reconstruction.append(name)
    return {"scope": "Matched native file-only inline DAQ. Forwarding failures, extra reconstructions and counter failures are reported separately; no unique-vulnerability count or deployed prevention claim.",
            "reports_sha256": {path.relative_to(ROOT).as_posix(): digest(path) for path in paths.values()},
            "comparison_source_sha256": digest(Path(__file__)), "binary_sha256": build["binary_sha256"],
            "unchanged_plugin_sha256": after["configuration"]["plugin_sha256"],
            "summary": {"paired_cases": len(current), "native_runs": 2 * len(current),
                        "baseline_all_checks_passed": before["summary"]["passed"],
                        "baseline_forwarding_checks_passed": sum(case["enforcement_passed"] for case in previous.values()),
                        "repaired_passed": after["summary"]["passed"], "forwarding_failures_fixed": len(forwarding),
                        "cases_with_extra_reconstruction_removed": len(reconstruction), "valid_controls_preserved": len(controls)},
            "forwarding_failures_fixed": forwarding, "cases_with_extra_reconstruction_removed": reconstruction}


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
