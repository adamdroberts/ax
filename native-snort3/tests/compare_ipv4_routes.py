#!/usr/bin/env python3
"""Bind IPv4 route audits to matched builds without treating failures as passes."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

if not __debug__:
    raise RuntimeError("comparison requires assertions")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compare(before_path, after_path, build_path):
    before, after, build = (json.loads(path.read_text()) for path in (before_path, after_path, build_path))
    assert build["comparison"]["same_configuration"]
    assert build["comparison"]["only_ipv4_route_repair_changes"]
    assert before["configuration"] == after["configuration"]
    assert before["fixture_source_sha256"] == after["fixture_source_sha256"]
    assert before["special_configuration_sha256"] == after["special_configuration_sha256"]
    assert before["snort_binary_sha256"] == build["binary_sha256"]["baseline"]
    assert after["snort_binary_sha256"] == build["binary_sha256"]["repaired"]
    for relative, expected in after["fixture_source_sha256"].items() | after["configuration"]["sha256"].items():
        assert digest(ROOT / relative) == expected, relative
    old, new = ({case["name"]: case for case in report["cases"]} for report in (before, after))
    assert len(old) == len(before["cases"]) == len(new) == len(after["cases"])
    assert old.keys() == new.keys()
    blocked, restored = [], []
    for name, current in new.items():
        previous = old[name]
        for field in ("protocol", "active_route", "valid", "malformed_route", "variant", "normalization",
                      "fragmented", "ah", "input_packet_sha256", "input_pcap_sha256", "expected_packet_sha256",
                      "expected_daq_verdicts"):
            assert current[field] == previous[field], (name, field)
        assert current["passed"] and current["enforcement_passed"] and current["checksum_counter_passed"], name
        old_should_fail = previous["malformed_route"] or (previous["active_route"] and previous["variant"] != "zero")
        assert previous["passed"] != old_should_fail, name
        if old_should_fail:
            if current["valid"]:
                assert previous["daq_verdicts"].get("block") == 1, name
                restored.append(name)
            else:
                assert previous["daq_verdicts"].get("block", 0) == 0, name
                assert current["daq_verdicts"].get("block") == 1, name
                blocked.append(name)
    return {"scope": "Matched local source builds and identical synthetic captures. No deployed or live routing evidence.",
            "reports_sha256": {path.relative_to(ROOT).as_posix(): digest(path) for path in (before_path, after_path, build_path)},
            "comparison_source_sha256": digest(Path(__file__)), "binary_sha256": build["binary_sha256"],
            "summary": {"paired_cases": len(new), "native_runs": len(new) * 2,
                        "repaired_passed": len(new), "newly_blocked_invalid_cases": len(blocked),
                        "restored_valid_cases": len(restored), "valid_cases": sum(case["valid"] for case in new.values()),
                        "fragment_cases": sum(case["fragmented"] for case in new.values()),
                        "normalization_cases": sum(bool(case["normalization"]) for case in new.values()),
                        "malformed_route_cases": sum(case["malformed_route"] for case in new.values())},
            "newly_blocked_cases": blocked, "restored_valid_cases": restored}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-report", type=Path, required=True)
    parser.add_argument("--repaired-report", type=Path, required=True)
    parser.add_argument("--build-report", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = compare(args.baseline_report.resolve(), args.repaired_report.resolve(), args.build_report.resolve())
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["summary"], indent=2))


if __name__ == "__main__":
    main()
