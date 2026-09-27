#!/usr/bin/env python3
"""Bind identical fragment-option captures to the reviewed native build delta."""
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
    assert build["comparison"]["same_configuration"] and build["comparison"]["only_fragment_options_repair_changes"]
    assert before["configuration"] == after["configuration"]
    assert before["fixture_source_sha256"] == after["fixture_source_sha256"]
    assert before["snort_binary_sha256"] == build["binary_sha256"]["baseline"]
    assert after["snort_binary_sha256"] == build["binary_sha256"]["repaired"]
    assert before["status"] == "conformance_failure" and after["status"] == "verified_expected_behavior"
    for relative, expected in after["fixture_source_sha256"].items() | after["configuration"]["sha256"].items():
        assert digest(ROOT / relative) == expected, relative
    old, new = ({case["name"]: case for case in report["cases"]} for report in (before, after))
    assert len(old) == len(before["cases"]) == len(new) == len(after["cases"])
    assert old.keys() == new.keys()
    blocked, restored, strengthened = [], [], []
    for name, current in new.items():
        previous = old[name]
        for field in ("category", "protocol", "zero_checksum", "valid_control", "retries", "arrival_order",
                      "fragment_count", "first_rejection", "expected_reassemblies", "input_packet_sha256",
                      "input_pcap_sha256", "expected_output_packet_sha256"):
            assert current[field] == previous[field], (name, field)
        assert current["passed"] and current["enforcement_passed"] and current["option_events_passed"]
        assert current["reassembly_passed"] and current["checksum_errors"] == 0
        if current["valid_control"]:
            if not previous["enforcement_passed"]:
                assert previous["daq_verdicts"].get("block", 0) > 0
                restored.append(name)
        else:
            assert current["daq_verdicts"].get("block", 0) > 0
            if not previous["daq_verdicts"].get("block", 0):
                assert previous["input_packet_sha256"] == previous["output_packet_sha256"]
                blocked.append(name)
            if not previous["enforcement_passed"]:
                strengthened.append(name)
            # A fresh-ID control may reassemble, but the conflicted one may not.
            assert current["reassemblies"] == int(current.get("isolation_control", False))
    return {"scope": "Matched local builds and synthetic file-only inline captures; no live endpoint or deployment proof.",
            "reports_sha256": {path.relative_to(ROOT).as_posix(): digest(path) for path in (before_path, after_path, build_path)},
            "comparison_source_sha256": digest(Path(__file__)), "binary_sha256": build["binary_sha256"],
            "summary": {"paired_cases": len(new), "native_runs": len(new) * 2, "repaired_passed": len(new),
                        "previously_fully_forwarded_conflict_cases_now_blocked": len(blocked),
                        "strengthened_conflict_enforcement_cases": len(strengthened),
                        "restored_valid_cases": len(restored),
                        "valid_controls": sum(case["valid_control"] for case in new.values()),
                        "retry_cases": sum(case["retries"] for case in new.values()),
                        "isolation_cases": sum(case.get("isolation_control", False) for case in new.values())},
            "newly_blocked_cases": blocked, "restored_valid_cases": restored, "strengthened_conflict_cases": strengthened}


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
