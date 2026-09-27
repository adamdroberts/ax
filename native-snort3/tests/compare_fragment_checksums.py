#!/usr/bin/env python3
"""Verify and bind paired fragment replay reports to the matched local builds."""
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
    assert build["comparison"]["only_fragment_checksum_repair_changes"]
    assert before["configuration"] == after["configuration"]
    assert before["fixture_source_sha256"] == after["fixture_source_sha256"]
    assert before["snort_binary_sha256"] == build["binary_sha256"]["baseline"]
    assert after["snort_binary_sha256"] == build["binary_sha256"]["repaired"]
    for relative, expected in after["fixture_source_sha256"].items() | after["configuration"]["sha256"].items():
        assert digest(ROOT / relative) == expected, relative
    old = {case["name"]: case for case in before["cases"]}
    new = {case["name"]: case for case in after["cases"]}
    assert len(old) == len(before["cases"]) == len(new) == len(after["cases"])
    assert old.keys() == new.keys()
    newly_enforced, counter_only = [], []
    for name, current in new.items():
        previous = old[name]
        for field in ("valid", "version", "protocol", "variant", "arrival_offsets",
                      "input_packet_sha256", "input_pcap_sha256"):
            assert previous[field] == current[field], (name, field)
        assert current["passed"] and current["enforcement_passed"] and current["checksum_counter_passed"], name
        assert not current["invalid_datagram_fully_forwarded"], name
        # Derive the old defect from protocol semantics, not a green baseline
        # expectation. Preserve the original nonzero audit exit and failures.
        old_accepts_invalid = (not previous["valid"] and previous["protocol"] != 6
                               and previous["variant"] != "zero")
        assert previous["invalid_datagram_fully_forwarded"] == old_accepts_invalid, name
        if old_accepts_invalid:
            newly_enforced.append(name)
        elif previous["enforcement_passed"] and not previous["checksum_counter_passed"]:
            assert previous["version"] == 6 and previous["protocol"] == 17 and previous["variant"] == "zero"
            counter_only.append(name)
    return {"scope": "Matched local source builds; identical input captures, rules, plugin and fixture oracles. No deployment or endpoint behavior tested.",
            "reports_sha256": {path.relative_to(ROOT).as_posix(): digest(path)
                              for path in (before_path, after_path, build_path)},
            "comparison_source_sha256": digest(Path(__file__)),
            "binary_sha256": build["binary_sha256"],
            "summary": {"paired_cases": len(new), "packet_replay_runs": 2 * len(new),
                        "repaired_passed": len(new), "newly_enforced_invalid_cases": len(newly_enforced),
                        "previously_blocked_zero_checksum_cases_with_repaired_counters": len(counter_only),
                        "valid_controls": sum(case["valid"] for case in new.values()),
                        "retry_cases": sum("first_completion_index" in case for case in new.values())},
            "newly_enforced_cases": newly_enforced,
            "counter_only_corrections": counter_only}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-report", type=Path, required=True)
    parser.add_argument("--repaired-report", type=Path, required=True)
    parser.add_argument("--build-report", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = compare(args.baseline_report.resolve(), args.repaired_report.resolve(), args.build_report.resolve())
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["summary"], indent=2))


if __name__ == "__main__":
    main()
