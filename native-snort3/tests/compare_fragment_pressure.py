#!/usr/bin/env python3
"""Compare pressure audits bound to matched cumulative native source builds."""
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
    assert build["comparison"]["same_configuration"] and build["comparison"]["only_fragment_pressure_repair_changes"]
    assert before["configuration"] == after["configuration"]
    assert before["fixture_source_sha256"] == after["fixture_source_sha256"]
    assert before["special_configuration_sha256"] == after["special_configuration_sha256"]
    assert before["snort_binary_sha256"] == build["binary_sha256"]["baseline"]
    assert after["snort_binary_sha256"] == build["binary_sha256"]["repaired"]
    assert before["status"] == "conformance_failure" and after["status"] == "verified_expected_behavior"
    for relative, expected in after["fixture_source_sha256"].items() | after["configuration"]["sha256"].items():
        assert digest(ROOT / relative) == expected, relative
    old, new = ({item["name"]: item for item in report["cases"]} for report in (before, after))
    assert len(old) == len(before["cases"]) == len(new) == len(after["cases"]) and old.keys() == new.keys()
    strengthened, fully_forwarded, prevented_reassembly, restored_rejection = [], [], [], []
    for name, current in new.items():
        previous = old[name]
        for field in ("kind", "version", "protocol", "max_frags", "max_flows", "policy", "retries", "recovery",
                      "bad_datagrams", "times_us", "expected_indices", "valid_control", "expected_counters",
                      "expected_checksum_errors", "expected_verdicts", "input_packet_sha256", "input_pcap_sha256",
                      "expected_output_packet_sha256"):
            assert current[field] == previous[field], (name, field)
        assert current["passed"] and current["enforcement_passed"] and current["counter_passed"], name
        assert current["pressure_telemetry_present"] and not previous["pressure_telemetry_present"]
        assert current["counters"]["max_fragment_nodes"] <= current["max_frags"]
        if current["valid_control"]:
            assert previous["passed"] and previous["input_packet_sha256"] == current["output_packet_sha256"], name
        else:
            assert current["daq_verdicts"].get("block", 0) > 0
            if not previous["enforcement_passed"]:
                strengthened.append(name)
            if not previous["daq_verdicts"].get("block", 0):
                assert previous["input_packet_sha256"] == previous["output_packet_sha256"]
                fully_forwarded.append(name)
            if previous["counters"]["reassembled"] > current["counters"]["reassembled"]:
                prevented_reassembly.append(name)
        if current["kind"] == "state-loss":
            # Packet 1 is a checksum-rejected tail, repeated after eviction.
            rejected = current["input_packet_sha256"][1]
            assert rejected in previous["output_packet_sha256"]
            assert rejected not in current["output_packet_sha256"]
            restored_rejection.append(name)
    return {"scope": "Matched local builds and actual inline file DAQ; finite pressure policy, not live overload or deployment assurance.",
            "reports_sha256": {path.relative_to(ROOT).as_posix(): digest(path) for path in (before_path, after_path, build_path)},
            "comparison_source_sha256": digest(Path(__file__)), "binary_sha256": build["binary_sha256"],
            "summary": {"paired_cases": len(new), "native_runs": 2 * len(new), "repaired_passed": len(new),
                        "stronger_enforcement_cases": len(strengthened),
                        "previously_fully_forwarded_pressure_cases": len(fully_forwarded),
                        "prevented_reassembly_cases": len(prevented_reassembly),
                        "rejected_retry_protections_restored": len(restored_rejection),
                        "valid_controls": sum(item["valid_control"] for item in new.values()),
                        "retry_cases": sum(item["retries"] for item in new.values()),
                        "recovery_cases": sum(item["recovery"] for item in new.values())},
            "strengthened_cases": strengthened, "previously_fully_forwarded_cases": fully_forwarded,
            "prevented_reassembly_cases": prevented_reassembly, "restored_rejection_cases": restored_rejection}


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
