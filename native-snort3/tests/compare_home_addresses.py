#!/usr/bin/env python3
"""Compare matching wire fixtures across the engine and structural-plugin repair."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if not __debug__:
    raise RuntimeError("comparison requires assertions")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compare(before_path, after_path, build_path, plugin_path):
    before, after, build, plugin = (json.loads(path.read_text()) for path in (before_path, after_path, build_path, plugin_path))
    assert build["comparison"]["same_configuration"] and build["comparison"]["only_home_address_repair_changes"]
    assert plugin["same_sdk"]
    for name, report in (("baseline", before), ("repaired", after)):
        assert report["snort_binary_sha256"] == build["binary_sha256"][name]
        assert report["configuration"]["plugin_sha256"] == {"ax_nd_options.so": plugin[name]["plugin_sha256"]}
    assert {key: value for key, value in before["configuration"].items() if key != "plugin_sha256"} == {
        key: value for key, value in after["configuration"].items() if key != "plugin_sha256"}
    assert before["fixture_source_sha256"] == after["fixture_source_sha256"]
    assert before["normalizer_configuration_sha256"] == after["normalizer_configuration_sha256"]
    assert before["status"] == "conformance_failure" and after["status"] == "verified_expected_behavior"
    for relative, expected in after["fixture_source_sha256"].items() | after["configuration"]["sha256"].items():
        assert digest(ROOT / relative) == expected, relative
    for name, expected in plugin["repaired_source_sha256"].items():
        assert digest(ROOT / "native-snort3/plugins" / name) == expected, name
    assert plugin["repaired"]["source_sha256"]["home_address.h"] == build["source_repair"]["after_sha256"]["src/codecs/ip/ipv6_home_address.h"]
    previous, current = ({item["name"]: item for item in report["cases"]} for report in (before, after))
    assert len(previous) == len(before["cases"]) == len(current) == len(after["cases"]) and previous.keys() == current.keys()
    strengthened, restored, structured = [], [], []
    for name, item in current.items():
        old = previous[name]
        for field in ("protocol", "structural_rejection", "checksum_valid", "checksum_source", "checksum_destination",
                      "fragmented", "retry", "normalization", "expected_reassemblies", "expected_checksum_errors",
                      "expected_verdicts", "input_pcap_sha256", "input_packet_sha256", "expected_output_packet_sha256"):
            assert old[field] == item[field], (name, field)
        assert item["passed"] and item["enforcement_passed"] and item["counter_passed"] and item["structural_guard_passed"]
        if not old["enforcement_passed"]:
            if item["expected_verdicts"].get("block", 0):
                strengthened.append(name)
                if item["structural_rejection"]:
                    structured.append(name)
            else:
                restored.append(name)
    return {"scope": "Paired engine and plugin changes. Checksums and stateless structure only; variable IPv6 fragment-prefix failures are recorded separately.",
            "reports_sha256": {path.relative_to(ROOT).as_posix(): digest(path) for path in (before_path, after_path, build_path, plugin_path)},
            "comparison_source_sha256": digest(Path(__file__)), "binary_sha256": build["binary_sha256"],
            "plugin_sha256": {name: plugin[name]["plugin_sha256"] for name in ("baseline", "repaired")},
            "summary": {"paired_cases": len(current), "native_runs": 2 * len(current), "repaired_passed": len(current),
                "stronger_rejection_cases": len(strengthened), "newly_blocked_structural_cases": len(structured),
                "valid_forwarding_restored": len(restored), "structural_cases": after["summary"]["structural_cases"],
                "fragment_cases": after["summary"]["fragment_cases"], "retry_cases": after["summary"]["retry_cases"],
                "normalization_cases": after["summary"]["normalization_cases"]},
            "strengthened_cases": strengthened, "newly_blocked_structural_cases": structured, "restored_cases": restored}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-report", type=Path, required=True)
    parser.add_argument("--repaired-report", type=Path, required=True)
    parser.add_argument("--build-report", type=Path, required=True)
    parser.add_argument("--plugin-report", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = compare(args.baseline_report.resolve(), args.repaired_report.resolve(), args.build_report.resolve(), args.plugin_report.resolve())
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["summary"], indent=2))


if __name__ == "__main__":
    main()
