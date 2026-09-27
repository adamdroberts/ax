#!/usr/bin/env python3
"""Bind native AddressSanitizer builds and replays to the release source snapshot."""
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
if not __debug__:
    raise RuntimeError("evidence requires assertions")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record(build_root, release_root, harness):
    directory = build_root / "repaired"
    manifest = json.loads((directory / "build-manifest.json").read_text())
    assert manifest["returncode"] == manifest["version_returncode"] == 0
    assert manifest["source_unchanged_during_build"]
    assert manifest["builder_sha256"] == digest(HERE / "build_snapshot.py")
    for name, expected in manifest["files"].items():
        assert digest(directory / name) == expected, name
    sources = json.loads((directory / "source-hashes.json").read_text())
    assert sources == json.loads((release_root / "repaired/source-hashes.json").read_text())
    actual = {path.relative_to(build_root / "source").as_posix(): digest(path)
              for path in (build_root / "source").rglob("*") if path.is_file()}
    assert actual == sources
    configuration = json.loads((build_root / "configure-manifest.json").read_text())
    release_configuration = json.loads((release_root / "configure-manifest.json").read_text())
    expected_command = [arg.replace(str(release_root), str(build_root)) for arg in release_configuration["command"]]
    assert configuration["command"] == expected_command + ["-DENABLE_ADDRESS_SANITIZER=ON"]
    assert configuration["environment"] == release_configuration["environment"]
    assert configuration["returncode"] == 0
    assert "ENABLE_ADDRESS_SANITIZER:BOOL=ON" in (directory / "CMakeCache.txt").read_text()
    commands = json.loads((directory / "compile_commands.json").read_text())
    checked_units = {}
    for name in ("src/stream/ip/ip_defrag.cc", "src/stream/ip/ip_session.cc", "src/protocols/packet_manager.cc"):
        matches = [item for item in commands if item["file"] == str(build_root / "source" / name)]
        assert len(matches) == 1 and "-fsanitize=address" in matches[0]["command"]
        checked_units[name] = matches[0]["command"]
    suites = {}
    for name, release_name in (("extent-validation", "../fragment-extent-validation"),
                               ("overlap-validation", "overlap-validation"),
                               ("ipv4-prefix-validation", "ipv4-prefix-validation"),
                               ("fragment-options-validation", "fragment-options-validation"),
                               ("wide-ipv4-validation", "wide-ipv4-validation"),
                               ("ipv6-prefix-validation", "ipv6-prefix-validation"),
                               ("fragment-pressure-validation", "fragment-pressure-validation"),
                               ("fragment-lifetime-validation", "fragment-lifetime-validation")):
        path = HERE.parent / "fragment-extent-asan" / (name + ".json")
        report = json.loads(path.read_text())
        release_path = HERE.parent / "fragment-extent-repaired-engine" / (release_name + ".json")
        release = json.loads(release_path.read_text())
        assert report["snort_binary_sha256"] == manifest["binary_sha256"] == digest(directory / "snort")
        assert report["fixture_source_sha256"] == release["fixture_source_sha256"]
        assert report["configuration"]["sha256"] == release["configuration"]["sha256"]
        assert report["configuration"]["plugin_sha256"] == release["configuration"]["plugin_sha256"]
        assert not report["summary"]["failures"] and all(case["passed"] for case in report["cases"])
        before = {case["name"]: case for case in release["cases"]}
        assert len(before) == len(report["cases"])
        for case in report["cases"]:
            for key in ("input_packet_sha256", "input_pcap_sha256", "output_packet_sha256", "daq_verdicts", "expected_rebuilt_packet_sha256", "rebuilt_packet_sha256", "counters"):
                assert case.get(key) == before[case["name"]].get(key), (name, case["name"], key)
        for name_, expected in report["fixture_source_sha256"].items() | report["configuration"]["sha256"].items():
            assert digest(ROOT / name_) == expected, name_
        suites[path.relative_to(ROOT).as_posix()] = {"sha256": digest(path), "cases": report["summary"]["cases"]}
    assert "env['ASAN_OPTIONS']='halt_on_error=1:abort_on_error=1'" in harness.read_text()
    return {"scope": "Native AddressSanitizer build and finite file-only replay; no leak, race, external-library instrumentation, deployment or universal memory-safety proof.",
            "source_matches_release": True, "sanitizer": "address",
            "environment": {"ASAN_OPTIONS": "halt_on_error=1:abort_on_error=1"},
            "build": manifest, "configuration": configuration, "instrumented_units": checked_units,
            "replay_reports": suites, "total_cases": sum(item["cases"] for item in suites.values()),
            "harness": str(harness), "harness_sha256": digest(harness), "recorder_sha256": digest(Path(__file__)),
            "release_build_report_sha256": digest(HERE.parent / "fragment-extent-build-validation.json")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--release-build-root", type=Path, required=True)
    parser.add_argument("--harness", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = record(args.build_root.resolve(), args.release_build_root.resolve(), args.harness.resolve())
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"cases": result["total_cases"], "binary_sha256": result["build"]["binary_sha256"]}, indent=2))


if __name__ == "__main__":
    main()
