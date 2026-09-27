#!/usr/bin/env python3
"""Verify existing structure/Type 2 behavior on the cumulative repaired engine.

Three existing source-route errors now also raise an IPv4 option event in the
decoder. This runner requires that earlier event and the original structural
rule, while keeping protocol errors separate from checksum-error counters.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import tempfile

from checksum_replay import module_count, write_pcap
from next_header_policy import CONFIG_FILES, run_capture
from replay import load_validator
import structure_replay as structure
import type2_repair_replay as type2

if not __debug__:
    raise RuntimeError("validation requires assertions")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
EARLY_ROUTES = {"ipv4-options-lsrr-pointer-zero": bytes.fromhex("83030000"),
                "ipv4-options-ssrr-pointer-three": bytes.fromhex("89030300"),
                "ipv4-options-mixed-source-route": bytes.fromhex("8303048903040000")}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def validate(snort, plugin):
    snort, plugin = snort.resolve(strict=True), plugin.resolve(strict=True)
    binary_hash = digest(snort.read_bytes())
    sources = [Path(__file__), HERE / "structure_replay.py", HERE / "type2_repair_replay.py",
               HERE / "checksum_replay.py", HERE / "next_header_policy.py", HERE / "generate_pcaps.py", HERE / "replay.py"]
    hashes = {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in sources}
    profiles = load_validator().validate(snort, plugin)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("AX_")}
    fixtures = [dict(case, group="structure") for case in structure.cases()]
    fixtures += [dict(case, group="type2") for case in type2.fixtures()]
    assert {case["name"] for case in fixtures if case["name"] in EARLY_ROUTES} == EARLY_ROUTES.keys()
    with tempfile.TemporaryDirectory(prefix="ax-cumulative-replay-") as temporary:
        directory = Path(temporary)
        for name in CONFIG_FILES:
            (directory / name).write_bytes((HERE.parent / name).read_bytes())
        text = (directory / "protocol-ips.lua").read_text()
        normal = "normalizer = { tcp = { ips = true, block = true, trim_win = true } }"
        assert text.count(normal) == 1
        special = text.replace(normal, normal.replace("{ tcp =", "{ ip6 = true, tcp =").replace(
            "ips = true", "rsv = true, ips = true"))
        (directory / "normalize.lua").write_text(special)

        def check(case):
            capture = directory / (case["group"] + "-" + case["name"] + ".pcap")
            output = capture.with_name(capture.stem + "-out.pcap")
            write_pcap(capture, [case["frame"]])
            config = directory / ("normalize.lua" if case.get("normalization") else "protocol-ips.lua")
            observed = run_capture(snort, plugin, config, capture, output, environment, include_stdout=True)
            stdout = observed.pop("stdout")
            early = case["name"] in EARLY_ROUTES
            if case["group"] == "structure":
                rule = case["expected_rule"]
                if rule:
                    matched = any([int(value) for value in event["rule"].split(":")[:2]] == rule
                                  for event in observed["events"])
                    passed = observed["blocked"] and matched
                    if early:
                        ip = case["frame"][14:]
                        length = (ip[0] & 15) * 4
                        assert rule == [1, 9201012] and ip[9] == 17
                        assert ip[20:length] == EARLY_ROUTES[case["name"]]
                        assert ip[length + 6:length + 8] == b"\0\0"
                        observed["checksum_errors"] = module_count(stdout, "udp", "bad_udp4_checksum")
                        observed["checksum_bypassed"] = module_count(stdout, "udp", "checksum_bypassed")
                        native_matched = any(event["rule"].split(":")[:2] == ["116", "4"] for event in observed["events"])
                        passed = (passed and native_matched and observed["checksum_errors"] == 0
                                  and observed["checksum_bypassed"] == 0)
                else:
                    passed = not observed["blocked"] and observed["output_packet_sha256"] == [digest(case["frame"])]
            else:
                errors = module_count(stdout, *case["counter"])
                bypassed = module_count(stdout, case["counter"][0], "checksum_bypassed")
                observed.update(checksum_errors=errors, checksum_bypassed=bypassed)
                passed = (observed["blocked"] == (not case["valid"]) and errors == int(not case["valid"])
                          and bypassed == 0)
                if case["valid"]:
                    passed = passed and observed["output_packet_sha256"] == [digest(case["expected_frame"])]
            return {key: value for key, value in case.items() if key not in ("frame", "expected_frame")} | {
                "passed": passed, "earlier_route_decoder_rejection": early,
                "input_packet_sha256": digest(case["frame"]), **observed}

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(check, fixtures))
    assert binary_hash == digest(snort.read_bytes())
    for relative, expected in hashes.items() | profiles["sha256"].items():
        assert digest((ROOT / relative).read_bytes()) == expected
    libraries = [plugin] if plugin.is_file() else sorted(set(plugin.rglob("*.so")) | set(plugin.rglob("*.dylib")))
    assert profiles["plugin_sha256"] == {path.name: digest(path.read_bytes()) for path in libraries}
    failures = [case["name"] for case in results if not case["passed"]]
    return {"scope": "Actual file-only inline DAQ verdicts and output bytes for existing fixtures; no live deployment.",
            "snort_binary_sha256": binary_hash, "configuration": profiles, "fixture_source_sha256": hashes,
            "normalizer_fixture_configuration_sha256": digest(special.encode()),
            "source_route_decode_guard": "Three malformed IPv4 source routes now raise native IPv4-option event 116:4 from the UDP decoder as well as rule 9201012. Both events, required rejection and zero checksum-failure counters are checked.",
            "summary": {"cases": len(results), "passed": len(results) - len(failures), "failures": failures,
                        "structure_cases": sum(case["group"] == "structure" for case in results),
                        "type2_cases": sum(case["group"] == "type2" for case in results),
                        "earlier_route_decoder_rejections": sum(case["earlier_route_decoder_rejection"] for case in results)},
            "cases": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snort", type=Path, required=True)
    parser.add_argument("--plugin-path", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = validate(args.snort, args.plugin_path)
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["summary"], indent=2))
    if result["summary"]["failures"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
