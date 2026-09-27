#!/usr/bin/env python3
"""Observe offset-zero IPv6 header retention without changing address identity.

Test-only rules match the Hop Limit on defragmented packets exclusively. An
observation policy records it; an enforcement policy drops reconstructed Hop
Limit 41 as an explicit local test policy. Neither is a product rule or a
claim that Hop Limit 41 is an RFC violation. All cases keep source/destination
addresses and valid transport checksums fixed.
"""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import struct
import tempfile

from home_address_replay import CARE, DEST, HERE, ROOT, digest, fixture, frame, run_case, transport, verify_oracle
from next_header_policy import CONFIG_FILES
from replay import load_validator

if not __debug__:
    raise RuntimeError("validation requires assertions")

RULES = '''
ips.rules = ips.rules .. [[
alert ip any any -> any any (msg:"AX offset-zero Hop Limit audit"; flow:only_frag; ttl:41; sid:2999011; rev:1;)
alert ip any any -> any any (msg:"AX continuation Hop Limit audit"; flow:only_frag; ttl:42; sid:2999012; rev:1;)
]]
ips.states = ips.states .. [[
alert ( gid:1; sid:2999011; enable:yes; )
alert ( gid:1; sid:2999012; enable:yes; )
]]
'''


def cases():
    pad = (60, bytes(8))
    long_pad = (60, bytes([0, 255]) + bytes(2046))
    layouts = (("plain", [], []), ("same-padding", [pad], [pad]),
               ("added-padding", [], [pad]), ("removed-padding", [pad], []),
               ("longer-continuation", [pad], [long_pad]),
               ("shorter-continuation", [long_pad], [pad]))
    for protocol in (6, 17, 58):
        data = transport(protocol, CARE, DEST)
        for label, first, continuation in layouts:
            for differs in (False, True):
                wires = []
                for start, end, prefix in ((0, 24, first), (24, 72, continuation)):
                    frag = (44, bytes(2) + struct.pack("!HI", start | int(end < 72), 9876))
                    wire = bytearray(frame(prefix + [frag], protocol, data[start:end]))
                    assert wire[14] >> 4 == 6
                    wire[14 + 7] = 42 if start and differs else 41
                    wires.append(bytes(wire))
                for order in ((0, 1), (1, 0)):
                    ordered = [wires[index] for index in order]
                    yield fixture(f"p{protocol}-{label}-" + "".join(map(str, order)) + ("-varied" if differs else "-control"),
                                  ordered, ordered, protocol, source=CARE, fragments=True, reassembled=1) | {
                                      "varied_hop_limit": differs, "arrival_order": list(order),
                                      "expected_rebuilt_rule": "1:2999011:1"}


def validate(snort, plugin):
    snort, plugin = snort.resolve(strict=True), plugin.resolve(strict=True)
    binary = digest(snort.read_bytes())
    sources = [Path(__file__), *[HERE / name for name in (
        "home_address_replay.py", "checksum_replay.py", "fragment_lifetime_replay.py",
        "fragment_checksum_replay.py", "generate_pcaps.py", "next_header_policy.py",
        "replay.py", "type2_repair_replay.py")]]
    hashes = {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in sources}
    profiles = load_validator().validate(snort, plugin)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("AX_")}
    original = (HERE.parent / "protocol-ips.lua").read_text()
    drop_rules = RULES.replace('alert ip any any -> any any (msg:"AX offset-zero',
                               'drop ip any any -> any any (msg:"AX offset-zero').replace(
                                   'alert ( gid:1; sid:2999011;', 'drop ( gid:1; sid:2999011;')
    configurations = {"observe": original + RULES, "enforce": original + drop_rules}
    with tempfile.TemporaryDirectory(prefix="ax-ipv6-fragment-header-") as temporary:
        directory = Path(temporary)
        for name in CONFIG_FILES:
            (directory / name).write_bytes((HERE.parent / name).read_bytes())
        for policy, configuration in configurations.items():
            (directory / (policy + ".lua")).write_text(configuration)
        items = [item | {"name": item["name"] + "-" + policy, "policy": policy,
                         "expected_frames": item["frames"][:-1] if policy == "enforce" else item["frames"]}
                 for item in cases() for policy in configurations]
        assert len({item["name"] for item in items}) == len(items)
        for item in items:
            verify_oracle(item)
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda item: run_case(snort, plugin, directory / (item["policy"] + ".lua"), directory, item, environment), items))
        for item in results:
            observations = [event["rule"] for event in item["events"] if event["rule"] in ("1:2999011:1", "1:2999012:1")]
            item["observed_rebuilt_rules"] = observations
            item["offset_zero_header_passed"] = observations == [item["expected_rebuilt_rule"]]
            item["passed"] = item["passed"] and item["offset_zero_header_passed"]
    assert binary == digest(snort.read_bytes())
    for relative, expected in hashes.items() | profiles["sha256"].items():
        assert digest((ROOT / relative).read_bytes()) == expected
    libraries = [plugin] if plugin.is_file() else sorted(set(plugin.rglob("*.so")) | set(plugin.rglob("*.dylib")))
    assert profiles["plugin_sha256"] == {path.name: digest(path.read_bytes()) for path in libraries}
    failures = [item["name"] for item in results if not item["passed"]]
    return {"status": "header_retention_failure" if failures else "verified_header_retention",
            "scope": "Synthetic file-only inline DAQ; defragmented Hop Limit observations with fixed source/destination identity. Not full extension-header semantics, ECN aggregation or endpoint/deployment proof.",
            "snort_binary_sha256": binary, "configuration": profiles,
            "fixture_source_sha256": hashes,
            "test_configuration_sha256": {name: digest(value.encode()) for name, value in configurations.items()},
            "summary": {"wire_cases": len(results) // 2, "native_runs": len(results),
                        "cases": len(results), "passed": len(results) - len(failures), "failures": failures,
                        "all_transport_checksums_passed": all(item["counter_passed"] for item in results),
                        "observation_policy_all_forwarded": all(item["enforcement_passed"] for item in results if item["policy"] == "observe"),
                        "local_policy_bypass_cases": sum(not item["enforcement_passed"] for item in results if item["policy"] == "enforce")},
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
    raise SystemExit(bool(result["summary"]["failures"]))


if __name__ == "__main__":
    main()
