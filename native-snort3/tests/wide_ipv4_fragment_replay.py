#!/usr/bin/env python3
"""Regression for the signed fragment-width repair shared with IPv4."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import struct
import tempfile

import fragment_checksum_replay as base

if not __debug__:
    raise RuntimeError("validation requires assertions")


def fixtures():
    size = 65515  # Maximum payload with a 20-byte IPv4 header.
    for protocol in (6, 17, 1):
        if protocol == 6:
            plain = struct.pack("!HHIIBBHHH", 50000, 80, 100, 0, 80, 2, 65535, 0, 0)
            offset, counter = 16, ["tcp", "bad_tcp4_checksum"]
        elif protocol == 17:
            plain = struct.pack("!HHHH", 50000, 9999, size, 0)
            offset, counter = 6, ["udp", "bad_udp4_checksum"]
        else:
            plain = struct.pack("!BBHHH", 8, 0, 0, 1, 1)
            offset, counter = 2, ["icmp4", "bad_checksum"]
        plain += b"Z" * (size - len(plain))
        value = base.checksum(plain if protocol == 1 else base.pseudo(4, protocol, size) + plain)
        if protocol == 17:
            value = value or 65535
        body = plain[:offset] + struct.pack("!H", value) + plain[offset + 2:]
        for valid in (True, False):
            data = body if valid else body[:offset] + bytes([body[offset] ^ 1]) + body[offset + 1:]
            for split in (24, 32768, 50000, 65464):
                for order in ((0, 1), (1, 0)):
                    wires = base.fragments(4, protocol, data, [split], order)
                    item = {"name": f"v4-p{protocol}-split{split}-" + "".join(map(str, order)) + ("-valid" if valid else "-invalid"),
                            "frames": wires, "valid": valid, "counter": counter, "version": 4, "protocol": protocol,
                            "variant": "correct" if valid else "one-bit-error", "arrival_offsets": [0, split] if not order[0] else [split, 0],
                            "expected_reassemblies_min": 1, "expected_reassemblies_max": 1,
                            "expected_checksum_errors_per_reassembly": int(not valid)}
                    yield item
                    if not valid:
                        yield item | {"name": item["name"] + "-retry", "first_completion_index": 1,
                                      "frames": wires + [wires[-1], *wires]}


def validate(snort, plugin):
    snort, plugin = snort.resolve(strict=True), plugin.resolve(strict=True)
    binary = base.digest(snort.read_bytes())
    sources = [Path(__file__), *[base.HERE / name for name in (
        "fragment_checksum_replay.py", "checksum_replay.py", "generate_pcaps.py", "next_header_policy.py", "replay.py")]]
    hashes = {path.relative_to(base.ROOT).as_posix(): base.digest(path.read_bytes()) for path in sources}
    profiles = base.load_validator().validate(snort, plugin)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("AX_")}
    with tempfile.TemporaryDirectory(prefix="ax-wide-ipv4-") as temporary:
        directory = Path(temporary)
        for name in base.CONFIG_FILES:
            (directory / name).write_bytes((base.HERE.parent / name).read_bytes())
        cases = list(fixtures())
        assert len({item["name"] for item in cases}) == len(cases)
        for item in cases:
            base.verify_wire_oracle(item)
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda item: base.run_case(snort, plugin, directory / "protocol-ips.lua", directory, item, environment), cases))
    assert binary == base.digest(snort.read_bytes())
    for relative, expected in hashes.items() | profiles["sha256"].items():
        assert base.digest((base.ROOT / relative).read_bytes()) == expected
    libraries = [plugin] if plugin.is_file() else sorted(set(plugin.rglob("*.so")) | set(plugin.rglob("*.dylib")))
    assert profiles["plugin_sha256"] == {path.name: base.digest(path.read_bytes()) for path in libraries}
    failures = [item["name"] for item in results if not item["passed"]]
    return {"status": "conformance_failure" if failures else "verified_expected_behavior",
            "scope": "File-only inline DAQ of maximum-size IPv4 datagrams with original fragments exceeding 32767 bytes; no live endpoint or deployment.",
            "snort_binary_sha256": binary, "configuration": profiles, "fixture_source_sha256": hashes,
            "summary": {"cases": len(results), "passed": len(results) - len(failures), "failures": failures}, "cases": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snort", type=Path, required=True)
    parser.add_argument("--plugin-path", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = validate(args.snort, args.plugin_path)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["summary"], indent=2))
    raise SystemExit(bool(report["summary"]["failures"]))


if __name__ == "__main__":
    main()
