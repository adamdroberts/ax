#!/usr/bin/env python3
"""Audit Type 2 routing pseudoheader checksums with file-only inline DAQ.

This is a conformance audit, not a passing protection test. The pinned decoder
currently rejects final-destination checksums and accepts base-destination
checksums. Reports retain that failure explicitly; a mismatch exits nonzero.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

from checksum_replay import module_count, write_pcap
from generate_pcaps import checksum, ip6, packet
from next_header_policy import CONFIG_FILES, run_capture
from replay import load_validator

if not __debug__:
    raise RuntimeError("audit requires assertions; do not use -O or PYTHONOPTIMIZE")

HERE = Path(__file__).resolve().parent
NATIVE = HERE.parent
ROOT = NATIVE.parent
SOURCE = "2001:db8::1"
CARE_OF = "2001:db8::2"
HOME = "2001:db8::3"
UPSTREAM_FILES = ("src/codecs/ip/cd_routing.cc", "src/codecs/ip/cd_tcp.cc",
                  "src/codecs/ip/cd_udp.cc", "src/codecs/ip/cd_icmp6.cc")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pseudoheader(destination, protocol, length):
    return (ipaddress.IPv6Address(SOURCE).packed + ipaddress.IPv6Address(destination).packed
            + struct.pack("!I3xB", length, protocol))


def cases():
    protocols = (
        ("tcp-syn", 6, struct.pack("!HHIIBBHHH", 50000, 80, 100, 0, 80, 2, 65535, 0, 0),
         16, "tcp", "bad_tcp6_checksum"),
        ("udp", 17, struct.pack("!HHHH", 50000, 9999, 13, 0) + b"hello",
         6, "udp", "bad_udp6_checksum"),
        ("icmpv6-echo", 58, struct.pack("!BBHHH", 128, 0, 0, 1, 1),
         2, "icmp6", "bad_icmp6_checksum"),
    )
    for name, protocol, plain, offset, module, counter in protocols:
        pair = []
        for basis, destination in (("final-home-address", HOME), ("incorrect-base-address", CARE_OF)):
            value = checksum(pseudoheader(destination, protocol, len(plain)) + plain)
            if protocol == 17:
                value = value or 0xffff
            body = plain[:offset] + struct.pack("!H", value) + plain[offset + 2:]
            home_residue = checksum(pseudoheader(HOME, protocol, len(body)) + body)
            base_residue = checksum(pseudoheader(CARE_OF, protocol, len(body)) + body)
            rfc_valid = destination == HOME
            assert (home_residue == 0) == rfc_valid
            assert (base_residue == 0) != rfc_valid
            routing = bytes([protocol, 2, 2, 1]) + b"\0" * 4 + ipaddress.IPv6Address(HOME).packed
            frame = packet(ip6(routing + body, 43, source=SOURCE, destination=CARE_OF), 6)
            pair.append(frame)
            yield {"name": name + "-" + basis, "protocol": name,
                   "next_header": protocol, "checksum_basis": basis,
                   "checksum_value": value, "rfc_checksum_valid": rfc_valid,
                   "final_destination_checksum_residue": home_residue,
                   "base_destination_checksum_residue": base_residue,
                   "checksum_counter": [module, counter], "frame": frame}
        # All routing, addressing, payload and transport fields are identical;
        # only the two checksum octets can differ between each pair.
        start = 14 + 40 + 24 + offset
        assert pair[0][:start] == pair[1][:start]
        assert pair[0][start + 2:] == pair[1][start + 2:]
        assert pair[0][start:start + 2] != pair[1][start:start + 2]


def audit(snort, plugin, upstream):
    snort, plugin, upstream = (path.resolve(strict=True) for path in (snort, plugin, upstream))
    sources = (Path(__file__), HERE / "checksum_replay.py", HERE / "generate_pcaps.py",
               HERE / "next_header_policy.py", HERE / "replay.py")
    source_hashes = {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in sources}
    profiles = load_validator().validate(snort, plugin)
    commit = subprocess.check_output(["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True).strip()
    assert commit == profiles["source_commit"], "source checkout is not the reviewed Snort commit"
    upstream_hashes = {}
    for relative in UPSTREAM_FILES:
        data = (upstream / relative).read_bytes()
        committed = subprocess.check_output(["git", "-C", str(upstream), "show", "HEAD:" + relative])
        assert data == committed, "reviewed upstream source has local changes: " + relative
        upstream_hashes[relative] = digest(data)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("AX_")}
    binary_hash = digest(snort.read_bytes())
    configuration = {name: (NATIVE / name).read_bytes() for name in CONFIG_FILES}
    results = []
    with tempfile.TemporaryDirectory(prefix="ax-mobility-checksum-") as temporary:
        directory = Path(temporary)
        for name, data in configuration.items():
            (directory / name).write_bytes(data)
        for case in list(cases()):
            capture = directory / (case["name"] + ".pcap")
            output = directory / (case["name"] + "-forwarded.pcap")
            write_pcap(capture, [case["frame"]])
            observed = run_capture(snort, plugin, directory / "protocol-ips.lua", capture,
                                   output, environment, include_stdout=True)
            stdout = observed.pop("stdout")
            errors = module_count(stdout, *case["checksum_counter"])
            bypassed = module_count(stdout, case["checksum_counter"][0], "checksum_bypassed")
            assert bypassed == 0, "checksum-offload metadata must not bypass this file audit"
            if not observed["blocked"]:
                assert observed["output_packet_sha256"] == [digest(case["frame"])]
            valid = case["rfc_checksum_valid"]
            counter_conformant = errors == int(not valid)
            verdict_conformant = observed["blocked"] == (not valid)
            # This describes evidence of the known failure, never a successful
            # standards/protection assertion. It becomes false if fixed.
            inverted = (errors == int(valid) and observed["blocked"] == valid
                        and observed["daq_verdict"] == ("block" if valid else "allow"))
            results.append({key: value for key, value in case.items() if key != "frame"} | {
                "input_pcap_sha256": digest(capture.read_bytes()), "input_packet_sha256": digest(case["frame"]),
                "observed_checksum_errors": errors, "observed_checksum_bypasses": bypassed,
                "checksum_counter_conformant": counter_conformant,
                "isolated_fixture_verdict_conformant": verdict_conformant,
                "known_inverted_behavior_reproduced": inverted, **observed})
    assert source_hashes == {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in sources}, "audit source changed during run"
    assert upstream_hashes == {relative: digest((upstream / relative).read_bytes()) for relative in UPSTREAM_FILES}, "reviewed upstream source changed during run"
    for relative, expected in profiles["sha256"].items():
        assert digest((ROOT / relative).read_bytes()) == expected, "configuration/source changed: " + relative
    plugin_files = [plugin] if plugin.is_file() else sorted(set(plugin.rglob("*.so")) | set(plugin.rglob("*.dylib")))
    assert profiles["plugin_sha256"] == {path.name: digest(path.read_bytes()) for path in plugin_files}, "plugin changed during run"
    assert binary_hash == digest(snort.read_bytes()), "Snort binary changed during run"
    failures = [case["name"] for case in results
                if not case["checksum_counter_conformant"] or not case["isolated_fixture_verdict_conformant"]]
    reproduced = sum(case["known_inverted_behavior_reproduced"] for case in results)
    return {
        "status": ("known_conformance_failure" if reproduced == len(results) else "conformance_failure")
                  if failures else "checksum_behavior_matches_oracle",
        "snort_version": profiles["snort_version"], "snort_binary_sha256": binary_hash,
        "scope": "File-only inline dump:pcap DAQ, with actual checksum counters, verdicts and forwarded packet captures. No interfaces, endpoints or deployment paths are tested.",
        "configuration": profiles,
        "fixture": {"source": SOURCE, "ipv6_base_destination_care_of": CARE_OF,
                    "type2_home_address_final_destination": HOME, "routing_type": 2,
                    "hdr_ext_len": 2, "segments_left": 1, "reserved": 0,
                    "pair_delta": "Only the two upper-layer checksum octets differ within each protocol pair."},
        "references": ["https://www.rfc-editor.org/rfc/rfc8200.html#section-8.1",
                       "https://www.rfc-editor.org/rfc/rfc6275.html#section-6.4",
                       "https://www.rfc-editor.org/rfc/rfc6275.html#section-11.3.3"],
        "reviewed_upstream": {"commit": commit, "sha256": upstream_hashes,
                              "scope": "Source inspection for the pinned release; not a reproducible-build attestation.",
                              "finding": "The routing codec advances extension framing but does not provide the final Home Address to TCP, UDP or ICMPv6 checksum calculations, which read the IPv6 base destination."},
        "fixture_source_sha256": source_hashes,
        "summary": {"cases": len(results), "standards_passed": len(results) - len(failures),
                    "rfc_checksum_mismatches": len(failures), "conformance_failures": failures,
                    "defect_reproduced": reproduced,
                    "correct_final_destination_checksums_rejected": sum(case["rfc_checksum_valid"] and case["blocked"] for case in results),
                    "incorrect_base_destination_checksums_accepted": sum(not case["rfc_checksum_valid"] and not case["blocked"] for case in results)},
        "limitations": ["These six bounded Type 2 shapes do not establish full Mobile IPv6 conformance or exploitability.",
                        "The oracle covers checksum pseudoheaders; Mobile IPv6 binding ownership and endpoint authorization are not established by synthetic addresses.",
                        "Incorrect-checksum acceptance here is a sensor parsing/validation failure; no claim is made that a conforming endpoint accepts the packet.",
                        "This artifact records an unresolved decoder failure. Reproducing it is not successful attack prevention."],
        "cases": results,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snort", type=Path, required=True)
    parser.add_argument("--plugin-path", type=Path, required=True)
    parser.add_argument("--snort-source", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = audit(args.snort, args.plugin_path, args.snort_source)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "summary": report["summary"]}, indent=2))
    if report["summary"]["rfc_checksum_mismatches"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
