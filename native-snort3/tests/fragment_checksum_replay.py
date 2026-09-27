#!/usr/bin/env python3
"""Audit complete fragmented datagrams using file-only inline DAQ output."""
import argparse
import hashlib
import ipaddress
import itertools
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from checksum_replay import module_count, write_pcap
from generate_pcaps import checksum, ip6, packet
from next_header_policy import CONFIG_FILES, VERDICTS, pcap_packets
from replay import load_validator

if not __debug__:
    raise RuntimeError("validation requires assertions")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pseudo(version, protocol, length, routed=False):
    source = "192.0.2.10" if version == 4 else "2001:db8::1"
    destination = "198.51.100.20" if version == 4 else ("2001:db8::3" if routed else "2001:db8::2")
    trailer = struct.pack("!BBH", 0, protocol, length) if version == 4 else struct.pack("!I3xB", length, protocol)
    return ipaddress.ip_address(source).packed + ipaddress.ip_address(destination).packed + trailer


def ipv4_fragment(body, protocol, offset, more):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 1234,
                         offset // 8 | (0x2000 if more else 0), 64, protocol, 0,
                         ipaddress.IPv4Address("192.0.2.10").packed,
                         ipaddress.IPv4Address("198.51.100.20").packed)
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + body


def fragments(version, protocol, body, cuts, order, before=b"", after=b""):
    payload = after + body
    offsets = [0, *cuts, len(payload)]
    assert sorted(set(offsets)) == offsets
    frames = []
    for start, end in zip(offsets, offsets[1:]):
        more = end != len(payload)
        assert start % 8 == 0 and (not more or (end - start) % 8 == 0)
        if version == 4:
            frame = packet(ipv4_fragment(payload[start:end], protocol, start, more))
        else:
            header = struct.pack("!BBHI", 60 if after else protocol, 0, start | int(more), 0x12345678)
            frame = packet(ip6(before + header + payload[start:end], 43 if before else 44), 6)
        frames.append(frame)
    return [frames[index] for index in order]


def base_fixtures():
    for version in (4, 6):
        for protocol in (6, 17, 1 if version == 4 else 58):
            if protocol == 6:
                plain = struct.pack("!HHIIBBHHH", 50000, 80, 100, 0, 80, 2, 65535, 0, 0) + b"a" * 52
                offset, split, module, counter = 16, 24, "tcp", f"bad_tcp{version}_checksum"
            elif protocol == 17:
                plain = struct.pack("!HHHH", 50000, 9999, 72, 0) + b"a" * 64
                offset, split, module, counter = 6, 8, "udp", f"bad_udp{version}_checksum"
            else:
                plain = struct.pack("!BBHHH", 8 if version == 4 else 128, 0, 0, 1, 1) + b"a" * 64
                offset, split, module, counter = 2, 8, "icmp4" if version == 4 else "icmp6", "bad_checksum" if version == 4 else "bad_icmp6_checksum"
            covered = plain if protocol == 1 else pseudo(version, protocol, len(plain)) + plain
            value = checksum(covered)
            if protocol == 17:
                value = value or 0xffff
            correct = plain[:offset] + struct.pack("!H", value) + plain[offset + 2:]
            variants = [("correct", correct, True),
                        ("one-bit-error", correct[:offset] + bytes([correct[offset] ^ 1]) + correct[offset + 1:], False)]
            if protocol == 17:
                variants.append(("zero", plain, version == 4))
            for label, body, valid in variants:
                residue = checksum(body if protocol == 1 else pseudo(version, protocol, len(body)) + body)
                if label != "zero":
                    assert (residue == 0) == valid
                layouts = ([split], [split, 48])
                if version == 4 and protocol == 6:
                    # IPv4 may split its TCP header; IPv6's complete first
                    # header-chain rule must not be incorrectly applied here.
                    layouts += ([8], [8, 16], [16])
                for cuts in layouts:
                    offsets = [0, *cuts]
                    for order in itertools.permutations(range(len(offsets))):
                        frames = fragments(version, protocol, body, cuts, order)
                        yield {"name": f"v{version}-{module}-{label}-" + "-".join(str(offsets[i]) for i in order),
                               "frames": frames, "valid": valid, "counter": [module, counter],
                               "version": version, "protocol": protocol, "variant": label,
                               "arrival_offsets": [offsets[i] for i in order],
                               "expected_reassemblies_min": 1, "expected_reassemblies_max": 1,
                               "expected_checksum_errors_per_reassembly": int(not valid)}
    yield from extension_fixtures()


def fixtures():
    base = list(base_fixtures())
    yield from base
    for original in base:
        if len(original["frames"]) != 2:
            continue
        for repeated in (False, True):
            # Once an invalid datagram is rejected, its missing fragment must
            # not slip through on retry while earlier bytes remain downstream.
            suffix = original["frames"] if repeated else original["frames"][-1:]
            yield original | {"name": original["name"] + ("-repeat-datagram" if repeated else "-retry-completing"),
                              "frames": original["frames"] + suffix,
                              "first_completion_index": 1,
                              "expected_reassemblies_min": 2 if repeated and original["valid"] else 1,
                              "expected_reassemblies_max": (2 if repeated else 1) if original["valid"] else 1 + len(suffix)}


def verify_wire_oracle(case):
    """Independently reconstruct the first datagram from serialized frames.

    Uses modular word summation, not the generator's folding checksum helper.
    This oracle deliberately supports only the exact fixture header shapes.
    """
    def valid_sum(data):
        return sum(int.from_bytes(data[i:i + 2].ljust(2, b"\0"), "big")
                   for i in range(0, len(data), 2)) % 65535 == 0

    initial = case["frames"][:case.get("first_completion_index", len(case["frames"]) - 1) + 1]
    parts, terminal = {}, None
    upper, source, destination = None, None, None
    for frame in initial:
        network = frame[14:]
        if case["version"] == 4:
            assert frame[12:14] == b"\x08\0" and network[0] == 0x45
            assert len(network) == int.from_bytes(network[2:4], "big") and valid_sum(network[:20])
            field = int.from_bytes(network[6:8], "big")
            offset, more, part = (field & 0x1fff) * 8, bool(field & 0x2000), network[20:]
            source, destination, upper = network[12:16], network[16:20], network[9]
        else:
            assert frame[12:14] == b"\x86\xdd" and network[0] == 0x60
            assert len(network) == 40 + int.from_bytes(network[4:6], "big")
            source, destination, next_header = network[8:24], network[24:40], network[6]
            cursor = 40
            if next_header == 43:
                assert network[cursor + 1:cursor + 4] == b"\x02\x02\x01"
                destination = network[cursor + 8:cursor + 24]
                next_header, cursor = network[cursor], cursor + 24
            assert next_header == 44
            field = int.from_bytes(network[cursor + 2:cursor + 4], "big")
            offset, more, part = field & 0xfff8, bool(field & 1), network[cursor + 8:]
            if offset == 0:
                upper = network[cursor]
        assert offset not in parts and (not more or len(part) % 8 == 0)
        parts[offset] = part
        if not more:
            assert terminal is None
            terminal = offset + len(part)
    payload = b""
    for offset, part in sorted(parts.items()):
        assert offset == len(payload)
        payload += part
    assert len(payload) == terminal
    if case["version"] == 6 and upper == 60:
        assert payload[1] == 0
        upper, payload = payload[0], payload[8:]
    assert upper == case["protocol"]
    if upper == 17:
        assert int.from_bytes(payload[4:6], "big") == len(payload)
        if payload[6:8] == b"\0\0":
            assert case["valid"] == (case["version"] == 4)
            return
    trailer = struct.pack("!BBH", 0, upper, len(payload)) if case["version"] == 4 else struct.pack("!I3xB", len(payload), upper)
    covered = payload if upper == 1 else source + destination + trailer + payload
    assert valid_sum(covered) == case["valid"], case["name"]


def extension_fixtures():
    route = bytes([44, 2, 2, 1]) + b"\0" * 4 + ipaddress.IPv6Address("2001:db8::3").packed
    for protocol, module, offset in ((6, "tcp", 16), (17, "udp", 6), (58, "icmp6", 2)):
        for routed, post in ((True, False), (False, True), (True, True)):
            # Odd length forces correct one's-complement padding after the
            # complete transport datagram, not separately for fragments.
            if protocol == 6:
                plain = struct.pack("!HHIIBBHHH", 50000, 80, 100, 0, 80, 2, 65535, 0, 0) + b"a" * 53
            elif protocol == 17:
                plain = struct.pack("!HHHH", 50000, 9999, 73, 0) + b"a" * 65
            else:
                plain = struct.pack("!BBHHH", 128, 0, 0, 1, 1) + b"a" * 65
            value = checksum(pseudo(6, protocol, len(plain), routed) + plain)
            if protocol == 17:
                value = value or 0xffff
            correct = plain[:offset] + struct.pack("!H", value) + plain[offset + 2:]
            assert checksum(pseudo(6, protocol, len(correct), routed) + correct) == 0
            for valid in (True, False):
                body = correct if valid else correct[:offset] + bytes([correct[offset] ^ 1]) + correct[offset + 1:]
                after = bytes([protocol, 0]) + b"\0" * 6 if post else b""
                split = (24 if protocol == 6 else 8) + len(after)
                for order in ((0, 1), (1, 0)):
                    frames = fragments(6, protocol, body, [split], order, route if routed else b"", after)
                    yield {"name": f"v6-{module}-route-{int(routed)}-dest-{int(post)}-odd-" +
                           ("correct" if valid else "one-bit-error") + "-" + "".join(map(str, order)),
                           "frames": frames, "valid": valid, "counter": [module,
                           {6: "bad_tcp6_checksum", 17: "bad_udp6_checksum", 58: "bad_icmp6_checksum"}[protocol]],
                           "version": 6, "protocol": protocol,
                           "variant": "correct" if valid else "one-bit-error",
                           "routing_type2": routed, "post_fragment_destination": post,
                           "arrival_offsets": [0, split] if order == (0, 1) else [split, 0],
                           "expected_reassemblies_min": 1, "expected_reassemblies_max": 1,
                           "expected_checksum_errors_per_reassembly": int(not valid)}


def run_case(snort, plugin, config, directory, case, environment):
    capture = directory / (case["name"] + ".pcap")
    output = directory / (case["name"] + "-forwarded.pcap")
    write_pcap(capture, case["frames"])
    command = [str(snort), "--plugin-path", str(plugin), "-c", str(config),
               "--daq", "pcap", "--daq-mode", "read-file", "--daq", "dump", "--daq-mode", "inline",
               "--daq-var", "file=" + str(output), "-Q", "-r", str(capture), "-s", "65535", "-A", "alert_json"]
    result = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=30)
    assert result.returncode == 0 and not result.stderr.strip(), result.stderr + result.stdout
    assert "dump:pcap DAQ configured to inline." in result.stdout
    section = re.search(r"(?m)^daq\n((?:[ \t].*\n)*)", result.stdout)
    assert section, "DAQ statistics missing"
    counters = {key: int(value) for key, value in re.findall(r"(?m)^\s+(\w+):\s+(\d+)\b", section[1])}
    assert counters.get("received") == len(case["frames"]) == counters.get("analyzed")
    verdicts = {key: counters[key] for key in sorted(VERDICTS) if counters.get(key)}
    assert sum(verdicts.values()) == len(case["frames"])
    assert not any(verdicts.get(key) for key in ("ignore", "retry", "replace", "whitelist", "blacklist")), verdicts
    forwarded = pcap_packets(output.read_bytes())
    assert len(forwarded) == verdicts.get("allow", 0)
    errors = module_count(result.stdout, *case["counter"])
    reassembled = module_count(result.stdout, "stream_ip", "reassembled")
    bypassed = module_count(result.stdout, case["counter"][0], "checksum_bypassed")
    completion = case.get("first_completion_index", len(case["frames"]) - 1)
    expected_output = case["frames"] if case["valid"] else case["frames"][:completion]
    expected_verdicts = {"allow": len(expected_output)}
    if not case["valid"]:
        expected_verdicts["block"] = len(case["frames"]) - len(expected_output)
    enforcement_passed = verdicts == expected_verdicts and forwarded == expected_output
    # A rejected datagram can be retained and rechecked on every retry, or
    # skipped by a sticky drop. Every performed reassembly must fail checksum.
    expected_errors = reassembled * case["expected_checksum_errors_per_reassembly"]
    counter_passed = errors == expected_errors
    reassembly_passed = case["expected_reassemblies_min"] <= reassembled <= case["expected_reassemblies_max"]
    passed = (enforcement_passed and counter_passed
              and reassembly_passed and bypassed == 0)
    events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    return {key: value for key, value in case.items() if key != "frames"} | {
        "passed": passed, "enforcement_passed": enforcement_passed,
        "checksum_counter_passed": counter_passed,
        "reassembly_count_passed": reassembly_passed,
        "expected_checksum_errors_for_observed_reassemblies": expected_errors,
        "invalid_datagram_fully_forwarded": not case["valid"] and all(
            frame in forwarded for frame in case["frames"][:completion + 1]),
        "daq_verdicts": verdicts, "daq_counters": counters,
        "checksum_errors": errors, "reassemblies": reassembled, "checksum_bypassed": bypassed,
        "input_pcap_sha256": digest(capture.read_bytes()), "output_pcap_sha256": digest(output.read_bytes()),
        "input_packet_sha256": [digest(frame) for frame in case["frames"]],
        "output_packet_sha256": [digest(frame) for frame in forwarded], "events": events}


def validate(snort, plugin):
    snort, plugin = snort.resolve(strict=True), plugin.resolve(strict=True)
    binary_hash = digest(snort.read_bytes())
    sources = [Path(__file__), HERE / "checksum_replay.py", HERE / "generate_pcaps.py",
               HERE / "next_header_policy.py", HERE / "replay.py"]
    hashes = {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in sources}
    profiles = load_validator().validate(snort, plugin)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("AX_")}
    with tempfile.TemporaryDirectory(prefix="ax-fragment-checksum-") as temporary:
        directory = Path(temporary)
        for name in CONFIG_FILES:
            (directory / name).write_bytes((HERE.parent / name).read_bytes())
        cases = list(fixtures())
        for case in cases:
            verify_wire_oracle(case)
        results = [run_case(snort, plugin, directory / "protocol-ips.lua", directory, case, environment)
                   for case in cases]
    assert binary_hash == digest(snort.read_bytes())
    for relative, expected in hashes.items() | profiles["sha256"].items():
        assert digest((ROOT / relative).read_bytes()) == expected, relative
    libraries = [plugin] if plugin.is_file() else sorted(set(plugin.rglob("*.so")) | set(plugin.rglob("*.dylib")))
    assert profiles["plugin_sha256"] == {path.name: digest(path.read_bytes()) for path in libraries}
    failures = [case["name"] for case in results if not case["passed"]]
    return {"status": "conformance_failure" if failures else "verified_expected_behavior",
            "scope": "Actual file-only inline DAQ verdicts and exact forwarded fragments; no live interface or endpoint.",
            "snort_binary_sha256": binary_hash, "configuration": profiles,
            "fixture_source_sha256": hashes,
            "summary": {"cases": len(results), "passed": len(results) - len(failures), "failures": failures,
                        "enforcement_passed": sum(case["enforcement_passed"] for case in results),
                        "invalid_datagrams_fully_forwarded": sum(case["invalid_datagram_fully_forwarded"] for case in results)},
            "limitations": ["Previously forwarded incomplete fragments cannot be recalled; rejection must block the fragment completing an invalid datagram.",
                            "Only these finite layouts and arrival orders are tested, not every overlap, timeout, offload or deployment scenario.",
                            "File DAQ provides no hardware checksum metadata; rejecting reuse of parent metadata needs separate source/API review."],
            "cases": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snort", type=Path, required=True)
    parser.add_argument("--plugin-path", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = validate(args.snort, args.plugin_path)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["summary"], indent=2))
    if report["summary"]["failures"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
