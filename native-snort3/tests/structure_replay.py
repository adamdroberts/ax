#!/usr/bin/env python3
"""Compare added IP structure guards with file-only inline packet verdicts."""
import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import struct
import tempfile

from generate_pcaps import checksum, ip6, packet, udp
from checksum_replay import write_pcap
from next_header_policy import CONFIG_FILES, rule_actions, run_capture
from replay import load_validator

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
NEW_RULES = {9201012, 9201013, 9201014, 9201015, 9201016}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def ipv4(body, protocol=17, options=b"", fragment=0):
    options += b"\0" * (-len(options) % 4)
    assert len(options) <= 40
    header = struct.pack("!BBHHHBBH4s4s", 0x45 + len(options) // 4, 0,
                         20 + len(options) + len(body), 1234, fragment, 64, protocol, 0,
                         ipaddress.ip_address("192.0.2.10").packed,
                         ipaddress.ip_address("198.51.100.20").packed) + options
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + body


def extension(options, next_header=17):
    padding = b"\0" * (-(len(options) + 2) % 8)
    return bytes([next_header, (len(options) + len(padding) + 2) // 8 - 1]) + options + padding


def fixture(name, frame, sid=None):
    return {"name": name, "frame": frame, "expected_rule": [1, sid] if sid else None}


def routing_cases():
    def header(length=2, segments=1, home="2001:db8::3", reserved=0,
               next_header=59, routing_type=2):
        result = bytes([next_header, length, routing_type, segments]) + struct.pack("!I", reserved)
        result += (ipaddress.IPv6Address(home).packed + b"\0" * 2048)[:length * 8]
        return result

    # Pure parser tests exhaust every byte value. These native cases verify
    # adapter selection, declared bounds and both ends of the wire fields.
    for length in (*range(9), 255):
        yield fixture(f"ipv6-type2-length-{length}", packet(ip6(header(length=length), 43), 6),
                      None if length == 2 else 9201016)
    for segments in (0, 1, 2, 3, 127, 128, 255):
        yield fixture(f"ipv6-type2-segments-{segments}", packet(ip6(header(segments=segments), 43), 6),
                      None if segments == 1 else 9201016)
    for home, label, invalid in (("::", "unspecified", True), ("::1", "loopback", True),
                                 ("ff02::1", "multicast", True), ("fe80::1", "link-local", True),
                                 ("febf::1", "link-local-upper", True), ("fc00::1", "ula", False),
                                 ("fdff::1", "ula-upper", False), ("2001:db8::3", "global-shape", False)):
        yield fixture("ipv6-type2-home-" + label, packet(ip6(header(home=home), 43), 6),
                      9201016 if invalid else None)
    for reserved in (1, 0x80000000, 0xffffffff):
        yield fixture(f"ipv6-type2-reserved-{reserved}", packet(ip6(header(reserved=reserved), 43), 6))
    for invalid in (False, True):
        route = header(segments=2 if invalid else 1)
        for location, first, prefix in (("after-destination", 60, extension(b"", 43)),
                                       ("after-ah", 51, bytes([43, 2]) + struct.pack("!HII", 0, 256, 1) + b"\0" * 4),
                                       ("first-fragment", 44, struct.pack("!BBHI", 43, 0, 1, 0x12345678))):
            yield fixture(f"ipv6-type2-{location}-" + ("bad" if invalid else "control"),
                          packet(ip6(prefix + route, first), 6), 9201016 if invalid else None)
    yield fixture("ipv6-type2-repeated-structural-control", packet(ip6(header(next_header=43) + header(), 43), 6))
    yield fixture("ipv6-type2-link-padding-is-not-header", packet(ip6(header(), 43), 6) + b"\xff" * 32)
    for segments in (0, 1):
        yield fixture(f"ipv6-unknown-routing-segments-{segments}",
                      packet(ip6(header(length=0, segments=segments, routing_type=253), 43), 6))
    # Continuation-fragment content and encrypted ESP data are not new headers.
    fake = header(length=0, segments=0)
    yield fixture("ipv6-type2-shaped-continuation-data", packet(ip6(
        struct.pack("!BBHI", 43, 0, 8, 0x12345678) + fake, 44), 6))
    yield fixture("ipv6-type2-shaped-opaque-esp", packet(ip6(fake + b"\0" * 16, 50), 6))


def cases():
    yield from routing_cases()
    for name, option_hex, invalid in (
            ("eol-zero", "00000000", False), ("eol-nonzero", "00000001", True),
            ("nop", "01010101", False), ("unknown", "1e020000", False),
            ("unknown-then-short-ra", "1e029402", True),
            ("rr-empty", "070304", False), ("rr-short", "0702", True),
            ("rr-pointer-zero", "070300", True), ("rr-pointer-three", "070303", True),
            ("rr-completed", "0703ff", False), ("rr-duplicate", "070304070304", True),
            ("lsrr-empty", "830304", False), ("lsrr-pointer-zero", "830300", True),
            ("ssrr-empty", "890304", False), ("ssrr-pointer-three", "890303", True),
            ("mixed-source-route", "830304890304", True),
            ("ts-empty", "44040500", False), ("ts-short", "440305", True),
            ("ts-pointer-four", "44040400", True), ("ts-completed", "4404ff00", False),
            ("ts-duplicate", "4404050044040500", True),
            ("ra-valid", "94040000", False), ("ra-unknown-value", "9404ffff", False),
            ("ra-two", "9402", True), ("ra-three", "940300", True),
            ("ra-five", "9405000000", True),
            ("obsolete-stream-id-opaque", "8802", False)):
        yield fixture("ipv4-options-" + name, packet(ipv4(udp(), options=bytes.fromhex(option_hex))),
                      9201012 if invalid else None)
    # The complete original option area must be checked, even after a legal
    # unknown option, at the maximum IHL, or when upper-layer bytes resemble options.
    yield fixture("ipv4-options-max-unknown", packet(ipv4(udp(), options=b"\x1e\x02" * 20)))
    yield fixture("ipv4-options-max-padding-hidden", packet(ipv4(udp(), options=b"\0" * 39 + b"\x01")), 9201012)
    yield fixture("ipv4-payload-is-not-options", packet(ipv4(udp(b"\0\0\0\x01\x94\x02"))))
    yield fixture("ipv4-link-padding-is-not-options", packet(ipv4(udp(), options=b"\0" * 4)) + b"\xff" * 32)
    for protocol, label in ((0, "hop"), (60, "destination")):
        for name, option_hex, invalid in (
                ("pad1", "00", False), ("padn", "010400000000", False),
                ("unknown", "1e00", False),
                ("ra-valid", "05020000", protocol != 0),
                ("ra-unknown-value", "0502ffff", protocol != 0),
                ("ra-zero", "0500", True), ("ra-one", "050100", True),
                ("ra-three", "0503000000", True), ("ra-misaligned", "0005020000", True),
                ("ra-duplicate", "0502000005020000", True),
                ("jumbo-zero", "c200", True), ("jumbo-short", "c203000001", True),
                ("jumbo-small", "c2040000ffff", True),
                ("jumbo-nonzero-base", "c20400010000", True)):
            body = extension(bytes.fromhex(option_hex)) + udp(ipv6=True)
            yield fixture(f"ipv6-{label}-{name}", packet(ip6(body, protocol), 6), 9201013 if invalid else None)
    # First fragments carry complete upper headers; malformed options must be
    # rejected before reassembly. No final fragment is required for this check.
    for invalid in (False, True):
        options = b"\x05\x00" if invalid else b"\x1e\x00"
        tail = extension(options) + udp(b"", ipv6=True)
        fragment = struct.pack("!BBHI", 60, 0, 1, 0x12345678)
        yield fixture("ipv6-first-fragment-options-" + ("bad" if invalid else "control"),
                      packet(ip6(fragment + tail, 44), 6), 9201013 if invalid else None)
    for version in (4, 6):
        for length in range(13):
            esp = (struct.pack("!II", 256, 1) + b"\0" * 16)[:length]
            network = ipv4(esp, 50) if version == 4 else ip6(esp, 50)
            yield fixture(f"ipv{version}-esp-size-{length}", packet(network, version), 9201014 if length < 10 else None)
        for spi in (0, 1, 0xffffffff):
            esp = struct.pack("!II", spi, 0) + b"\0" * 16
            network = ipv4(esp, 50) if version == 4 else ip6(esp, 50)
            yield fixture(f"ipv{version}-esp-spi-{spi}", packet(network, version), 9201014 if spi == 0 else None)
        for spi in (0, 256):
            esp = struct.pack("!II", spi, 1)
            network = (ipv4(esp, 50, fragment=0x2000) if version == 4 else
                       ip6(struct.pack("!BBHI", 50, 0, 1, 0x12345678) + esp, 44))
            yield fixture(f"ipv{version}-esp-first-fragment-spi-{spi}", packet(network, version),
                          9201014 if spi == 0 else None)
        # AH has no SA here; these are only visible framing controls.
        for spi in (0, 256):
            ah_size = 12 if version == 4 else 16
            ah = bytes([50, ah_size // 4 - 2]) + struct.pack("!HII", 0, 256, 1) + b"\0" * (ah_size - 12)
            esp = struct.pack("!II", spi, 1) + b"\0" * 16
            network = ipv4(ah + esp, 51) if version == 4 else ip6(ah + esp, 51)
            yield fixture(f"ipv{version}-ah-esp-spi-{spi}", packet(network, version), 9201014 if spi == 0 else None)
    for spi in (0, 256):
        esp = struct.pack("!II", spi, 1) + b"\0" * 16
        yield fixture(f"ipv6-destination-esp-spi-{spi}",
                      packet(ip6(extension(b"", 50) + esp, 60), 6), 9201014 if spi == 0 else None)
    # IPv4 can split AH/ESP across fragments. Do not impose RFC7112's IPv6
    # complete-first-header requirement on these original IPv4 fragments.
    yield fixture("ipv4-first-fragment-split-ah", packet(ipv4(
        bytes([50, 2]) + struct.pack("!HI", 0, 256), 51, fragment=0x2000)))
    yield fixture("ipv4-first-fragment-split-esp-after-ah", packet(ipv4(
        bytes([50, 1]) + struct.pack("!HII", 0, 256, 1) + struct.pack("!I", 256), 51, fragment=0x2000)))
    for kind in (128, 129):
        for code in (0, 1, 255):
            echo = struct.pack("!BBHHH", kind, code, 0, 1, 1)
            pseudo = (ipaddress.ip_address("2001:db8::1").packed
                      + ipaddress.ip_address("2001:db8::2").packed + struct.pack("!I3xB", len(echo), 58))
            echo = echo[:2] + struct.pack("!H", checksum(pseudo + echo)) + echo[4:]
            yield fixture(f"ipv6-echo-{kind}-code-{code}", packet(ip6(echo, 58), 6), 9201015 if code else None)


def validate(snort, plugin):
    source_files = (Path(__file__), HERE / "generate_pcaps.py", HERE / "checksum_replay.py",
                    HERE / "next_header_policy.py", HERE / "replay.py")
    source_hashes = {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in source_files}
    profiles = load_validator().validate(snort, plugin)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("AX_")}
    binary_hash = digest(snort.read_bytes())
    current = {name: (HERE.parent / name).read_text() for name in CONFIG_FILES}
    previous = dict(current)
    removed = set()
    lines = []
    for line in current["protocol-validation.rules"].splitlines(keepends=True):
        match = re.search(r"; sid:(\d+);", line)
        if match and int(match[1]) in NEW_RULES:
            assert line.startswith("drop ") and int(match[1]) not in removed
            removed.add(int(match[1]))
        else:
            lines.append(line)
    assert removed == NEW_RULES
    previous["protocol-validation.rules"] = "".join(lines)
    fixtures = list(cases())
    assert len({case["name"] for case in fixtures}) == len(fixtures)
    with tempfile.TemporaryDirectory(prefix="ax-ip-structure-") as temporary:
        directory = Path(temporary)
        for label, contents in (("current", current), ("without_added_guards", previous)):
            (directory / label).mkdir()
            for name, text in contents.items():
                (directory / label / name).write_text(text)
        actions = rule_actions(snort, plugin, directory / "current/protocol-ips.lua", environment)
        old_actions = rule_actions(snort, plugin, directory / "without_added_guards/protocol-ips.lua", environment)
        assert all(actions[(1, sid)] == "drop" for sid in NEW_RULES)
        assert old_actions == {key: value for key, value in actions.items() if key not in {(1, sid) for sid in NEW_RULES}}

        def check(case):
            source = directory / (case["name"] + ".pcap")
            write_pcap(source, [case["frame"]])
            results = {}
            for label in ("without_added_guards", "current"):
                results[label] = run_capture(snort, plugin, directory / label / "protocol-ips.lua",
                                            source, directory / label / (case["name"] + ".pcap"), environment)
            after, before = results["current"], results["without_added_guards"]
            expected = case["expected_rule"]
            if expected:
                matched = any([int(value) for value in event["rule"].split(":")[:2]] == expected
                              for event in after["events"])
                passed = after["blocked"] and matched
            else:
                expected_output = [digest(case["frame"])]
                passed = (not before["blocked"] and not after["blocked"]
                          and before["output_packet_sha256"] == after["output_packet_sha256"] == expected_output)
            return {key: value for key, value in case.items() if key != "frame"} | {
                "capture_sha256": digest(source.read_bytes()), "passed": passed, **results}

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(check, fixtures))
    for relative, expected in profiles["sha256"].items():
        assert digest((ROOT / relative).read_bytes()) == expected, "source changed: " + relative
    plugin_files = [plugin] if plugin.is_file() else sorted(set(plugin.rglob("*.so")) | set(plugin.rglob("*.dylib")))
    assert profiles["plugin_sha256"] == {path.name: digest(path.read_bytes()) for path in plugin_files}
    assert binary_hash == digest(snort.read_bytes())
    assert source_hashes == {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in source_files}, "fixture source changed during validation"
    failures = [case["name"] for case in results if not case["passed"]]
    return {
        "snort_version": profiles["snort_version"], "snort_binary_sha256": binary_hash,
        "scope": "File-only inline dump:pcap DAQ verdicts and forwarded packet bytes; no live interfaces or deployed route tested.",
        "configuration": profiles,
        "comparison": {"baseline": "Current binary/plugin/configuration with only SIDs9201012-9201016 omitted; not a historical runtime.",
                       "effective_rule_delta_verified": True,
                       "baseline_sha256": {name: digest(value.encode()) for name, value in previous.items()}},
        "fixture_source_sha256": source_hashes,
        "summary": {"cases": len(results), "native_runs": 2 * len(results),
                    "passed": len(results) - len(failures), "failures": failures,
                    "controls": sum(case["expected_rule"] is None for case in results),
                    "malformed": sum(case["expected_rule"] is not None for case in results),
                    "newly_blocked": sum(not case["without_added_guards"]["blocked"] and case["current"]["blocked"] for case in results)},
        "limitations": ["Selected synthetic shapes only; not exhaustive RFC compliance or an exploitability assessment.",
                        "ESP/AH controls validate visible structure only, without security associations, authentication or decryption.",
                        "Whole jumbograms and endpoint-specific option processing are outside the tested native profile.",
                        "Type2 routing controls end at No Next Header: they do not establish Mobile IPv6 transport-checksum correctness or home-address ownership.",
                        "Unknown routing types remain opaque. Nonzero Segments Left requires endpoint-specific recognition policy, which this sensor does not know.",
                        "Single first-fragment controls test original-header guards, not complete datagram reassembly."],
        "cases": results,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snort", type=Path, required=True)
    parser.add_argument("--plugin-path", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = validate(args.snort.resolve(strict=True), args.plugin_path.resolve(strict=True))
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["summary"], indent=2))
    if report["summary"]["failures"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
