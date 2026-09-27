#!/usr/bin/env python3
"""Audit IPv4 source-route checksums using actual file-only inline DAQ verdicts."""
import argparse
import concurrent.futures
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
from generate_pcaps import checksum, packet
from next_header_policy import CONFIG_FILES, VERDICTS, pcap_packets
from replay import load_validator

if not __debug__:
    raise RuntimeError("validation requires assertions")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SOURCE, BASE, FINAL = (ipaddress.IPv4Address(value).packed for value in
                       ("192.0.2.10", "198.51.100.20", "203.0.113.30"))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def route(kind, count=1, pointer=4):
    addresses = b"".join(bytes([203, 0, 113, index + 40]) for index in range(count - 1))
    return bytes([kind, 3 + 4 * count, pointer]) + addresses + (FINAL if count else b"")


def padded(options):
    assert len(options) <= 40
    return options + b"\0" * (-len(options) % 4)


def network(body, protocol, options=b"", offset=0, more=False):
    options = padded(options)
    length = 20 + len(options)
    header = struct.pack("!BBHHHBBH4s4s", 0x40 | length // 4, 0, length + len(body),
                         1234, offset // 8 | (0x2000 if more else 0), 64, protocol, 0, SOURCE, BASE) + options
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + body


def transport(protocol, destination, variant, reserved=False, rewritten=False):
    payload = (b"AFTER!" if rewritten else b"BEFORE") + b"x" * (47 if protocol == 6 else 59)
    if protocol == 6:
        body = struct.pack("!HHIIBBHHH", 50000, 80, 100, 0, 82 if reserved else 80, 2, 65535, 0, 0) + payload
        where = 16
    else:
        body = struct.pack("!HHHH", 50000, 9999, 8 + len(payload), 0) + payload
        where = 6
    if variant == "zero":
        assert protocol == 17
        return body
    value = checksum(SOURCE + destination + struct.pack("!BBH", 0, protocol, len(body)) + body)
    if protocol == 17:
        value = value or 0xffff
    if variant == "one-bit-error":
        value ^= 1
        assert protocol != 17 or value != 0
    return body[:where] + struct.pack("!H", value) + body[where + 2:]


def make_case(name, protocol, options, active, valid, *, cuts=(), order=None,
              normalization="", malformed=False, zero=False, ah=False):
    variant = "zero" if zero else "correct" if valid else "wrong-base" if active else "one-bit-error"
    destination = FINAL if active and valid else BASE
    body = transport(protocol, destination, variant, normalization == "tcp-reserved")
    expected_body = transport(protocol, FINAL if active else BASE, "zero" if zero else "correct",
                              rewritten=normalization == "rewrite")
    prefix = bytes([protocol, 1]) + struct.pack("!HII", 0, 256, 1) if ah else b""
    plain, expected_plain = prefix + body, prefix + expected_body
    offsets = [0, *cuts, len(plain)]
    assert sorted(set(offsets)) == offsets
    frames = [packet(network(plain[start:end], 51 if ah else protocol, options, start, end != len(plain)))
              for start, end in zip(offsets, offsets[1:])]
    if order is not None:
        frames = [frames[index] for index in order]
    expected = frames if not normalization else [packet(network(expected_plain, protocol, options))]
    return {"name": name, "protocol": protocol, "active_route": active,
            "valid": valid, "malformed_route": malformed, "variant": variant,
            "normalization": normalization, "fragmented": bool(cuts), "ah": ah,
            "frames": frames, "expected_frames": expected if valid else frames[:-1]}


def fixtures():
    layouts = [("direct", b"", False), ("nop-only", b"\x01" * 4, False),
               ("record-route", bytes([7, 7, 4]) + FINAL, False),
               ("opaque-route-bytes", bytes([158, 10]) + route(131) + b"\0", False)]
    for kind, label in ((131, "lsrr"), (137, "ssrr")):
        for name, options, active in (
                ("one", route(kind), True), ("three-first", route(kind, 3), True),
                ("three-middle", route(kind, 3, 8), True), ("three-last", route(kind, 3, 12), True),
                ("completed", route(kind, 3, 16), False), ("completed-255", route(kind, 3, 255), False),
                ("empty", route(kind, 0), False), ("empty-255", route(kind, 0, 255), False),
                ("unaligned-option", b"\x01" + route(kind), True),
                ("after-opaque", bytes([158, 4, 131, 137]) + route(kind), True),
                ("before-opaque", route(kind) + bytes([158, 10]) + route(131) + b"\0", True),
                ("maximum-ihl", b"\x01" + route(kind, 9, 20), True)):
            layouts.append((label + "-" + name, options, active))
    for name, options, active in layouts:
        for protocol in (6, 17):
            for valid in (True, False):
                yield make_case(name + f"-p{protocol}-" + ("correct" if valid else "incorrect"),
                                protocol, options, active, valid)
            if protocol == 17:
                yield make_case(name + "-udp-zero", protocol, options, active, True, zero=True)

    for kind, label in ((131, "lsrr"), (137, "ssrr")):
        for protocol in (6, 17):
            for valid in (True, False):
                suffix = f"-p{protocol}-" + ("correct" if valid else "incorrect")
                for cuts in ((8,), (8, 24)):
                    for order in itertools.permutations(range(len(cuts) + 1)):
                        yield make_case(label + "-fragments-" + "".join(map(str, order)) + suffix,
                                        protocol, route(kind), True, valid, cuts=cuts, order=order)
                yield make_case(label + "-ah" + suffix, protocol, route(kind), True, valid, ah=True)
                yield make_case(label + "-rewrite" + suffix, protocol, route(kind), True, valid,
                                normalization="rewrite")
                if protocol == 6:
                    yield make_case(label + "-reserved" + suffix, protocol, route(kind), True, valid,
                                    normalization="tcp-reserved")
        for bad_name, options in (
                ("partial-address", bytes([kind, 6, 4, 203, 0, 113])),
                ("unaligned-active-pointer", route(kind, 2, 5)),
                ("incomplete-active-slot", route(kind, 1, 7))):
            for protocol in (6, 17):
                # A correct base-address checksum or omitted UDP checksum
                # must not rescue an invalid route whose destination is undefined.
                case = make_case(label + "-" + bad_name + f"-p{protocol}", protocol,
                                 options, False, True, zero=protocol == 17)
                yield case | {"valid": False, "malformed_route": True, "expected_frames": []}


def wire_oracle(case):
    """Reassemble serialized bytes and simulate routing pointer progression.

    This does not use the source helper or the generator's checksum routine.
    Malformed route cases have no well-defined checksum destination.
    """
    def valid_sum(data):
        return sum(int.from_bytes(data[i:i + 2].ljust(2, b"\0"), "big")
                   for i in range(0, len(data), 2)) % 65535 == 0

    parts, destination, source, protocol = {}, None, None, None
    for frame in case["frames"]:
        ip = frame[14:]
        length = (ip[0] & 15) * 4
        assert frame[12:14] == b"\x08\0" and ip[0] >> 4 == 4
        assert len(ip) == int.from_bytes(ip[2:4], "big") and valid_sum(ip[:length])
        source, final, protocol = ip[12:16], ip[16:20], ip[9]
        cursor, malformed = 20, False
        while cursor < length and ip[cursor] != 0:
            kind = ip[cursor]
            if kind == 1:
                cursor += 1
                continue
            size = ip[cursor + 1]
            assert size >= 2 and cursor + size <= length
            if kind in (131, 137):
                position = ip[cursor + 2]
                malformed = size < 3 or (size - 3) % 4 != 0 or position < 4
                if position <= size:
                    malformed = malformed or position % 4 != 0
                while not malformed and position <= size:
                    assert position + 3 <= size
                    final = ip[cursor + position - 1:cursor + position + 3]
                    position += 4
            cursor += size
        assert malformed == case["malformed_route"], case["name"]
        if destination is not None:
            assert destination == final
        destination = final
        field = int.from_bytes(ip[6:8], "big")
        offset = (field & 0x1fff) * 8
        assert offset not in parts
        parts[offset] = ip[length:]
    payload = b""
    for offset, part in sorted(parts.items()):
        assert offset == len(payload)
        payload += part
    if case["malformed_route"]:
        return
    if protocol == 51:
        size = (payload[1] + 2) * 4
        protocol, payload = payload[0], payload[size:]
    assert protocol == case["protocol"]
    if protocol == 17 and payload[6:8] == b"\0\0":
        assert case["valid"]
        return
    covered = source + destination + struct.pack("!BBH", 0, protocol, len(payload)) + payload
    assert valid_sum(covered) == case["valid"], case["name"]


def configurations(directory):
    for name in CONFIG_FILES:
        (directory / name).write_bytes((HERE.parent / name).read_bytes())
    text = (directory / "protocol-ips.lua").read_text()
    normal = "normalizer = { tcp = { ips = true, block = true, trim_win = true } }"
    assert text.count(normal) == 1
    special = {"tcp-reserved": text.replace(normal, normal.replace("ips = true", "rsv = true, ips = true")),
               "rewrite": text + '\nips.rules = ips.rules .. [[\nrewrite ip any any -> any any (msg:"AX fixture payload rewrite"; pkt_data; content:"BEFORE"; replace:"AFTER!"; sid:9299999; rev:1;)\n]]\nips.states = ips.states .. [[\nrewrite (gid:1; sid:9299999; enable:yes;)\n]]\n'}
    for name, content in special.items():
        (directory / (name + ".lua")).write_text(content)
    return {name: digest(content.encode()) for name, content in special.items()}


def run_case(snort, plugin, directory, case, environment):
    capture, output = directory / (case["name"] + ".pcap"), directory / (case["name"] + "-out.pcap")
    write_pcap(capture, case["frames"])
    config = directory / ((case["normalization"] + ".lua") if case["normalization"] else "protocol-ips.lua")
    command = [str(snort), "--plugin-path", str(plugin), "-c", str(config),
               "--daq", "pcap", "--daq-mode", "read-file", "--daq", "dump", "--daq-mode", "inline",
               "--daq-var", "file=" + str(output), "-Q", "-r", str(capture), "-s", "65535", "-A", "alert_json"]
    result = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=30)
    assert result.returncode == 0 and not result.stderr.strip(), result.stderr + result.stdout
    assert "dump:pcap DAQ configured to inline." in result.stdout
    section = re.search(r"(?m)^daq\n((?:[ \t].*\n)*)", result.stdout)
    assert section
    counters = {key: int(value) for key, value in re.findall(r"(?m)^\s+(\w+):\s+(\d+)\b", section[1])}
    assert counters.get("received") == len(case["frames"]) == counters.get("analyzed")
    verdicts = {key: counters[key] for key in sorted(VERDICTS) if counters.get(key)}
    assert sum(verdicts.values()) == len(case["frames"])
    forwarded = pcap_packets(output.read_bytes())
    assert len(forwarded) == verdicts.get("allow", 0) + verdicts.get("replace", 0)
    expected = {"replace" if case["normalization"] and case["valid"] else "allow": len(case["expected_frames"])}
    if not case["valid"]:
        expected["block"] = len(case["frames"]) - len(case["expected_frames"])
    expected = {key: value for key, value in expected.items() if value}
    module = "tcp" if case["protocol"] == 6 else "udp"
    errors = module_count(result.stdout, module, f"bad_{module}4_checksum")
    bypassed = module_count(result.stdout, module, "checksum_bypassed")
    events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    option_error = any(event["rule"].split(":")[:2] == ["116", "4"] for event in events)
    counter_ok = (errors == 0 and option_error) if case["malformed_route"] else errors == int(not case["valid"])
    enforced = verdicts == expected and forwarded == case["expected_frames"]
    return {key: value for key, value in case.items() if key not in ("frames", "expected_frames")} | {
        "passed": enforced and counter_ok and bypassed == 0, "enforcement_passed": enforced,
        "checksum_counter_passed": counter_ok, "checksum_errors": errors, "checksum_bypassed": bypassed,
        "ipv4_option_error": option_error,
        "reassemblies": module_count(result.stdout, "stream_ip", "reassembled"),
        "daq_verdicts": verdicts, "expected_daq_verdicts": expected,
        "input_packet_sha256": [digest(frame) for frame in case["frames"]],
        "expected_packet_sha256": [digest(frame) for frame in case["expected_frames"]],
        "output_packet_sha256": [digest(frame) for frame in forwarded],
        "input_pcap_sha256": digest(capture.read_bytes()), "output_pcap_sha256": digest(output.read_bytes()),
        "events": events}


def validate(snort, plugin):
    snort, plugin = snort.resolve(strict=True), plugin.resolve(strict=True)
    binary_hash = digest(snort.read_bytes())
    sources = [Path(__file__), HERE / "checksum_replay.py", HERE / "generate_pcaps.py",
               HERE / "next_header_policy.py", HERE / "replay.py"]
    hashes = {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in sources}
    profiles = load_validator().validate(snort, plugin)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("AX_")}
    cases = list(fixtures())
    assert len({case["name"] for case in cases}) == len(cases)
    for case in cases:
        wire_oracle(case)
        if case["valid"]:
            wire_oracle(case | {"frames": case["expected_frames"]})
    with tempfile.TemporaryDirectory(prefix="ax-ipv4-route-replay-") as temporary:
        directory = Path(temporary)
        special_hashes = configurations(directory)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(lambda case: run_case(snort, plugin, directory, case, environment), cases))
    assert binary_hash == digest(snort.read_bytes())
    for relative, expected in hashes.items() | profiles["sha256"].items():
        assert digest((ROOT / relative).read_bytes()) == expected
    libraries = [plugin] if plugin.is_file() else sorted(set(plugin.rglob("*.so")) | set(plugin.rglob("*.dylib")))
    assert profiles["plugin_sha256"] == {path.name: digest(path.read_bytes()) for path in libraries}
    failures = [case["name"] for case in results if not case["passed"]]
    return {"status": "conformance_failure" if failures else "verified_expected_behavior",
            "scope": "Actual file-only inline DAQ and exact forwarded bytes; no live routing, interface or deployment.",
            "snort_binary_sha256": binary_hash, "configuration": profiles,
            "fixture_source_sha256": hashes, "special_configuration_sha256": special_hashes,
            "summary": {"cases": len(results), "passed": len(results) - len(failures), "failures": failures,
                        "valid_controls": sum(case["valid"] for case in results),
                        "fragment_cases": sum(case["fragmented"] for case in results),
                        "normalization_cases": sum(bool(case["normalization"]) for case in results),
                        "malformed_route_cases": sum(case["malformed_route"] for case in results)},
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
