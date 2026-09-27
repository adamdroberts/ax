#!/usr/bin/env python3
"""Audit copied IPv4 fragment options using actual file-only inline DAQ output."""
import argparse
import concurrent.futures
import hashlib
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
from ipv4_route_replay import BASE, FINAL, SOURCE, network, padded, route, transport
from next_header_policy import CONFIG_FILES, VERDICTS, pcap_packets
from replay import load_validator

if not __debug__:
    raise RuntimeError("validation requires assertions")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


def option_cases():
    ra = bytes([148, 4, 0, 0])
    opaque = bytes([158, 4, 0x12, 0x34])
    rr = bytes([7, 7, 4]) + FINAL
    completed = route(131, pointer=8)
    changed_record = completed[:-1] + bytes([completed[-1] ^ 1])
    long_route = route(131, count=3, pointer=8)
    changed_long_record = long_route[:3] + b"\xc0\x00\x02\x10" + long_route[7:]
    examples = [
        ("plain", [b"", b""], True),
        ("router-alert", [ra, ra], True),
        ("nop-added", [ra, b"\x01" + ra], True),
        ("nop-only", [b"", b"\x01" * 4], True),
        ("nop-removed", [b"\x01" * 4, b""], True),
        ("eol-padding-added", [ra, ra + b"\0" * 4], True),
        ("eol-padding-removed", [ra + b"\0" * 4, ra], True),
        ("max-padding", [ra, b"\x01" * 36 + ra], True),
        ("record-route-first", [rr, b""], True),
        ("mixed-copy-flags", [ra + rr, b"\x01" + ra], True),
        ("opaque-mutable", [opaque, opaque[:2] + b"\x56\x78"], True),
        ("max-opaque", [bytes([158, 40]) + b"a" * 38, bytes([158, 40]) + b"b" * 38], True),
        ("max-option-count", [bytes([158, 2]) * 20] * 2, True),
        ("lsrr", [route(131)] * 2, True),
        ("ssrr", [route(137)] * 2, True),
        ("completed-route-record", [completed, changed_record], True),
        ("active-route-record", [long_route, changed_long_record], True),
        ("completed-route-pointer", [completed, completed[:2] + b"\xff" + completed[3:]], True),
        ("missing-copy", [ra, b""], False),
        ("added-copy", [b"", ra], False),
        ("different-kind", [ra, opaque], False),
        ("different-value", [ra, bytes([148, 4, 0, 1])], False),
        ("different-length", [opaque, bytes([158, 5, 0x12, 0x34, 0x56])], False),
        ("different-order", [ra + opaque, opaque + ra], False),
        ("duplicate-copy", [opaque, opaque * 2], False),
        ("noncopied-later", [b"", rr], False),
        ("mixed-noncopied-later", [ra, ra + rr], False),
        ("route-kind", [route(131), route(137)], False),
        ("route-final", [route(131), route(131)[:-1] + b"\x31"], False),
        ("route-missing", [route(131), b""], False),
    ]
    yield from examples


def wire_options(options, base=BASE):
    """Independent fixture oracle: parse literal type/length/data tuples.

    Returns stable copied attributes, non-copied attributes and final address.
    Does not import either C++ helper or its canonical byte representation.
    """
    result, noncopied, destination = [], [], base
    pos = 0
    while pos < len(options) and options[pos]:
        kind = options[pos]
        if kind == 1:
            pos += 1
            continue
        size = options[pos + 1]
        assert 2 <= size <= len(options) - pos
        data = options[pos + 2:pos + size]
        if kind & 128:
            result.append((kind, size, data if kind == 148 else None))
        else:
            noncopied.append(kind)
        if kind in (131, 137):
            assert size >= 3 and (size - 3) % 4 == 0
            pointer = data[0]
            assert pointer >= 4
            if pointer <= size:
                assert (pointer - 4) % 4 == 0
                # Independently advance through unprocessed source-route slots.
                for slot in range(pointer - 1, size, 4):
                    destination = options[pos + slot:pos + slot + 4]
        pos += size
    assert not any(options[pos:]), "nonzero header padding"
    return (tuple(result), destination), noncopied


def make_case(name, option_spans, valid, protocol, zero, order, retries=False):
    first_key, _ = wire_options(padded(option_spans[0]))
    body = transport(protocol, first_key[1], "zero" if zero else "correct")
    cuts = [0, 24, len(body)] if len(option_spans) == 2 else [0, 24, 48, len(body)]
    original = [packet(network(body[start:end], protocol, options, start, end != len(body)))
                for options, start, end in zip(option_spans, cuts, cuts[1:])]
    frames = [original[index] for index in order]
    expected_stop = len(frames)
    seen = None
    for index, which in enumerate(order):
        key, noncopied = wire_options(padded(option_spans[which]))
        if (which != 0 and noncopied) or (seen is not None and key != seen):
            expected_stop = index
            break
        seen = key
    assert valid == (expected_stop == len(frames))
    if retries:
        assert not valid
        # Retry both conflicting and original bytes, then the entire datagram.
        frames += [frames[expected_stop], frames[0], *frames]
    label = f"{name}-{'tcp' if protocol == 6 else 'udp-zero' if zero else 'udp'}-" + "".join(map(str, order))
    if retries:
        label += "-retries"
    return {"name": label, "category": name, "protocol": protocol, "zero_checksum": zero,
            "valid_control": valid, "retries": retries, "arrival_order": list(order),
            "fragment_count": len(original), "first_rejection": None if valid else expected_stop,
            "frames": frames, "expected_frames": frames if valid else frames[:expected_stop],
            "expected_reassemblies": 1 if valid else 0}


def fixtures():
    examples = list(option_cases())
    for name, options, valid in examples:
        for protocol, zero in ((6, False), (17, False), (17, True)):
            for order in ((0, 1), (1, 0)):
                yield make_case(name, options, valid, protocol, zero, order)
                if not valid and protocol == 17 and zero:
                    yield make_case(name, options, valid, protocol, zero, order, True)
    selected = {"plain", "nop-added", "eol-padding-added", "mixed-copy-flags",
                "missing-copy", "added-copy", "different-kind", "noncopied-later", "route-final"}
    for name, options, valid in examples:
        if name not in selected:
            continue
        # The third fragment can reveal a conflict after two consistent ones.
        for last_changed in (False, True):
            spans = [options[0], options[0], options[1]] if last_changed else [*options, options[1]]
            # Non-copied offset-zero data cannot be copied to the middle one.
            if name == "mixed-copy-flags" and last_changed:
                spans[1] = options[1]
            for order in itertools.permutations(range(3)):
                yield make_case(name + ("-late" if last_changed else "-early"), spans, valid,
                                17, True, order, not valid)
    # A conflict must not poison another IPv4 ID with the same endpoints.
    isolated = {"missing-copy", "different-kind", "noncopied-later", "route-final"}
    for name, options, valid in examples:
        if name not in isolated:
            continue
        for order in ((0, 1), (1, 0)):
            case = make_case(name, options, valid, 17, True, order, True)
            control = make_case("fresh", [b"", b""], True, 17, False, order)
            fresh = []
            for frame in control["frames"]:
                ip = bytearray(frame[14:])
                ip[4:6], ip[10:12] = b"\x43\x21", b"\0\0"
                ip[10:12] = struct.pack("!H", checksum(ip[:20]))
                fresh.append(frame[:14] + bytes(ip))
            yield case | {"name": case["name"] + "-fresh-id", "isolation_control": True,
                          "frames": case["frames"] + fresh,
                          "expected_frames": case["expected_frames"] + fresh,
                          "expected_reassemblies": 1}


def verify_wire_oracle(case):
    """Check serialized boundaries/checksums, payload and declared first conflict."""
    def sum_valid(data):
        return sum(int.from_bytes(data[i:i + 2].ljust(2, b"\0"), "big")
                   for i in range(0, len(data), 2)) % 65535 == 0
    pieces, seen, first_rejection, source, upper, end = {}, None, None, None, None, None
    zero_destination = None
    for index, frame in enumerate(case["frames"][:case["fragment_count"]]):
        assert frame[12:14] == b"\x08\0"
        ip = frame[14:]
        hlen = (ip[0] & 15) * 4
        assert ip[0] >> 4 == 4 and 20 <= hlen <= 60
        assert len(ip) == int.from_bytes(ip[2:4], "big") and sum_valid(ip[:hlen])
        field = int.from_bytes(ip[6:8], "big")
        offset, more = (field & 8191) * 8, bool(field & 8192)
        payload = ip[hlen:]
        assert offset not in pieces and (not more or len(payload) % 8 == 0)
        pieces[offset] = payload
        key, noncopied = wire_options(ip[20:hlen], ip[16:20])
        if first_rejection is None and ((offset and noncopied) or (seen is not None and seen != key)):
            first_rejection = index
        if seen is None:
            seen = key
        if offset == 0:
            source, upper, zero_destination = ip[12:16], ip[9], key[1]
        if not more:
            assert end is None
            end = offset + len(payload)
    body = b""
    for offset, data in sorted(pieces.items()):
        assert offset == len(body)
        body += data
    assert len(body) == end and upper == case["protocol"]
    if case["zero_checksum"]:
        assert upper == 17 and body[6:8] == b"\0\0"
    else:
        assert sum_valid(source + zero_destination + struct.pack("!BBH", 0, upper, len(body)) + body)
    assert first_rejection == case["first_rejection"]
    if case.get("isolation_control"):
        control = make_case("fresh", [b"", b""], True, 17, False, case["arrival_order"])
        restored = []
        for frame in case["frames"][-2:]:
            ip = bytearray(frame[14:])
            assert ip[4:6] == b"\x43\x21" and sum_valid(ip[:20])
            ip[4:6], ip[10:12] = b"\x04\xd2", b"\0\0"
            ip[10:12] = struct.pack("!H", checksum(ip[:20]))
            restored.append(frame[:14] + bytes(ip))
        assert restored == control["frames"]
        verify_wire_oracle(control)


def run_case(snort, plugin, config, directory, case, environment):
    capture, output = (directory / (case["name"] + suffix) for suffix in (".pcap", "-forwarded.pcap"))
    write_pcap(capture, case["frames"])
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
    assert not any(verdicts.get(key) for key in ("ignore", "retry", "replace", "whitelist", "blacklist"))
    forwarded = pcap_packets(output.read_bytes())
    assert len(forwarded) == verdicts.get("allow", 0)
    expected = case["expected_frames"]
    expected_verdicts = {"allow": len(expected)} if expected else {}
    if len(expected) < len(case["frames"]):
        expected_verdicts["block"] = len(case["frames"]) - len(expected)
    events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    option_events = [event for event in events if event.get("rule") == "123:1:1"]
    reassembled = module_count(result.stdout, "stream_ip", "reassembled")
    errors = module_count(result.stdout, "tcp" if case["protocol"] == 6 else "udp",
                          "bad_tcp4_checksum" if case["protocol"] == 6 else "bad_udp4_checksum")
    enforcement = forwarded == expected and verdicts == expected_verdicts
    events_pass = (not option_events if case["valid_control"] else len(option_events) == expected_verdicts["block"])
    reassembly_pass = reassembled == case["expected_reassemblies"]
    return {key: value for key, value in case.items() if key not in ("frames", "expected_frames")} | {
        "passed": enforcement and events_pass and reassembly_pass and errors == 0,
        "enforcement_passed": enforcement, "option_events_passed": events_pass,
        "reassembly_passed": reassembly_pass, "reassemblies": reassembled, "checksum_errors": errors,
        "daq_verdicts": verdicts, "daq_counters": counters, "events": events,
        "input_pcap_sha256": digest(capture.read_bytes()), "output_pcap_sha256": digest(output.read_bytes()),
        "input_packet_sha256": [digest(frame) for frame in case["frames"]],
        "output_packet_sha256": [digest(frame) for frame in forwarded],
        "expected_output_packet_sha256": [digest(frame) for frame in expected]}


def validate(snort, plugin):
    snort, plugin = snort.resolve(strict=True), plugin.resolve(strict=True)
    binary_hash = digest(snort.read_bytes())
    sources = [Path(__file__), HERE / "ipv4_route_replay.py", HERE / "checksum_replay.py",
               HERE / "generate_pcaps.py", HERE / "next_header_policy.py", HERE / "replay.py"]
    hashes = {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in sources}
    profiles = load_validator().validate(snort, plugin)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("AX_")}
    with tempfile.TemporaryDirectory(prefix="ax-fragment-options-") as temporary:
        directory = Path(temporary)
        for name in CONFIG_FILES:
            (directory / name).write_bytes((HERE.parent / name).read_bytes())
        cases = list(fixtures())
        assert len({case["name"] for case in cases}) == len(cases)
        for case in cases:
            verify_wire_oracle(case)
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda case: run_case(snort, plugin, directory / "protocol-ips.lua",
                                                        directory, case, environment), cases))
    assert binary_hash == digest(snort.read_bytes())
    for relative, expected in hashes.items() | profiles["sha256"].items():
        assert digest((ROOT / relative).read_bytes()) == expected, relative
    libraries = [plugin] if plugin.is_file() else sorted(set(plugin.rglob("*.so")) | set(plugin.rglob("*.dylib")))
    assert profiles["plugin_sha256"] == {path.name: digest(path.read_bytes()) for path in libraries}
    failures = [case["name"] for case in results if not case["passed"]]
    return {"status": "conformance_failure" if failures else "verified_expected_behavior",
            "scope": "Actual file-only inline verdicts and bytes; local strict reassembly policy, no endpoint or live interface.",
            "snort_binary_sha256": binary_hash, "configuration": profiles, "fixture_source_sha256": hashes,
            "summary": {"cases": len(results), "passed": len(results) - len(failures), "failures": failures,
                        "valid_controls": sum(case["valid_control"] for case in results),
                        "retry_cases": sum(case["retries"] for case in results),
                        "isolation_cases": sum(case.get("isolation_control", False) for case in results)},
            "limitations": ["Earlier forwarded fragments cannot be recalled.",
                            "Rejection lasts for the current tracker; timeout, eviction and identifier reuse are separate lifecycle limits.",
                            "Unknown option data and mutable route records are deliberately not compared or authenticated.",
                            "Bounded nonoverlapping captures do not prove endpoint equivalence, queue exhaustion or all RFC compliance."],
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
