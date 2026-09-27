#!/usr/bin/env python3
"""Audit reconstructed IPv6 bytes, ECN aggregation and final length bounds."""
import argparse
import concurrent.futures
import ipaddress
import itertools
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from checksum_replay import module_count
from fragment_lifetime_replay import write_capture
from generate_pcaps import checksum
from home_address_replay import CARE, DEST, HERE, ROOT, digest, frame
from next_header_policy import CONFIG_FILES, VERDICTS, pcap_packets
from replay import load_validator

if not __debug__:
    raise RuntimeError("validation requires assertions")

OBSERVER = '''
log_pcap = {}
ips.rules = ips.rules .. [[
log ip any any -> any any (msg:"AX reconstructed IPv6 bytes"; flow:only_frag; sid:2999110; rev:1;)
]]
ips.states = ips.states .. [[
log ( gid:1; sid:2999110; enable:yes; )
]]
'''


def transport(protocol, size):
    if protocol == 6:
        data = struct.pack("!HHIIBBHHH", 50000, 80, 100, 0, 80, 2, 65535, 0, 0)
        offset = 16
    elif protocol == 17:
        data = struct.pack("!HHHH", 50000, 9999, size, 0)
        offset = 6
    else:
        data = struct.pack("!BBHHH", 128, 0, 0, 1, 1)
        offset = 2
    data += bytes((index * 29 + 7) % 256 for index in range(size - len(data)))
    pseudo = ipaddress.IPv6Address(CARE).packed + ipaddress.IPv6Address(DEST).packed + struct.pack("!I3xB", size, protocol)
    value = checksum(pseudo + data)
    if protocol == 17:
        value = value or 65535
    data = data[:offset] + struct.pack("!H", value) + data[offset + 2:]
    assert sum(int.from_bytes((pseudo + data)[index:index + 2].ljust(2, b"\0"), "big")
               for index in range(0, len(pseudo + data), 2)) % 65535 == 0
    return data


def fields(wire, index, ecn):
    result = bytearray(wire)
    tc = ((0x28 if not index else 0x4c + 4 * index) & 0xfc) | ecn
    result[14:18] = struct.pack("!I", (6 << 28) | (tc << 20) | (0xabc01 + index))
    result[21] = 41 + index
    return bytes(result)


def make_case(name, protocol, headers, codes, order, size=72, retry=False, nexts=None, splits=None):
    data = transport(protocol, size)
    count = len(codes)
    offsets = splits or (list(range(0, size, 16000)) if size > 72 else [0, 24] if count == 2 else [0, 24, 48])
    assert len(offsets) == count and sorted(order) == list(range(count))
    wires = []
    for i, (start, end) in enumerate(zip(offsets, offsets[1:] + [size])):
        frag = (44, bytes(2) + struct.pack("!HI", start | int(end < size), 2468))
        wire = bytearray(frame(headers[i] + [frag], protocol, data[start:end]))
        if nexts and i:
            wire[54 + sum(len(raw) for _, raw in headers[i])] = nexts[i - 1]
        wires.append(fields(wire, i, codes[i]))
    ordered = [wires[index] for index in order]
    seen, rejected, reason, zero_seen, largest_end = set(), None, "", False, 0
    prefix_bytes = sum(len(raw) for _, raw in headers[0])
    ends = offsets[1:] + [size]
    for i, index in enumerate(order):
        zero_seen = zero_seen or index == 0
        largest_end = max(largest_end, ends[index])
        if largest_end + (prefix_bytes if zero_seen else 0) > 65535:
            rejected, reason = i, "prefix"
            break
        seen.add(codes[index])
        if 0 in seen and 3 in seen:
            rejected, reason = i, "ecn"
            break
    expected = []
    if rejected is None:
        ecn = 3 if 3 in codes else codes[0]
        expected = [fields(frame(headers[0], protocol, data), 0, ecn)]
    original_count = len(ordered)
    forwarded = ordered if rejected is None else ordered[:rejected]
    if retry:
        assert rejected is not None
        ordered = ordered + [ordered[-1], *ordered]
    return {"name": name, "protocol": protocol, "frames": ordered,
            "expected_frames": forwarded, "expected_rebuilt": expected,
            "arrival_order": list(order), "ecn": list(codes), "payload_bytes": size,
            "first_prefix_extension_bytes": prefix_bytes, "original_fragment_count": original_count,
            "expected_reassemblies": int(rejected is None), "reason": reason, "retry": retry,
            "expected_reason_drops": len(ordered) - rejected if rejected is not None else 0}


def fixtures():
    pad, long_pad = (60, bytes(8)), (60, bytes([0, 255]) + bytes(2046))
    for protocol in (6, 17, 58):
        for padded in (False, True):
            headers = [[pad] if padded else [], [long_pad] if padded else []]
            for codes in itertools.product(range(4), repeat=2):
                for order in ((0, 1), (1, 0)):
                    stem = f"ecn-p{protocol}-pad{int(padded)}-" + "".join(map(str, codes)) + "-" + "".join(map(str, order))
                    item = make_case(stem, protocol, headers, codes, order)
                    yield item
                    if item["reason"]:
                        yield make_case(stem + "-retry", protocol, headers, codes, order, retry=True)
    for codes in itertools.product(range(4), repeat=3):
        for order in itertools.permutations(range(3)):
            yield make_case("ecn-three-" + "".join(map(str, codes)) + "-" + "".join(map(str, order)),
                            17, [[pad], [], [long_pad]], codes, order)
    for protocol in (6, 17, 58):
        for size, split in ((65527, 32768), (65527, 50000), (65527, 65464), (65000, 24)):
            for order in ((0, 1), (1, 0)):
                yield make_case(f"wide-fragment-p{protocol}-size{size}-split{split}-" + "".join(map(str, order)),
                                protocol, [[pad], []], [2, 2], order, size, splits=[0, split])
        for first in ([], [pad], [long_pad], [long_pad] * 7):
            prefix_bytes = sum(len(raw) for _, raw in first)
            for adjustment in (-1, 0, 1):
                size = 65535 - prefix_bytes + adjustment
                if protocol == 17 and size > 65535:
                    continue
                count = (size + 15999) // 16000
                headers = [first] + [[], [pad], [long_pad], []][:count - 1]
                for order in (tuple(range(count)), tuple(reversed(range(count))), tuple(range(1, count)) + (0,)):
                    stem = f"length-p{protocol}-prefix{prefix_bytes}-delta{adjustment}-" + "".join(map(str, order))
                    yield make_case(stem, protocol, headers, [2] * count, order, size)
                    if adjustment == 1:
                        yield make_case(stem + "-retry", protocol, headers, [2] * count, order, size, retry=True)
        for order in itertools.permutations(range(3)):
            for nexts in ((59, 0), (253, 254), (6, 58)):
                yield make_case(f"next-header-p{protocol}-" + "".join(map(str, order)) + "-" + "-".join(map(str, nexts)),
                                protocol, [[long_pad], [], [pad]], [1] * 3, order, nexts=nexts)


def logged_packets(path):
    # The pinned logger's global snaplen is limited to 65535, even for complete
    # manufactured IPv6 frames that include 40 IP and 14 Ethernet bytes beyond
    # the 65535-byte IPv6 payload. Check complete record lengths explicitly.
    data = path.read_bytes()
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(data[:4])
    assert endian and len(data) >= 24
    _, major, minor, _, _, snaplen, linktype = struct.unpack(endian + "IHHIIII", data[:24])
    assert (major, minor, linktype, snaplen) == (2, 4, 1, 65535)
    result, above_snaplen, offset, errors = [], 0, 24, []
    while offset < len(data):
        assert len(data) - offset >= 16
        _, _, captured, original = struct.unpack(endian + "IIII", data[offset:offset + 16])
        offset += 16
        if captured != original or captured > 67053 or captured > len(data) - offset:
            errors.append({"captured": captured, "original": original, "available": len(data) - offset})
        if captured > len(data) - offset:
            break
        result.append(data[offset:offset + captured])
        above_snaplen += captured > snaplen
        offset += captured
    return result, above_snaplen, errors


def run_case(snort, plugin, config, directory, item, environment):
    directory = directory / item["name"]
    directory.mkdir()
    capture, output = directory / "input.pcap", directory / "output.pcap"
    write_capture(capture, item["frames"], [i * 100 for i in range(len(item["frames"]))])
    command = [str(snort), "--plugin-path", str(plugin), "-c", str(config), "--daq", "pcap", "--daq-mode", "read-file",
               "--daq", "dump", "--daq-mode", "inline", "--daq-var", "file=" + str(output), "-Q", "-r", str(capture),
               "-s", "65535", "-l", str(directory)]
    # CLI -A/-L overrides the Lua output list (and -L can disable inspection).
    run = subprocess.run(command, cwd=directory, env=environment, text=True, capture_output=True, timeout=30)
    if run.returncode or run.stderr.strip():
        return {key: value for key, value in item.items() if key not in ("frames", "expected_frames", "expected_rebuilt")} | {
            "passed": False, "enforcement_passed": False, "rebuilt_bytes_passed": False, "counter_passed": False,
            "native_failure": {"returncode": run.returncode, "diagnostic_tail": (run.stdout + run.stderr)[-3500:]},
            "input_pcap_sha256": digest(capture.read_bytes()),
            "input_packet_sha256": [digest(wire) for wire in item["frames"]],
            "expected_output_packet_sha256": [digest(wire) for wire in item["expected_frames"]],
            "expected_rebuilt_packet_sha256": sorted(digest(wire) for wire in item["expected_rebuilt"]),
            "logger_records_above_declared_snaplen": 0}
    assert "dump:pcap DAQ configured to inline." in run.stdout
    section = re.search(r"(?m)^daq\n((?:[ \t].*\n)*)", run.stdout)
    assert section
    counts = {key: int(value) for key, value in re.findall(r"(?m)^\s+(\w+):\s+(\d+)\b", section[1])}
    assert counts.get("received") == counts.get("analyzed") == len(item["frames"])
    verdicts = {key: counts[key] for key in sorted(VERDICTS) if counts.get(key)}
    assert sum(verdicts.values()) == len(item["frames"])
    forwarded = pcap_packets(output.read_bytes())
    expected_verdicts = {"allow": len(item["expected_frames"])} if item["expected_frames"] else {}
    if len(item["frames"]) > len(item["expected_frames"]):
        expected_verdicts["block"] = len(item["frames"]) - len(item["expected_frames"])
    records, above_snaplen, logger_errors = [], 0, []
    for path in directory.glob("log.pcap*"):
        packets, count, errors = logged_packets(path)
        records.extend(packets)
        above_snaplen += count
        logger_errors.extend(errors)
    # Multiple events may log the same reconstructed frame. Original fragment
    # event records are distinguished by exact input bytes, never discarded by
    # a loose parse of a potentially malformed reconstructed prefix.
    rebuilt = set(records) - set(item["frames"])
    module, key = {6: ("tcp", "bad_tcp6_checksum"), 17: ("udp", "bad_udp6_checksum"), 58: ("icmp6", "bad_icmp6_checksum")}[item["protocol"]]
    counters = {"reassembled": module_count(run.stdout, "stream_ip", "reassembled"),
                "checksum_errors": module_count(run.stdout, module, key),
                "checksum_bypassed": module_count(run.stdout, module, "checksum_bypassed"),
                "prefix_drops": module_count(run.stdout, "stream_ip", "prefix_drops"),
                "ecn_drops": module_count(run.stdout, "stream_ip", "ecn_drops")}
    desired_counters = {"reassembled": item["expected_reassemblies"], "checksum_errors": 0, "checksum_bypassed": 0,
                        "prefix_drops": item["expected_reason_drops"] if item["reason"] == "prefix" else 0,
                        "ecn_drops": item["expected_reason_drops"] if item["reason"] == "ecn" else 0}
    enforcement = forwarded == item["expected_frames"] and verdicts == expected_verdicts
    prefix = rebuilt == set(item["expected_rebuilt"]) and not logger_errors
    counter_pass = counters == desired_counters
    result = {key: value for key, value in item.items() if key not in ("frames", "expected_frames", "expected_rebuilt")} | {
        "passed": enforcement and prefix and counter_pass, "enforcement_passed": enforcement,
        "rebuilt_bytes_passed": prefix, "counter_passed": counter_pass,
        "daq_verdicts": verdicts, "expected_verdicts": expected_verdicts,
        "counters": counters, "expected_counters": desired_counters,
        "logger_records_above_declared_snaplen": above_snaplen,
        "logger_length_errors": logger_errors,
        "input_pcap_sha256": digest(capture.read_bytes()), "output_pcap_sha256": digest(output.read_bytes()),
        "input_packet_sha256": [digest(wire) for wire in item["frames"]],
        "output_packet_sha256": [digest(wire) for wire in forwarded],
        "expected_output_packet_sha256": [digest(wire) for wire in item["expected_frames"]],
        "logged_packet_sha256": [digest(wire) for wire in records],
        "rebuilt_packet_sha256": sorted(digest(wire) for wire in rebuilt),
        "expected_rebuilt_packet_sha256": sorted(digest(wire) for wire in item["expected_rebuilt"])}
    if not result["passed"]:
        result["diagnostic_tail"] = run.stdout[-3500:]
    return result


def validate(snort, plugin):
    snort, plugin = snort.resolve(strict=True), plugin.resolve(strict=True)
    binary = digest(snort.read_bytes())
    sources = [Path(__file__), *[HERE / name for name in ("home_address_replay.py", "checksum_replay.py",
        "fragment_lifetime_replay.py", "fragment_checksum_replay.py", "generate_pcaps.py", "next_header_policy.py",
        "replay.py", "type2_repair_replay.py")]]
    hashes = {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in sources}
    profiles = load_validator().validate(snort, plugin)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("AX_")}
    configuration = (HERE.parent / "protocol-ips.lua").read_text() + OBSERVER
    with tempfile.TemporaryDirectory(prefix="ax-ipv6-prefix-") as temporary:
        directory = Path(temporary)
        for name in CONFIG_FILES:
            (directory / name).write_bytes((HERE.parent / name).read_bytes())
        config = directory / "observe.lua"
        config.write_text(configuration)
        items = list(fixtures())
        assert len({item["name"] for item in items}) == len(items)
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda item: run_case(snort, plugin, config, directory, item, environment), items))
    assert binary == digest(snort.read_bytes())
    for relative, expected in hashes.items() | profiles["sha256"].items():
        assert digest((ROOT / relative).read_bytes()) == expected
    libraries = [plugin] if plugin.is_file() else sorted(set(plugin.rglob("*.so")) | set(plugin.rglob("*.dylib")))
    assert profiles["plugin_sha256"] == {path.name: digest(path.read_bytes()) for path in libraries}
    failures = [item["name"] for item in results if not item["passed"]]
    return {"status": "conformance_failure" if failures else "verified_expected_behavior",
            "scope": "File-only inline DAQ and exact reconstructed packet logs. Prefix retention, RFC 3168 ECN rules and final size bounds; not Mobile IPv6 endpoint state or deployment proof.",
            "snort_binary_sha256": binary, "configuration": profiles, "fixture_source_sha256": hashes,
            "observer_configuration_sha256": digest(configuration.encode()),
            "summary": {"cases": len(results), "passed": len(results) - len(failures), "failures": failures,
                        "ecn_rejections": sum(item["reason"] == "ecn" for item in results),
                        "size_rejections": sum(item["reason"] == "prefix" for item in results),
                        "retry_cases": sum(item["retry"] for item in results),
                        "valid_controls": sum(not item["reason"] for item in results),
                        "native_failures": sum("native_failure" in item for item in results),
                        "logger_records_above_declared_snaplen": sum(item["logger_records_above_declared_snaplen"] for item in results)},
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
