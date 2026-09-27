#!/usr/bin/env python3
"""Replay IPv4 first-header, ECN and size invariants through the actual inline DAQ.

TTL 41 is only a temporary test policy, not an invalid value in the protocol.
All packets are synthetic and remain in local capture files.
"""
import argparse
import concurrent.futures
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
from generate_pcaps import checksum, packet
from ipv6_prefix_replay import logged_packets
from next_header_policy import CONFIG_FILES, VERDICTS, pcap_packets
from replay import load_validator
from fragment_checksum_replay import HERE, ROOT, digest, pseudo

if not __debug__:
    raise RuntimeError("validation requires assertions")

OBSERVER = '''
log_pcap = {}
ips.rules = ips.rules .. [[
log ip any any -> any any (msg:"AX reconstructed IPv4 bytes"; flow:only_frag; sid:2999120; rev:1;)
]]
ips.states = ips.states .. [[
log ( gid:1; sid:2999120; enable:yes; )
]]
'''
ENFORCER = '''
ips.rules = ips.rules .. [[
drop ip any any -> any any (msg:"AX first IPv4 header test policy"; flow:only_frag; ttl:41; sid:2999121; rev:1;)
]]
ips.states = ips.states .. [[
drop ( gid:1; sid:2999121; enable:yes; )
]]
'''


def transport(protocol, size, zero=False):
    if protocol == 6:
        data = struct.pack("!HHIIBBHHH", 50000, 80, 100, 0, 80, 2, 65535, 0, 0)
        offset = 16
    elif protocol == 17:
        data, offset = struct.pack("!HHHH", 50000, 9999, size, 0), 6
    else:
        data, offset = struct.pack("!BBHHH", 8, 0, 0, 1, 1), 2
    data += bytes((index * 29 + 7) % 256 for index in range(size - len(data)))
    prefix = b"" if protocol == 1 else pseudo(4, protocol, size)
    value = checksum(prefix + data)
    if protocol == 17:
        value = 0 if zero else value or 65535
    result = data[:offset] + struct.pack("!H", value) + data[offset + 2:]
    # Independent arithmetic over serialized bytes, not the C++ repair helper.
    assert zero or sum(int.from_bytes((prefix + result)[index:index + 2].ljust(2, b"\0"), "big")
                       for index in range(0, len(prefix + result), 2)) % 65535 == 0
    return result


def network(data, protocol, options, offset, more, index, ecn, *, ttl_base=41):
    assert len(options) % 4 == 0 and len(options) <= 40 and offset % 8 == 0
    total = 20 + len(options) + len(data)
    assert total <= 65535
    head = struct.pack("!BBHHHBBH4s4s", 0x45 + len(options) // 4,
                       ((0x28 + 4 * index) & 0xfc) | ecn, total, 2468,
                       (offset // 8) | (0x2000 if more else 0), ttl_base + index, protocol, 0,
                       b"\xc0\x00\x02\x0a", b"\xc6\x33\x64\x14") + options
    head = head[:10] + struct.pack("!H", checksum(head)) + head[12:]
    assert sum(int.from_bytes(head[i:i + 2], "big") for i in range(0, len(head), 2)) % 65535 == 0
    return packet(head + data)


def make_case(name, protocol, options, codes, order, *, size=72, splits=None,
              retry=False, zero=False, policy="observe", ttl_base=41):
    data = transport(protocol, size, zero)
    count = len(codes)
    starts = splits or (list(range(0, size, 16000)) if size > 72 else
                        [0, 24] if count == 2 else [0, 24, 48])
    assert len(starts) == count and sorted(order) == list(range(count))
    ends = starts[1:] + [size]
    wires = [network(data[start:end], protocol, options[i], start, end < size, i, codes[i], ttl_base=ttl_base)
             for i, (start, end) in enumerate(zip(starts, ends))]
    ordered = [wires[index] for index in order]
    seen, rejected, reason, zero_seen, largest_end = set(), None, "", False, 0
    for arrival, index in enumerate(order):
        zero_seen = zero_seen or index == 0
        largest_end = max(largest_end, ends[index])
        if largest_end + 20 + (len(options[0]) if zero_seen else 0) > 65535:
            rejected, reason = arrival, "prefix"
            break
        seen.add(codes[index])
        if 0 in seen and 3 in seen:
            rejected, reason = arrival, "ecn"
            break
    rebuilt = [] if rejected is not None else [network(data, protocol, options[0], 0, False, 0,
                3 if 3 in codes else codes[0], ttl_base=ttl_base)]
    forwarded = ordered if rejected is None else ordered[:rejected]
    if policy == "enforce" and ttl_base == 41 and rejected is None:
        forwarded = ordered[:-1]
    if retry:
        assert rejected is not None
        ordered = ordered + [ordered[-1], *ordered]
    return {"name": name, "protocol": protocol, "frames": ordered, "policy": policy,
            "expected_frames": forwarded, "expected_rebuilt": rebuilt,
            "arrival_order": list(order), "ecn": list(codes), "payload_bytes": size,
            "first_header_bytes": 20 + len(options[0]), "original_fragment_count": count,
            "expected_reassemblies": int(rejected is None), "reason": reason, "retry": retry,
            "zero_udp_checksum": zero, "expected_reason_drops": len(ordered) - rejected if rejected is not None else 0}


def fixtures():
    for protocol, zero in ((6, False), (17, False), (17, True), (1, False)):
        for options in ([b"", b""], [b"\x01" * 4, b"\x01" * 40]):
            for codes in itertools.product(range(4), repeat=2):
                for order in ((0, 1), (1, 0)):
                    name = f"ecn-p{protocol}-zero{int(zero)}-pad{len(options[0])}-" + "".join(map(str, codes)) + "-" + "".join(map(str, order))
                    item = make_case(name, protocol, options, codes, order, zero=zero)
                    yield item
                    if item["reason"]:
                        yield make_case(name + "-retry", protocol, options, codes, order, zero=zero, retry=True)
        for option_bytes in (0, 4, 40):
            for delta in (-1, 0, 1):
                size = 65515 - option_bytes + delta
                count = (size + 15999) // 16000
                options = [b"\x01" * option_bytes] + [b"", b"\x01" * 4, b"\x01" * 40, b""][:count - 1]
                for order in (tuple(range(count)), tuple(reversed(range(count))), tuple(range(1, count)) + (0,)):
                    name = f"length-p{protocol}-zero{int(zero)}-pad{option_bytes}-delta{delta}-" + "".join(map(str, order))
                    yield make_case(name, protocol, options, [2] * count, order, size=size, zero=zero)
                    if delta == 1:
                        yield make_case(name + "-retry", protocol, options, [2] * count, order,
                                        size=size, zero=zero, retry=True)
        for split in (24, 32768, 50000, 65456):
            for order in ((0, 1), (1, 0)):
                name = f"wide-p{protocol}-zero{int(zero)}-split{split}-" + "".join(map(str, order))
                yield make_case(name, protocol, [b"\x01" * 40, b""], [2, 3], order,
                                size=65475, splits=[0, split], zero=zero)
        for first, later in ((b"", b""), (b"\x01" * 4, b""), (b"", b"\x01" * 40),
                             (b"\x01" * 40, b"\x01" * 4)):
            for ttl_base in (41, 51):
                for order in ((0, 1), (1, 0)):
                    name = f"policy-p{protocol}-zero{int(zero)}-pad{len(first)}-{len(later)}-ttl{ttl_base}-" + "".join(map(str, order))
                    yield make_case(name, protocol, [first, later], [2, 2], order, zero=zero,
                                    policy="enforce", ttl_base=ttl_base)
    for codes in itertools.product(range(4), repeat=3):
        for order in itertools.permutations(range(3)):
            yield make_case("ecn-three-" + "".join(map(str, codes)) + "-" + "".join(map(str, order)),
                            17, [b"\x01" * 40, b"", b"\x01" * 4], codes, order)
    for protocol in (6, 17, 1):
        for offset, size in ((65504, 11), (65512, 3), (65512, 4), (65520, 1), (65528, 8)):
            wire = network(b"Z" * size, protocol, b"", offset, False, 0, 2)
            invalid = offset + size + 20 > 65535
            for retry in (False, True) if invalid else (False,):
                frames = [wire]
                if retry:
                    good = make_case("retry", protocol, [b"", b""], [2, 2], (0, 1))
                    frames += [wire, *good["frames"]]
                yield {"name": f"orphan-p{protocol}-offset{offset}-size{size}" + ("-retry" if retry else ""),
                       "protocol": protocol, "frames": frames, "policy": "observe",
                       "expected_frames": [] if invalid else frames, "expected_rebuilt": [],
                       "arrival_order": [0], "ecn": [2], "payload_bytes": size,
                       "first_header_bytes": None, "original_fragment_count": 1,
                       "expected_reassemblies": 0, "reason": "prefix" if invalid else "", "retry": retry,
                       "zero_udp_checksum": False, "expected_reason_drops": len(frames) if invalid else 0}


def run_case(snort, plugin, config, directory, item, environment):
    directory = directory / item["name"]
    directory.mkdir()
    capture, output = directory / "input.pcap", directory / "output.pcap"
    assert all(len(wire) <= 65535 for wire in item["frames"]), "input exceeds DAQ capture limit"
    write_capture(capture, item["frames"], [i * 100 for i in range(len(item["frames"]))])
    command = [str(snort), "--plugin-path", str(plugin), "-c", str(config), "--daq", "pcap", "--daq-mode", "read-file",
               "--daq", "dump", "--daq-mode", "inline", "--daq-var", "file=" + str(output), "-Q", "-r", str(capture),
               "-s", "65535", "-l", str(directory)]
    run = subprocess.run(command, cwd=directory, env=environment, text=True, capture_output=True, timeout=30)
    result = {key: value for key, value in item.items() if key not in ("frames", "expected_frames", "expected_rebuilt")}
    result.update(input_pcap_sha256=digest(capture.read_bytes()),
                  input_packet_sha256=[digest(wire) for wire in item["frames"]],
                  expected_output_packet_sha256=[digest(wire) for wire in item["expected_frames"]],
                  expected_rebuilt_packet_sha256=sorted(digest(wire) for wire in item["expected_rebuilt"]))
    if run.returncode or run.stderr.strip():
        return result | {"passed": False, "enforcement_passed": False, "rebuilt_bytes_passed": False,
                         "counter_passed": False, "logger_records_above_declared_snaplen": 0,
                         "native_failure": {"returncode": run.returncode, "diagnostic_tail": (run.stdout + run.stderr)[-3500:]}}
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
    rebuilt = set(records) - set(item["frames"])
    module, key = {6: ("tcp", "bad_tcp4_checksum"), 17: ("udp", "bad_udp4_checksum"), 1: ("icmp4", "bad_checksum")}[item["protocol"]]
    counters = {"reassembled": module_count(run.stdout, "stream_ip", "reassembled"),
                "checksum_errors": module_count(run.stdout, module, key),
                "checksum_bypassed": module_count(run.stdout, module, "checksum_bypassed"),
                "prefix_drops": module_count(run.stdout, "stream_ip", "prefix_drops"),
                "ecn_drops": module_count(run.stdout, "stream_ip", "ecn_drops")}
    desired = {"reassembled": item["expected_reassemblies"], "checksum_errors": 0, "checksum_bypassed": 0,
               "prefix_drops": item["expected_reason_drops"] if item["reason"] == "prefix" else 0,
               "ecn_drops": item["expected_reason_drops"] if item["reason"] == "ecn" else 0}
    enforcement = forwarded == item["expected_frames"] and verdicts == expected_verdicts
    prefix = rebuilt == set(item["expected_rebuilt"]) and not logger_errors
    counter_pass = counters == desired
    result.update(passed=enforcement and prefix and counter_pass, enforcement_passed=enforcement,
                  rebuilt_bytes_passed=prefix, counter_passed=counter_pass, daq_verdicts=verdicts,
                  expected_verdicts=expected_verdicts, counters=counters, expected_counters=desired,
                  logger_records_above_declared_snaplen=above_snaplen, logger_length_errors=logger_errors,
                  output_pcap_sha256=digest(output.read_bytes()), output_packet_sha256=[digest(wire) for wire in forwarded],
                  logged_packet_sha256=[digest(wire) for wire in records],
                  rebuilt_packet_sha256=sorted(digest(wire) for wire in rebuilt))
    if not result["passed"]:
        result["diagnostic_tail"] = run.stdout[-3500:]
    return result


def validate(snort, plugin):
    snort, plugin = snort.resolve(strict=True), plugin.resolve(strict=True)
    binary = digest(snort.read_bytes())
    sources = [Path(__file__), *[HERE / name for name in ("ipv6_prefix_replay.py", "home_address_replay.py",
        "checksum_replay.py", "fragment_lifetime_replay.py", "fragment_checksum_replay.py", "generate_pcaps.py",
        "next_header_policy.py", "replay.py", "type2_repair_replay.py")]]
    hashes = {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in sources}
    profiles = load_validator().validate(snort, plugin)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("AX_")}
    base = (HERE.parent / "protocol-ips.lua").read_text() + OBSERVER
    configurations = {"observe": base, "enforce": base + ENFORCER}
    with tempfile.TemporaryDirectory(prefix="ax-ipv4-prefix-") as temporary:
        directory = Path(temporary)
        for name in CONFIG_FILES:
            (directory / name).write_bytes((HERE.parent / name).read_bytes())
        for name, value in configurations.items():
            (directory / (name + ".lua")).write_text(value)
        items = list(fixtures())
        assert len({item["name"] for item in items}) == len(items)
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda item: run_case(snort, plugin, directory / (item["policy"] + ".lua"),
                                    directory, item, environment), items))
    assert binary == digest(snort.read_bytes())
    for relative, expected in hashes.items() | profiles["sha256"].items():
        assert digest((ROOT / relative).read_bytes()) == expected
    libraries = [plugin] if plugin.is_file() else sorted(set(plugin.rglob("*.so")) | set(plugin.rglob("*.dylib")))
    assert profiles["plugin_sha256"] == {path.name: digest(path.read_bytes()) for path in libraries}
    failures = [item["name"] for item in results if not item["passed"]]
    return {"status": "conformance_failure" if failures else "verified_expected_behavior",
            "scope": "File-only inline DAQ and exact reconstructed bytes. RFC 791 header/length and RFC 3168 ECN checks plus a temporary TTL policy; not universal compliance or deployment proof.",
            "snort_binary_sha256": binary, "configuration": profiles, "fixture_source_sha256": hashes,
            "test_configuration_sha256": {name: digest(value.encode()) for name, value in configurations.items()},
            "summary": {"cases": len(results), "passed": len(results) - len(failures), "failures": failures,
                        "ecn_rejections": sum(item["reason"] == "ecn" for item in results),
                        "size_rejections": sum(item["reason"] == "prefix" for item in results),
                        "retry_cases": sum(item["retry"] for item in results),
                        "valid_controls": sum(not item["reason"] for item in results),
                        "local_policy_bypass_cases": sum(not item["enforcement_passed"] for item in results if item["policy"] == "enforce"),
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
    print(json.dumps({key: value for key, value in result["summary"].items() if key != "failures"}, indent=2))
    raise SystemExit(bool(result["summary"]["failures"]))


if __name__ == "__main__":
    main()
