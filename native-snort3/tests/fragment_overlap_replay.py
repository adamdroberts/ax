#!/usr/bin/env python3
"""Test overlap rejection, tracker quarantine and prompt fragment-buffer release."""
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
from fragment_checksum_replay import HERE, ROOT, digest, ipv4_fragment, pseudo
from fragment_lifetime_replay import body, write_capture
from generate_pcaps import checksum, ip6, packet
from next_header_policy import CONFIG_FILES, VERDICTS, pcap_packets
from replay import load_validator

if not __debug__:
    raise RuntimeError("validation requires assertions")

COUNTERS = ("reassembled", "nodes_inserted", "nodes_deleted", "max_fragment_nodes",
            "overlap_drops", "drops", "resource_drops")


def frame(version, protocol, data, start, end, more, padding=False, identification=1234):
    if version == 4:
        raw = bytearray(ipv4_fragment(data[start:end], protocol, start, more))
        if padding:
            raw = raw[:20] + b"\x01" * (40 if not start else 4) + raw[20:]
            raw[0] = 0x4f if not start else 0x46
            raw[2:4], raw[10:12] = struct.pack("!H", len(raw)), b"\0\0"
            raw[10:12] = struct.pack("!H", checksum(raw[:(raw[0] & 15) * 4]))
        raw[4:6], raw[10:12] = struct.pack("!H", identification), b"\0\0"
        raw[10:12] = struct.pack("!H", checksum(raw[:(raw[0] & 15) * 4]))
        return packet(bytes(raw))
    header = struct.pack("!BBHI", protocol, 0, start | int(more), identification)
    prefix = bytes([44, 0]) + bytes(6) if padding else b""
    return packet(ip6(prefix + header + data[start:end], 60 if padding else 44), 6)


def oracle(frames):
    """Independent per-byte occupancy oracle over serialized packet fragments.

    Keeps a rejected identity until the end of this sub-millisecond capture;
    releases completed identities, so late packets are not falsely considered
    overlaps of an already delivered datagram.
    """
    contexts, rejected, allowed, inserted, completed, first_overlap = {}, set(), [], 0, 0, None
    for arrival, wire in enumerate(frames):
        ip = wire[14:]
        version = ip[0] >> 4
        if version == 4:
            header = (ip[0] & 15) * 4
            assert len(ip) == int.from_bytes(ip[2:4], "big") and checksum(ip[:header]) == 0
            field = int.from_bytes(ip[6:8], "big")
            start, more, data = (field & 8191) * 8, bool(field & 8192), ip[header:]
            identity = (4, ip[12:20], ip[9], ip[4:6])
        else:
            assert len(ip) == int.from_bytes(ip[4:6], "big") + 40
            header = 48 if ip[6] == 60 else 40
            assert ip[6] in (44, 60) and (header == 40 or ip[40:42] == bytes([44, 0]))
            field = int.from_bytes(ip[header + 2:header + 4], "big")
            start, more, data = field & 65528, bool(field & 1), ip[header + 8:]
            identity = (6, ip[8:40], ip[header + 4:header + 8])
        assert data and (not more or len(data) % 8 == 0)
        if identity in rejected:
            continue
        seen, terminal = contexts.get(identity, (set(), None))
        positions = set(range(start, start + len(data)))
        if seen.intersection(positions):
            rejected.add(identity)
            contexts.pop(identity, None)
            if first_overlap is None:
                first_overlap = arrival
            continue
        seen.update(positions)
        if not more:
            assert terminal is None or terminal == start + len(data)
            terminal = start + len(data)
        allowed.append(arrival)
        inserted += 1
        if terminal is not None and seen == set(range(terminal)):
            completed += 1
            contexts.pop(identity, None)
        else:
            contexts[identity] = (seen, terminal)
    return allowed, inserted, completed, first_overlap


def make_case(name, version, protocol, spans, order, *, changed=False, padding=False,
              limit=1, policy="linux", retry=True, cleanup=False, size=72):
    data = body(version, protocol)
    if size != 72:
        header, offset = (20, 16) if protocol == 6 else (8, 6) if protocol == 17 else (8, 2)
        data = bytearray(data[:header] + b"z" * (size - header))
        if protocol == 17:
            data[4:6] = struct.pack("!H", size)
        data[offset:offset + 2] = b"\0\0"
        value = checksum(data if protocol == 1 else pseudo(version, protocol, size) + data)
        data[offset:offset + 2] = struct.pack("!H", value or 65535 if protocol == 17 else value)
        data = bytes(data)
    alternate = data
    if changed:
        # Change two words within a shared payload region while keeping the
        # complete transport checksum valid, so checksums cannot mask the test.
        intersection = sorted(set(range(*spans[0][:2])) & set(range(*spans[1][:2])))
        payload_start = 20 if protocol == 6 else 8
        position = next(i for i in intersection if i >= payload_start and i % 2 == 0 and
                        all(i + j in intersection for j in range(4)))
        words = struct.unpack("!HH", data[position:position + 4])
        alternate = data[:position] + struct.pack("!HH", words[0] + 1, words[1] - 1) + data[position + 4:]
    for payload in (data, alternate):
        covered = payload if protocol == 1 else pseudo(version, protocol, len(payload)) + payload
        assert sum(int.from_bytes(covered[i:i + 2].ljust(2, b"\0"), "big")
                   for i in range(0, len(covered), 2)) % 65535 == 0
    wires = [frame(version, protocol, alternate if changed and i == 1 else data, *span, padding)
             for i, span in enumerate(spans)]
    frames = [wires[i] for i in order]
    allowed, _, _, overlap = oracle(frames)
    if overlap is not None and retry:
        clean = [frame(version, protocol, data, 0, 24, True, padding),
                 frame(version, protocol, data, 24, size, False, padding)]
        frames += [frames[overlap], frames[-1], *clean]
    if cleanup:
        assert overlap is not None
        frames += [frame(version, protocol, data, 0, 24, True, padding, 4567),
                   frame(version, protocol, data, 24, size, False, padding, 4567)]
    allowed, nodes, completed, overlap = oracle(frames)
    drops = len(frames) - len(allowed)
    return {"name": name, "version": version, "protocol": protocol, "policy": policy,
            "max_overlaps": limit, "max_frags": 2 if cleanup else 4096,
            "frames": frames, "expected_frames": [frames[i] for i in allowed],
            "expected_indices": allowed, "arrival_order": list(order), "changed_payload": changed,
            "padding": padding, "retry": retry and overlap is not None, "cleanup_control": cleanup,
            "payload_bytes": size,
            "first_overlap_index": overlap, "valid_control": overlap is None,
            "expected_counters": {"reassembled": completed, "nodes_inserted": nodes, "nodes_deleted": nodes,
                                  "overlap_drops": drops, "drops": drops, "resource_drops": 0}}


def fixtures():
    layouts = {
        "partial": ((0, 32, True), (24, 48, True), (48, 72, False)),
        "contained": ((0, 48, True), (24, 32, True), (48, 72, False)),
        "duplicate-first": ((0, 32, True), (0, 32, True), (32, 72, False)),
        "same-start": ((0, 24, True), (0, 40, True), (40, 72, False)),
        "same-end": ((0, 40, True), (24, 40, True), (40, 72, False)),
        "duplicate-last": ((48, 72, False), (48, 72, False), (0, 48, True)),
        "adjacent": ((0, 24, True), (24, 48, True), (48, 72, False)),
    }
    for version in (4, 6):
        for protocol in (6, 17, 1 if version == 4 else 58):
            for limit in ((1,) if version == 4 else (1, 0)):
                for label, spans in layouts.items():
                    for order in itertools.permutations(range(3)):
                        for changed in (False, True) if label != "adjacent" else (False,):
                            for padding in (False, True):
                                name = f"v{version}-p{protocol}-limit{limit}-{label}-" + "".join(map(str, order)) + f"-change{int(changed)}-pad{int(padding)}"
                                item = make_case(name, version, protocol, spans, order,
                                                 changed=changed, padding=padding, limit=limit)
                                # Isolate overlaps detected before a datagram completes.
                                if label == "adjacent" or item["first_overlap_index"] is not None:
                                    yield item
            for limit in ((1,) if version == 4 else (0, 1, 8)):
                for policy in ("first", "linux", "bsd", "bsd_right", "last", "windows", "solaris"):
                    for reverse in (False, True):
                        yield make_case(f"v{version}-p{protocol}-policy-{policy}-limit{limit}-reverse{int(reverse)}",
                                        version, protocol, layouts["partial"], (1, 0, 2) if reverse else (0, 1, 2),
                                        limit=limit, policy=policy, changed=True)
            for padded in (False, True):
                for order in ((0, 1, 2), (1, 0, 2)):
                    yield make_case(f"v{version}-p{protocol}-cleanup-pad{int(padded)}-" + "".join(map(str, order)),
                                    version, protocol, layouts["partial"], order, padding=padded, cleanup=True, retry=False)
            for padding in (False, True):
                size = (65515 - (40 if padding else 0)) if version == 4 else (65535 - (8 if padding else 0))
                for changed in (False, True):
                    for order in ((0, 1, 2), (1, 0, 2)):
                        yield make_case(f"v{version}-p{protocol}-wide-pad{int(padding)}-change{int(changed)}-" + "".join(map(str, order)),
                                        version, protocol, ((0, 40000, True), (39992, 50000, True), (50000, size, False)),
                                        order, changed=changed, padding=padding, retry=False, size=size)


def config_key(item):
    return f"{item['policy']}-limit{item['max_overlaps']}-nodes{item['max_frags']}"


def run_case(snort, plugin, config, directory, item, environment):
    capture, output = (directory / (item["name"] + suffix) for suffix in (".pcap", "-forwarded.pcap"))
    assert all(len(wire) <= 65535 for wire in item["frames"])
    write_capture(capture, item["frames"], [i * 100 for i in range(len(item["frames"]))])
    command = [str(snort), "--plugin-path", str(plugin), "-c", str(config), "--daq", "pcap", "--daq-mode", "read-file",
               "--daq", "dump", "--daq-mode", "inline", "--daq-var", "file=" + str(output), "-Q", "-r", str(capture),
               "-s", "65535", "-A", "alert_json"]
    run = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=30)
    result = {key: value for key, value in item.items() if key not in ("frames", "expected_frames")}
    result.update(input_pcap_sha256=digest(capture.read_bytes()),
                  input_packet_sha256=[digest(wire) for wire in item["frames"]],
                  expected_output_packet_sha256=[digest(wire) for wire in item["expected_frames"]])
    if run.returncode or run.stderr.strip():
        return result | {"passed": False, "enforcement_passed": False, "counter_passed": False,
                         "native_failure": {"returncode": run.returncode, "diagnostic_tail": (run.stdout + run.stderr)[-3000:]}}
    assert "dump:pcap DAQ configured to inline." in run.stdout
    section = re.search(r"(?m)^daq\n((?:[ \t].*\n)*)", run.stdout)
    assert section
    counts = {key: int(value) for key, value in re.findall(r"(?m)^\s+(\w+):\s+(\d+)\b", section[1])}
    assert counts.get("received") == counts.get("analyzed") == len(item["frames"])
    verdicts = {key: counts[key] for key in sorted(VERDICTS) if counts.get(key)}
    assert sum(verdicts.values()) == len(item["frames"])
    forwarded = pcap_packets(output.read_bytes())
    expected = {"allow": len(item["expected_frames"])}
    if len(item["frames"]) > len(item["expected_frames"]):
        expected["block"] = len(item["frames"]) - len(item["expected_frames"])
    counters = {key: module_count(run.stdout, "stream_ip", key) for key in COUNTERS}
    checksum_errors = sum(module_count(run.stdout, module, key) for module, key in
        (("tcp", "bad_tcp4_checksum"), ("tcp", "bad_tcp6_checksum"), ("udp", "bad_udp4_checksum"),
         ("udp", "bad_udp6_checksum"), ("icmp4", "bad_checksum"), ("icmp6", "bad_icmp6_checksum")))
    enforcement = forwarded == item["expected_frames"] and verdicts == expected
    counter_pass = not checksum_errors and all(counters[key] == value for key, value in item["expected_counters"].items())
    counter_pass &= counters["max_fragment_nodes"] <= item["max_frags"]
    result.update(passed=enforcement and counter_pass, enforcement_passed=enforcement, counter_passed=counter_pass,
                  daq_verdicts=verdicts, expected_verdicts=expected, counters=counters, checksum_errors=checksum_errors,
                  output_pcap_sha256=digest(output.read_bytes()), output_packet_sha256=[digest(wire) for wire in forwarded],
                  events=[json.loads(line) for line in run.stdout.splitlines() if line.startswith("{")])
    if not result["passed"]:
        result["diagnostic_tail"] = run.stdout[-2500:]
    return result


def validate(snort, plugin):
    snort, plugin = snort.resolve(strict=True), plugin.resolve(strict=True)
    binary = digest(snort.read_bytes())
    sources = [Path(__file__), *[HERE / name for name in ("fragment_checksum_replay.py", "fragment_lifetime_replay.py",
        "checksum_replay.py", "generate_pcaps.py", "next_header_policy.py", "replay.py")]]
    hashes = {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in sources}
    profiles = load_validator().validate(snort, plugin)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("AX_")}
    configurations = {}
    with tempfile.TemporaryDirectory(prefix="ax-fragment-overlap-") as temporary:
        directory = Path(temporary)
        for name in CONFIG_FILES:
            (directory / name).write_bytes((HERE.parent / name).read_bytes())
        original = (HERE.parent / "protocol-ips.lua").read_text()
        items = list(fixtures())
        assert len({item["name"] for item in items}) == len(items)
        for item in items:
            key = config_key(item)
            if key not in configurations:
                source = original
                for old, new in (("max_overlaps = 1,", f"max_overlaps = {item['max_overlaps']},"),
                                 ("max_frags = 4096,", f"max_frags = {item['max_frags']},"),
                                 ("policy = 'linux', max_frags", f"policy = '{item['policy']}', max_frags")):
                    assert source.count(old) == 1
                    source = source.replace(old, new)
                (directory / (key + ".lua")).write_text(source)
                configurations[key] = digest(source.encode())
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda item: run_case(snort, plugin, directory / (config_key(item) + ".lua"),
                                    directory, item, environment), items))
    assert binary == digest(snort.read_bytes())
    for relative, expected in hashes.items() | profiles["sha256"].items():
        assert digest((ROOT / relative).read_bytes()) == expected
    libraries = [plugin] if plugin.is_file() else sorted(set(plugin.rglob("*.so")) | set(plugin.rglob("*.dylib")))
    assert profiles["plugin_sha256"] == {path.name: digest(path.read_bytes()) for path in libraries}
    failures = [item["name"] for item in results if not item["passed"]]
    return {"status": "conformance_failure" if failures else "verified_expected_behavior",
            "scope": "Actual inline file DAQ: finite IPv6 overlap rejection and explicit IPv4 no-overlap policy; not live endpoint or deployment proof.",
            "snort_binary_sha256": binary, "configuration": profiles, "fixture_source_sha256": hashes,
            "test_configuration_sha256": configurations,
            "summary": {"cases": len(results), "passed": len(results) - len(failures), "failures": failures,
                        "valid_controls": sum(item["valid_control"] for item in results),
                        "retry_cases": sum(item["retry"] for item in results),
                        "cleanup_controls": sum(item["cleanup_control"] for item in results),
                        "enforcement_failures": sum(not item["enforcement_passed"] for item in results),
                        "native_failures": sum("native_failure" in item for item in results)}, "cases": results}


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
