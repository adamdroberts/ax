#!/usr/bin/env python3
"""Test contradictory final lengths, sparse coverage, retries and valid reassembly."""
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
from fragment_overlap_replay import frame
from generate_pcaps import checksum, ip6, packet
from next_header_policy import CONFIG_FILES, VERDICTS, pcap_packets
from replay import load_validator

if not __debug__:
    raise RuntimeError("validation requires assertions")

COUNTERS = ("reassembled", "nodes_inserted", "nodes_deleted", "max_fragment_nodes",
            "overlap_drops", "extent_drops", "drops", "resource_drops")


def decode(wire):
    ip = wire[14:]
    if ip[0] >> 4 == 4:
        header = (ip[0] & 15) * 4
        field = int.from_bytes(ip[6:8], "big")
        identity = (4, ip[12:20], ip[9], ip[4:6])
        start, more = (field & 8191) * 8, bool(field & 8192)
        assert checksum(ip[:header]) == 0 and len(ip) == int.from_bytes(ip[2:4], "big")
        return identity, start, ip[header:], more
    header = 48 if ip[6] == 60 else 40
    assert ip[6] in (44, 60) and len(ip) == int.from_bytes(ip[4:6], "big") + 40
    field = int.from_bytes(ip[header + 2:header + 4], "big")
    identity = (6, ip[8:40], ip[header + 4:header + 8])
    return identity, field & 65528, ip[header + 8:], bool(field & 1)


def oracle(frames):
    # Independent per-byte occupancy plus pairwise declarations. Do not model
    # the native aggregate counters or infer coverage from a sum of lengths.
    states, rejected, allowed = {}, set(), []
    nodes, completed, first = 0, 0, None
    for i, wire in enumerate(frames):
        identity, start, data, more = decode(wire)
        assert data and (not more or len(data) % 8 == 0)
        end = start + len(data)
        assert end <= 65535
        if identity in rejected:
            continue
        history, occupied = states.get(identity, ([], set()))
        positions = set(range(start, end))
        assert not occupied.intersection(positions), "isolate extent checks from overlap rejection"
        conflict = any((not old_more and not more and old_end != end) or
                       (not old_more and more and end >= old_end) or
                       (old_more and not more and old_end >= end)
                       for old_end, old_more in history)
        if conflict:
            rejected.add(identity)
            states.pop(identity, None)
            first = i if first is None else first
            continue
        history.append((end, more))
        occupied.update(positions)
        allowed.append(i)
        nodes += 1
        finals = [old_end for old_end, old_more in history if not old_more]
        if finals and occupied == set(range(finals[0])):
            completed += 1
            states.pop(identity, None)
        else:
            states[identity] = (history, occupied)
    return allowed, nodes, completed, first


def payload(version, protocol, size):
    data = body(version, protocol)
    if size == len(data):
        return data
    header, offset = (20, 16) if protocol == 6 else (8, 6) if protocol == 17 else (8, 2)
    data = bytearray(data[:header] + bytes((i * 29 + 7) % 256 for i in range(size - header)))
    if protocol == 17:
        data[4:6] = struct.pack("!H", size)
    data[offset:offset + 2] = bytes(2)
    value = checksum(data if protocol == 1 else pseudo(version, protocol, size) + data)
    data[offset:offset + 2] = struct.pack("!H", value or 65535 if protocol == 17 else value)
    return bytes(data)


def make_case(name, version, protocol, spans, order, *, size=72, padding=False,
              policy="linux", limit=1, retry=True, fresh=False, next_header=None):
    data = payload(version, protocol, size)
    covered = data if protocol == 1 else pseudo(version, protocol, size) + data
    assert sum(int.from_bytes(covered[i:i + 2].ljust(2, b"\0"), "big")
               for i in range(0, len(covered), 2)) % 65535 == 0
    originals = [frame(version, protocol, data, *span, padding) for span in spans]
    if next_header is not None:
        assert version == 6
        for i, span in enumerate(spans):
            if span[0]:
                wire = bytearray(originals[i])
                wire[54 + (8 if padding else 0)] = next_header
                originals[i] = bytes(wire)
    wires = [originals[i] for i in order]
    _, _, _, conflict = oracle(wires)
    if conflict is not None and retry:
        wires += [wires[conflict], *originals,
                  frame(version, protocol, data, 0, 24, True, padding),
                  frame(version, protocol, data, 24, size, False, padding)]
    if fresh:
        wires += [frame(version, protocol, data, 0, 24, True, padding, 4567),
                  frame(version, protocol, data, 24, size, False, padding, 4567)]
    allowed, nodes, completed, conflict = oracle(wires)
    drops = len(wires) - len(allowed)
    return {"name": name, "version": version, "protocol": protocol, "policy": policy,
            "max_overlaps": limit, "max_frags": 4096, "frames": wires,
            "expected_frames": [wires[i] for i in allowed], "expected_indices": allowed,
            "arrival_order": list(order), "spans": [list(span) for span in spans],
            "padding": padding, "payload_bytes": size, "next_header": next_header,
            "retry": retry and conflict is not None, "fresh_control": fresh,
            "first_conflict_index": conflict, "valid_control": conflict is None,
            "expected_counters": {"reassembled": completed, "nodes_inserted": nodes,
                                  "nodes_deleted": nodes, "overlap_drops": 0,
                                  "extent_drops": drops, "drops": drops, "resource_drops": 0}}


def fixtures():
    layouts = {
        "two-finals": ((0, 24, True), (24, 48, True), (48, 56, False), (56, 72, False)),
        "more-past-final": ((0, 24, True), (24, 48, False), (48, 72, True)),
        "sparse-past-final": ((0, 24, True), (48, 72, False), (96, 144, True)),
        "valid": ((0, 24, True), (24, 48, True), (48, 72, False)),
        "gap": ((0, 24, True), (48, 72, False)),
        "gap-filled": ((0, 24, True), (48, 72, False), (24, 48, True)),
    }
    for version in (4, 6):
        for protocol in (6, 17, 1 if version == 4 else 58):
            for label, spans in layouts.items():
                for order in itertools.permutations(range(len(spans))):
                    for padded in (False, True):
                        name = f"v{version}-p{protocol}-{label}-pad{int(padded)}-" + "".join(map(str, order))
                        item = make_case(name, version, protocol, spans, order,
                                         size=144 if label == "sparse-past-final" else 72, padding=padded)
                        # Later traffic is independent after valid completion.
                        if label in ("valid", "gap", "gap-filled") or item["first_conflict_index"] is not None:
                            yield item
            for policy in ("first", "linux", "bsd", "bsd_right", "last", "windows", "solaris"):
                for limit in (0, 1, 8):
                    for order in ((2, 3, 0, 1), (3, 2, 1, 0)):
                        yield make_case(f"v{version}-p{protocol}-policy-{policy}-limit{limit}-" + "".join(map(str, order)),
                                        version, protocol, layouts["two-finals"], order, policy=policy, limit=limit)
            for padded in (False, True):
                yield make_case(f"v{version}-p{protocol}-fresh-pad{int(padded)}", version, protocol,
                                layouts["two-finals"], (2, 3, 0, 1), padding=padded, fresh=True)
                size = (65515 - (40 if padded else 0)) if version == 4 else (65535 - (8 if padded else 0))
                spans = ((0, 24, True), (24, 40000, True), (40000, 40008, False), (40008, size, False))
                for order in ((2, 3, 0, 1), (3, 2, 1, 0), (1, 2, 3, 0), (0, 3, 2, 1)):
                    yield make_case(f"v{version}-p{protocol}-wide-pad{int(padded)}-" + "".join(map(str, order)),
                                    version, protocol, spans, order, size=size, padding=padded, retry=False)
            if version == 6:
                for nxt in (0, 6, 17, 44, 58, 59, 253, 255):
                    yield make_case(f"v6-p{protocol}-continuation-next-{nxt}", version, protocol,
                                    layouts["two-finals"], (2, 3, 0, 1), next_header=nxt)


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
    sources = [Path(__file__), *[HERE / name for name in ("fragment_checksum_replay.py", "fragment_lifetime_replay.py", "fragment_overlap_replay.py",
        "checksum_replay.py", "generate_pcaps.py", "next_header_policy.py", "replay.py")]]
    hashes = {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in sources}
    profiles = load_validator().validate(snort, plugin)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("AX_")}
    configurations = {}
    with tempfile.TemporaryDirectory(prefix="ax-fragment-extent-") as temporary:
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
            "scope": "Actual inline file DAQ: finite fragment final-length and contiguous-coverage checks; not live endpoint or deployment proof.",
            "snort_binary_sha256": binary, "configuration": profiles, "fixture_source_sha256": hashes,
            "test_configuration_sha256": configurations,
            "summary": {"cases": len(results), "passed": len(results) - len(failures), "failures": failures,
                        "valid_controls": sum(item["valid_control"] for item in results),
                        "retry_cases": sum(item["retry"] for item in results),
                        "fresh_controls": sum(item["fresh_control"] for item in results),
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
