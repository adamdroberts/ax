#!/usr/bin/env python3
"""Test fragment identity preservation, inspection and independent datagram isolation."""
import argparse
import concurrent.futures
import itertools
import ipaddress
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


DENY_SID = 2999140
DENY = '''
ips.rules = ips.rules .. [[
drop ip any any -> any any (msg:"AX fragment identity policy oracle"; flow:only_frag; content:"AX_IDENTITY_DENY"; sid:2999140; rev:1;)
]]
ips.states = ips.states .. [[
drop ( gid:1; sid:2999140; enable:yes; )
]]
'''


def datagram(version, protocol, identification, next_header=None, valid=True, padding=False,
             source=None, destination=None):
    source = source or ("192.0.2.10" if version == 4 else "2001:db8::1")
    destination = destination or ("198.51.100.20" if version == 4 else "2001:db8::2")
    src, dst = ipaddress.ip_address(source).packed, ipaddress.ip_address(destination).packed
    data = bytearray(body(version, protocol))
    header, checksum_offset = (20, 16) if protocol == 6 else (8, 6) if protocol == 17 else (8, 2)
    data[header:header + 16] = b"AX_IDENTITY_DENY"
    assert len(data) == 72
    assert protocol != 17 or int.from_bytes(data[4:6], "big") == len(data)
    data[checksum_offset:checksum_offset + 2] = bytes(2)
    prefix = b"" if protocol == 1 and version == 4 else src + dst + (
        struct.pack("!BBH", 0, protocol, len(data)) if version == 4 else struct.pack("!I3xB", len(data), protocol))
    value = checksum(prefix + data)
    data[checksum_offset:checksum_offset + 2] = struct.pack("!H", value or 65535 if protocol == 17 else value)
    assert checksum(prefix + data) == 0
    if not valid:
        data[-1] ^= 1
        assert checksum(prefix + data) != 0
    wires = []
    for start, end, more in ((0, 24, True), (24, len(data), False)):
        wire = bytearray(frame(version, protocol, bytes(data), start, end, more, padding, identification))
        if version == 4:
            wire[26:34] = src + dst
            size = (wire[14] & 15) * 4
            wire[24:26] = bytes(2)
            wire[24:26] = struct.pack("!H", checksum(wire[14:14 + size]))
        else:
            wire[22:54] = src + dst
            if start and next_header is not None:
                wire[54 + (8 if padding else 0)] = next_header
        wires.append(bytes(wire))
    return wires


def identity(wire):
    raw = wire[14:]
    if raw[0] >> 4 == 4:
        return (4, raw[12:20], raw[9], raw[4:6])
    offset = 48 if raw[6] == 60 else 40
    return (6, raw[8:40], raw[offset + 4:offset + 8])


def make_case(name, version, protocol, datagrams, order, *, valid=True, policy="observe", metadata=None):
    wires = [datagrams[which][part] for which, part in order]
    keys = [identity(parts[0]) for parts in datagrams]
    assert len(set(keys)) == len(keys)
    assert all(identity(parts[0]) == identity(parts[1]) for parts in datagrams)
    seen, allowed, checksums, completed = {}, [], 0, 0
    for i, ((which, part), wire) in enumerate(zip(order, wires)):
        key = identity(wire)
        seen.setdefault(key, set()).add(part)
        complete = seen[key] == {0, 1}
        if complete:
            completed += 1
            checksums += int(not valid)
        if not complete or (valid and policy == "observe"):
            allowed.append(i)
    return {"name": name, "version": version, "protocol": protocol, "valid": valid,
            "policy": policy, "frames": wires, "expected_frames": [wires[i] for i in allowed],
            "expected_indices": allowed, "arrival_order": [list(pair) for pair in order],
            "datagrams": len(datagrams), "metadata": metadata or {}, "max_frags": 4096,
            "expected_checksum_errors": checksums,
            "expected_counters": {"reassembled": completed, "nodes_inserted": len(wires),
                                  "nodes_deleted": len(wires), "overlap_drops": 0,
                                  "extent_drops": 0, "drops": 0, "resource_drops": 0}}


def fixtures():
    ids = (0, 1, 8, 9, 10, 128, 129, 133, 134, 65535, 65536, 65537, 0x12340001, 0xffff0081, 0xffffffff)
    for protocol in (6, 17, 58):
        for identification in ids:
            for nxt in sorted({protocol, 1, 58}):
                for valid in (False, True):
                    for reverse in (False, True):
                        order = [(0, 1), (0, 0)] if reverse else [(0, 0), (0, 1)]
                        name = f"v6-p{protocol}-id{identification}-next{nxt}-valid{int(valid)}-reverse{int(reverse)}"
                        yield make_case(name, 6, protocol, [datagram(6, protocol, identification, nxt, valid)], order,
                                        valid=valid, metadata={"id": identification, "continuation_next": nxt})
        for identification in (129, 133, 65537, 0xffff0081):
            for nxt in (1, 58):
                for reverse in (False, True):
                    for padding in (False, True):
                        order = [(0, 1), (0, 0)] if reverse else [(0, 0), (0, 1)]
                        name = f"v6-p{protocol}-policy-id{identification}-next{nxt}-reverse{int(reverse)}-pad{int(padding)}"
                        yield make_case(name, 6, protocol, [datagram(6, protocol, identification, nxt, padding=padding)], order,
                                        policy="deny", metadata={"id": identification, "continuation_next": nxt, "padding": padding})
    # ID high bits must distinguish ICMPv6 fragmented datagrams, including IDs
    # whose low bits resemble ICMP message types. Use actual wire identities.
    for low in (0, 1, 9, 10, 128, 129, 133, 134, 1234, 65535):
        ids_pair = (65536 + low, 131072 + low)
        for reverse in (False, True):
            for valid in (False, True):
                parts = [datagram(6, 58, value, valid=valid) for value in ids_pair]
                order = [(0, 1), (1, 1), (0, 0), (1, 0)] if reverse else [(0, 0), (1, 0), (0, 1), (1, 1)]
                yield make_case(f"v6-icmp-id-isolation-low{low}-valid{int(valid)}-reverse{int(reverse)}",6,58,parts,order,
                                valid=valid,metadata={"ids":list(ids_pair)})
    # ICMP session normalization must never erase a fragment's source or
    # destination address based on the numeric value of its ID.
    for version, protocol, ids_ in ((4, 1, (0, 8, 9, 10, 11, 65535)), (6, 58, (0, 128, 129, 133, 134, 65537))):
        for identification in ids_:
            for side in ("source", "destination"):
                for reverse in (False, True):
                    first = datagram(version, protocol, identification)
                    address = ("192.0.2.11" if side == "source" else "198.51.100.21") if version == 4 else (
                        "2001:db8::11" if side == "source" else "2001:db8::22")
                    second = datagram(version, protocol, identification, **{side:address})
                    order = [(0, 1), (1, 1), (0, 0), (1, 0)] if reverse else [(0, 0), (1, 0), (0, 1), (1, 1)]
                    yield make_case(f"v{version}-address-isolation-id{identification}-{side}-reverse{int(reverse)}",
                                    version,protocol,[first,second],order,metadata={"id":identification,"different":side})
    # IPv4 retains protocol as part of its fragment identity.
    for identification in (0, 9, 10, 129, 65535):
        for protocols in ((6,17),(1,17),(1,6)):
            for reverse in (False,True):
                parts=[datagram(4,p,identification) for p in protocols]
                order=[(0,1),(1,1),(0,0),(1,0)] if reverse else [(0,0),(1,0),(0,1),(1,1)]
                yield make_case(f"v4-protocol-isolation-id{identification}-p{protocols[0]}-{protocols[1]}-reverse{int(reverse)}",
                                4,protocols[0],parts,order,metadata={"id":identification,"protocols":list(protocols)})


def config_key(item):
    return item["policy"]


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
    counter_pass = checksum_errors == item["expected_checksum_errors"] and all(counters[key] == value for key, value in item["expected_counters"].items())
    counter_pass &= counters["max_fragment_nodes"] <= item["max_frags"]
    if item["policy"] == "deny":
        counter_pass &= sum(json.loads(line).get("rule") == f"1:{DENY_SID}:1" for line in run.stdout.splitlines() if line.startswith("{")) == item["datagrams"]
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
    with tempfile.TemporaryDirectory(prefix="ax-fragment-identity-") as temporary:
        directory = Path(temporary)
        for name in CONFIG_FILES:
            (directory / name).write_bytes((HERE.parent / name).read_bytes())
        original = (HERE.parent / "protocol-ips.lua").read_text()
        items = list(fixtures())
        assert len({item["name"] for item in items}) == len(items)
        for item in items:
            key = config_key(item)
            if key not in configurations:
                source = original + (DENY if key == "deny" else "")
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
            "scope": "Actual inline file DAQ: finite fragment identity, reassembly inspection and context isolation checks; not live endpoint or deployment proof.",
            "snort_binary_sha256": binary, "configuration": profiles, "fixture_source_sha256": hashes,
            "test_configuration_sha256": configurations,
            "summary": {"cases": len(results), "passed": len(results) - len(failures), "failures": failures,
                        "valid_controls": sum(item["valid"] and item["policy"] == "observe" for item in results),
                        "policy_cases": sum(item["policy"] == "deny" for item in results),
                        "isolation_cases": sum(item["datagrams"] > 1 for item in results),
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
