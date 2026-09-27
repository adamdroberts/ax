#!/usr/bin/env python3
"""Audit fragment allocation limits and lost-state handling with inline file DAQ."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from checksum_replay import module_count
from fragment_checksum_replay import fragments, ipv4_fragment
from fragment_lifetime_replay import body, with_id, write_capture
from generate_pcaps import ip6, packet
from next_header_policy import CONFIG_FILES, VERDICTS, pcap_packets
from replay import load_validator

if not __debug__:
    raise RuntimeError("validation requires assertions")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
COUNTERS = ("reassembled", "nodes_inserted", "nodes_deleted", "max_fragment_nodes",
            "resource_drops", "state_lost_drops", "premature_state_losses", "drops")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def datagram(version, protocol=17, identification=1234, cuts=(24,), order=None):
    count = len(cuts) + 1
    return [with_id(frame, version, identification) for frame in fragments(
        version, protocol, body(version, protocol), cuts, range(count) if order is None else order)]


def unfragmented(version):
    payload = body(version, 17)
    return with_id(packet(ipv4_fragment(payload, 17, 0, False)), 4, 40001) if version == 4 else packet(ip6(payload, 17), 6)


def case(name, frames, allowed, *, version, protocol=17, budget=4096, capacity=4096,
         reassembled=0, nodes=0, peak=0, resource_drops=0, state_drops=0,
         checksum_errors=0, kind="nodes", policy="linux", retries=False,
         recovery=False, times=None, bad_datagrams=()):
    assert allowed == sorted(set(allowed)) and all(0 <= index < len(frames) for index in allowed)
    return {"name": name, "kind": kind, "version": version, "protocol": protocol,
            "max_frags": budget, "max_flows": capacity, "policy": policy,
            "retries": retries, "recovery": recovery, "bad_datagrams": list(bad_datagrams),
            "frames": frames, "times_us": times or [i * 100 for i in range(len(frames))],
            "expected_indices": allowed, "expected_frames": [frames[index] for index in allowed],
            "valid_control": len(allowed) == len(frames),
            "expected_counters": {"reassembled": reassembled, "nodes_inserted": nodes,
                "nodes_deleted": nodes, "max_fragment_nodes": peak, "resource_drops": resource_drops,
                "state_lost_drops": state_drops, "drops": resource_drops + state_drops},
            "expected_checksum_errors": checksum_errors}


def node_fixtures():
    for version in (4, 6):
        for protocol in (6, 17, 1 if version == 4 else 58):
            layouts = ((24,), (24, 48)) + (() if protocol == 6 else (tuple(range(8, 72, 8)),))
            for cuts in layouts:
                count = len(cuts) + 1
                for reverse in (False, True):
                    order = list(reversed(range(count))) if reverse else list(range(count))
                    frames = datagram(version, protocol, cuts=cuts, order=order)
                    for budget in (1, 2, 3, 8, 9):
                        over = count > budget
                        for retry in ((False, True) if over else (False,)):
                            submitted = frames + ([frames[0], frames[-1]] if retry else [])
                            allowed = list(range(min(count, budget)))
                            name = f"v{version}-p{protocol}-nodes{count}-cap{budget}-{'reverse' if reverse else 'forward'}"
                            if retry:
                                name += "-retry"
                            yield case(name, submitted, allowed, version=version, protocol=protocol, budget=budget,
                                       reassembled=int(not over), nodes=min(count, budget), peak=min(count, budget),
                                       resource_drops=len(submitted) - len(allowed), retries=retry)


def sharing_fixtures():
    for version in (4, 6):
        for protocol in (6, 17, 1 if version == 4 else 58):
            a, b = (datagram(version, protocol, identity) for identity in (2000, 2001))
            prefix = f"v{version}-p{protocol}"
            yield case(prefix + "-shared-cap", [a[0], b[0], a[1], b[1], a[0]], [0, 1, 3],
                       version=version, protocol=protocol, budget=2, reassembled=1, nodes=3, peak=2,
                       resource_drops=2, retries=True, kind="shared-nodes")
            yield case(prefix + "-first-admission-cap", [a[0], b[0], a[1], b[1]], [0],
                       version=version, protocol=protocol, budget=1, nodes=1, peak=1,
                       resource_drops=3, kind="first-admission")
            yield case(prefix + "-successful-release", a + b, list(range(4)),
                       version=version, protocol=protocol, budget=2, reassembled=2, nodes=4, peak=2,
                       kind="release-control", recovery=True)
            exhausted = datagram(version, protocol, 2002, (24, 48))
            yield case(prefix + "-failed-release", exhausted + b, [0, 1, 3, 4],
                       version=version, protocol=protocol, budget=2, reassembled=1, nodes=4, peak=2,
                       resource_drops=1, kind="release-after-rejection", recovery=True)
        # The live-node limit is shared by IP families within the packet thread.
        other = 6 if version == 4 else 4
        a, b = datagram(version, identification=2100), datagram(other, identification=2101)
        yield case(f"v{version}-cross-family-shared-cap", [a[0], b[0], a[1], b[1]], [0, 1, 3],
                   version=version, budget=2, reassembled=1, nodes=3, peak=2,
                   resource_drops=1, kind="cross-family-nodes")


def split_fixtures():
    # Identical overlapping bytes under an explicit IPv4 last-wins test policy
    # exercise duplicate-node allocation as well as ordinary insertion.
    payload = body(4, 17)
    frames = [packet(ipv4_fragment(payload[start:end], 17, start, more))
              for start, end, more in ((0, 48, True), (16, 24, True), (48, 72, False))]
    for budget, allowed in ((1, [0]), (2, [0]), (3, [0, 1]), (4, [0, 1, 2])):
        yield case(f"v4-contained-overlap-cap{budget}", frames, allowed, version=4, budget=budget,
                   reassembled=int(budget == 4), nodes=budget, peak=budget,
                   resource_drops=3 - len(allowed), kind="split-allocation", policy="last")


def eviction_fixtures():
    for version in (4, 6):
        for capacity, count in ((16, 40), (4096, 4200)):
            for controls in (False, True):
                victim = datagram(version)
                bad_tail = victim[1][:-1] + bytes([victim[1][-1] ^ 1])
                fills = [datagram(version, identification=5000 + index)[0] for index in range(count)]
                frames = [victim[0], bad_tail, *fills, bad_tail]
                allowed = [0, *range(2, capacity + 1)]
                times = [i * 100 for i in range(len(frames))]
                nodes, reassembled = capacity + 1, 1
                if controls:
                    def append(items, permit, start):
                        index = len(frames)
                        frames.extend(items)
                        times.extend(start + i * 100 for i in range(len(items)))
                        if permit:
                            allowed.extend(range(index, len(frames)))
                    append(datagram(6 if version == 4 else 4, identification=30000), True, 1000000)
                    nodes += 2
                    reassembled += 1
                    append([unfragmented(version)], True, 2000000)
                    append(datagram(version, identification=30001), False, 3000000)
                    # Traffic rejected without admission must not continually
                    # extend the loss-of-state window when its tracker is pruned.
                    retention = 121 if version == 4 else 61
                    append([datagram(version, identification=31000 + i)[0]
                            for i in range(capacity + 8)], False, (retention - 2) * 1000000)
                    append(datagram(version, identification=40000), True, (retention + 3) * 1000000)
                    nodes += 2
                    reassembled += 1
                yield case(f"v{version}-eviction-cap{capacity}" + ("-recovery" if controls else ""),
                           frames, allowed, version=version, capacity=capacity, nodes=nodes,
                           peak=capacity - 1, reassembled=reassembled, checksum_errors=1,
                           state_drops=len(frames) - len(allowed) - 1,
                           kind="state-loss", retries=True, recovery=controls, times=times,
                           bad_datagrams=[{"version": version, "identification": 1234}])
        # A recent admitted context survives the first eviction. Its inspection
        # continues while admission of a fresh fragmented datagram is blocked.
        victim = datagram(version, identification=2000)
        held = datagram(version, identification=2001)
        fills = [datagram(version, identification=6000 + i)[0] for i in range(14)]
        trigger = datagram(version, identification=6100)
        frames = [victim[0], *fills, held[0], trigger[0], held[1], trigger[1]]
        yield case(f"v{version}-existing-context-survives", frames, [*range(16), 17],
                   version=version, capacity=16, nodes=17, peak=16, reassembled=1,
                   state_drops=2, kind="existing-context")
        # Expiry after the retention floor is ordinary cleanup, not premature
        # state loss. A new flow and reuse of the old ID should both be allowed.
        stale = datagram(version, identification=2200)
        fresh = datagram(version, identification=2201)
        start = (124 if version == 4 else 64) * 1000000
        frames = [stale[0], *fresh, *stale]
        yield case(f"v{version}-natural-retention-expiry", frames, list(range(5)),
                   version=version, capacity=16, nodes=5, peak=3, reassembled=2,
                   kind="natural-expiry", recovery=True, times=[0, start, start + 100, start + 200, start + 300])


def fixtures():
    yield from node_fixtures()
    yield from sharing_fixtures()
    yield from split_fixtures()
    yield from eviction_fixtures()


def verify_wire_oracle(item):
    def valid_sum(data):
        return sum(int.from_bytes(data[i:i + 2].ljust(2, b"\0"), "big")
                   for i in range(0, len(data), 2)) % 65535 == 0
    bad = {(entry["version"], entry["identification"]) for entry in item["bad_datagrams"]}
    seen = set()
    for frame in item["frames"]:
        ip = frame[14:]
        version = ip[0] >> 4
        if version == 4:
            assert frame[12:14] == b"\x08\0" and ip[0] == 0x45 and valid_sum(ip[:20])
            assert len(ip) == int.from_bytes(ip[2:4], "big")
            field = int.from_bytes(ip[6:8], "big")
            offset, more, data = (field & 8191) * 8, bool(field & 8192), ip[20:]
            src, dst, proto = ip[12:16], ip[16:20], ip[9]
            identification = int.from_bytes(ip[4:6], "big")
        else:
            assert version == 6 and frame[12:14] == b"\x86\xdd" and ip[0] == 0x60
            assert len(ip) == 40 + int.from_bytes(ip[4:6], "big")
            src, dst = ip[8:24], ip[24:40]
            if ip[6] == 44:
                field = int.from_bytes(ip[42:44], "big")
                offset, more, data = field & 65528, bool(field & 1), ip[48:]
                proto, identification = ip[40], int.from_bytes(ip[44:48], "big")
            else:
                offset, more, data, proto, identification = 0, False, ip[40:], ip[6], -1
        corrupt = (version, identification) in bad
        payload = body(version, proto)
        if corrupt:
            payload = payload[:-1] + bytes([payload[-1] ^ 1])
            seen.add((version, identification))
        assert data and data == payload[offset:offset + len(data)]
        assert not more or len(data) % 8 == 0
        assert more or offset + len(data) == 72
        trailer = struct.pack("!BBH", 0, proto, 72) if version == 4 else struct.pack("!I3xB", 72, proto)
        assert valid_sum(payload if proto == 1 else src + dst + trailer + payload) != corrupt
    assert seen == bad
    assert item["times_us"] == sorted(item["times_us"]) and len(item["times_us"]) == len(item["frames"])


def config_key(item):
    return f"nodes{item['max_frags']}-flows{item['max_flows']}-{item['policy']}"


def run_case(snort, plugin, config, directory, item, environment):
    capture, output = (directory / (item["name"] + suffix) for suffix in (".pcap", "-forwarded.pcap"))
    write_capture(capture, item["frames"], item["times_us"])
    # Read every serialized timestamp independently, including >1,000 frames.
    wire, cursor, times = capture.read_bytes(), 24, []
    while cursor < len(wire):
        seconds, micros, captured, original = struct.unpack_from("<IIII", wire, cursor)
        assert micros < 1000000 and captured == original
        times.append((seconds - 1700000000) * 1000000 + micros - 750000)
        cursor += 16 + captured
    assert cursor == len(wire) and times == item["times_us"]
    command = [str(snort), "--plugin-path", str(plugin), "-c", str(config), "--daq", "pcap",
               "--daq-mode", "read-file", "--daq", "dump", "--daq-mode", "inline", "--daq-var", "file=" + str(output),
               "-Q", "-r", str(capture), "-s", "65535", "-A", "alert_json"]
    result = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=60)
    assert result.returncode == 0 and not result.stderr.strip(), item["name"] + result.stdout + result.stderr
    assert "dump:pcap DAQ configured to inline." in result.stdout
    section = re.search(r"(?m)^daq\n((?:[ \t].*\n)*)", result.stdout)
    assert section
    counts = {key: int(value) for key, value in re.findall(r"(?m)^\s+(\w+):\s+(\d+)\b", section[1])}
    assert counts.get("received") == counts.get("analyzed") == len(item["frames"])
    verdicts = {key: counts[key] for key in sorted(VERDICTS) if counts.get(key)}
    assert sum(verdicts.values()) == len(item["frames"])
    assert not any(verdicts.get(key) for key in ("ignore", "retry", "replace", "whitelist", "blacklist"))
    forwarded = pcap_packets(output.read_bytes())
    assert len(forwarded) == verdicts.get("allow", 0)
    expected = item["expected_frames"]
    desired = {"allow": len(expected)}
    if len(expected) != len(item["frames"]):
        desired["block"] = len(item["frames"]) - len(expected)
    counters = {key: module_count(result.stdout, "stream_ip", key) for key in COUNTERS}
    checksum_errors = sum(module_count(result.stdout, module, key) for module, key in
        (("tcp", "bad_tcp4_checksum"), ("tcp", "bad_tcp6_checksum"), ("udp", "bad_udp4_checksum"),
         ("udp", "bad_udp6_checksum"), ("icmp4", "bad_checksum"), ("icmp6", "bad_icmp6_checksum")))
    # Older baseline binaries lack pressure telemetry. Keep its absence explicit
    # while still testing allocation counts and actual forwarding in both builds.
    telemetry_present = counters["max_fragment_nodes"] > 0
    new_keys = {"max_fragment_nodes", "resource_drops", "state_lost_drops"}
    counter_pass = all(counters[key] == value for key, value in item["expected_counters"].items()
                       if key not in new_keys or telemetry_present) and checksum_errors == item["expected_checksum_errors"]
    if telemetry_present:
        counter_pass &= counters["max_fragment_nodes"] <= item["max_frags"]
        if item["kind"] == "natural-expiry":
            counter_pass &= counters["premature_state_losses"] == 0
        if item["kind"] in ("state-loss", "existing-context"):
            counter_pass &= counters["premature_state_losses"] > 0
    enforcement = verdicts == desired and forwarded == expected
    return {key: value for key, value in item.items() if key not in ("frames", "expected_frames")} | {
        "passed": enforcement and counter_pass, "enforcement_passed": enforcement, "counter_passed": counter_pass,
        "pressure_telemetry_present": telemetry_present, "daq_verdicts": verdicts, "expected_verdicts": desired,
        "counters": counters, "checksum_errors": checksum_errors,
        "events": [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")],
        "input_pcap_sha256": digest(capture.read_bytes()), "output_pcap_sha256": digest(output.read_bytes()),
        "input_packet_sha256": [digest(frame) for frame in item["frames"]],
        "expected_output_packet_sha256": [digest(frame) for frame in expected],
        "output_packet_sha256": [digest(frame) for frame in forwarded]}


def validate(snort, plugin):
    snort, plugin = snort.resolve(strict=True), plugin.resolve(strict=True)
    binary = digest(snort.read_bytes())
    sources = [Path(__file__), *[HERE / name for name in ("fragment_checksum_replay.py", "fragment_lifetime_replay.py",
               "checksum_replay.py", "generate_pcaps.py", "next_header_policy.py", "replay.py")]]
    hashes = {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in sources}
    profiles = load_validator().validate(snort, plugin)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("AX_")}
    configurations = {}
    with tempfile.TemporaryDirectory(prefix="ax-fragment-pressure-") as temporary:
        directory = Path(temporary)
        for name in CONFIG_FILES:
            (directory / name).write_bytes((HERE.parent / name).read_bytes())
        original = (HERE.parent / "protocol-ips.lua").read_text()
        cases = list(fixtures())
        assert len({item["name"] for item in cases}) == len(cases)
        for item in cases:
            verify_wire_oracle(item)
            key = config_key(item)
            if key in configurations:
                continue
            source = original
            for old, new in (("max_frags = 4096,", f"max_frags = {item['max_frags']},"),
                             ("max_flows = 4096,", f"max_flows = {item['max_flows']},"),
                             ("policy = 'linux', max_frags", f"policy = '{item['policy']}', max_frags")):
                assert source.count(old) == 1
                source = source.replace(old, new)
            if item["policy"] == "last":
                # A contained overlap counts twice in the pinned engine. This
                # special policy isolates both allocation paths from the
                # independently tested strict profile's overlap drop.
                assert source.count("max_overlaps = 1,") == 1
                source = source.replace("max_overlaps = 1,", "max_overlaps = 0,")
            (directory / (key + ".lua")).write_text(source)
            configurations[key] = digest(source.encode())
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda item: run_case(snort, plugin,
                directory / (config_key(item) + ".lua"), directory, item, environment), cases))
    assert binary == digest(snort.read_bytes())
    for relative, expected in hashes.items() | profiles["sha256"].items():
        assert digest((ROOT / relative).read_bytes()) == expected
    libraries = [plugin] if plugin.is_file() else sorted(set(plugin.rglob("*.so")) | set(plugin.rglob("*.dylib")))
    assert profiles["plugin_sha256"] == {path.name: digest(path.read_bytes()) for path in libraries}
    failures = [item["name"] for item in results if not item["passed"]]
    return {"status": "conformance_failure" if failures else "verified_expected_behavior",
            "scope": "Synthetic file-only inline DAQ; finite allocation and eviction policy, not live workload or endpoint assurance.",
            "snort_binary_sha256": binary, "configuration": profiles, "fixture_source_sha256": hashes,
            "special_configuration_sha256": configurations,
            "summary": {"cases": len(results), "passed": len(results) - len(failures), "failures": failures,
                "valid_controls": sum(item["valid_control"] for item in results),
                "retry_cases": sum(item["retries"] for item in results),
                "recovery_cases": sum(item["recovery"] for item in results)},
            "limitations": ["Capacity and quarantine are local admission policies, not RFC claims that these packets are malformed.",
                "Earlier forwarded fragments cannot be recalled; path delay and endpoint retention may exceed this local window.",
                "Native replays use one packet thread. Pure atomic tests separately cover concurrent deadline publication.",
                "No allocator failure, failover, process restart, flow migration or live overload behavior is established."],
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
