#!/usr/bin/env python3
"""Audit native reassembly deadlines and quarantine with timestamped file DAQ."""
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

from checksum_replay import module_count
from fragment_checksum_replay import fragments, pseudo
from generate_pcaps import checksum
from next_header_policy import CONFIG_FILES, VERDICTS, pcap_packets
from replay import load_validator

if not __debug__:
    raise RuntimeError("validation requires assertions")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


def body(version, protocol):
    if protocol == 6:
        plain = struct.pack("!HHIIBBHHH", 50000, 80, 100, 0, 80, 2, 65535, 0, 0) + b"t" * 52
        offset = 16
    elif protocol == 17:
        plain = struct.pack("!HHHH", 50000, 9999, 72, 0) + b"u" * 64
        offset = 6
    else:
        plain = struct.pack("!BBHHH", 8 if version == 4 else 128, 0, 0, 1, 1) + b"i" * 64
        offset = 2
    covered = plain if protocol == 1 else pseudo(version, protocol, len(plain)) + plain
    value = checksum(covered)
    if protocol == 17:
        value = value or 65535
    return plain[:offset] + struct.pack("!H", value) + plain[offset + 2:]


def with_id(frame, version, value):
    frame = bytearray(frame)
    if version == 4:
        frame[18:20], frame[24:26] = struct.pack("!H", value), b"\0\0"
        frame[24:26] = struct.pack("!H", checksum(frame[14:34]))
    else:
        frame[58:62] = struct.pack("!I", value)
    return bytes(frame)


def fixtures():
    for version in (4, 6):
        for protocol in (6, 17, 1 if version == 4 else 58):
            payload = body(version, protocol)
            for configured in (1, 30, 60, 120):
                seconds = min(configured, 60) if version == 6 else configured
                limit = seconds * 1000000
                for layout, times in (("before", [0, limit - 1]), ("at", [0, limit]),
                                      ("after", [0, limit + 1]),
                                      ("trickle", [0, limit * 3 // 4, limit * 3 // 2]),
                                      ("long-trickle", [0, limit * 3 // 4, limit * 3 // 2, limit * 9 // 4])):
                    offsets = [0, 24] if len(times) == 2 else [0, 24, 40] if len(times) == 3 else [0, 24, 40, 56]
                    # Reversed and cyclic arrival orders make the first arriving
                    # fragment different from the offset-zero fragment.
                    orders = [tuple(range(len(times))), tuple(reversed(range(len(times))))]
                    if len(times) == 3:
                        orders = list(itertools.permutations(range(3)))
                    for order in orders:
                        frames = fragments(version, protocol, payload, offsets[1:], order)
                        rejection = next((i for i, value in enumerate(times) if value >= limit), None)
                        valid = rejection is None
                        name = f"v{version}-p{protocol}-budget{configured}-{layout}-" + "".join(map(str, order))
                        case = {"name": name, "version": version, "protocol": protocol,
                                "configured_seconds": configured, "deadline_seconds": seconds,
                                "layout": layout, "arrival_order": list(order), "offsets": offsets,
                                "valid_control": valid, "first_rejection": rejection,
                                "frames": frames, "times_us": times, "original_fragment_count": len(frames),
                                "expected_frames": frames if valid else frames[:rejection],
                                "expected_reassemblies": int(valid), "expected_timeouts": int(not valid),
                                "retries": False, "recovery": ""}
                        yield case
                        if not valid and layout == "at" and configured == 30:
                            # Retain rejection across the old 30-second idle
                            # timeout, then retry both individual and whole data.
                            extra = [frames[-1], *frames]
                            retry_times = [limit + 31000000 + i * 1000 for i in range(len(extra))]
                            retried = case | {"name": name + "-idle-retry", "frames": frames + extra,
                                              "times_us": times + retry_times, "retries": True}
                            yield retried
                            for recovery in ("fresh-id", "after-retention"):
                                control = fragments(version, protocol, payload, [24], (0, 1))
                                if recovery == "fresh-id":
                                    control = [with_id(frame, version, 4321) for frame in control]
                                    start = retry_times[-1] + 1000
                                else:
                                    start = retry_times[-1] + (max(configured, 60 if version == 6 else 120) + 3) * 1000000
                                yield retried | {"name": retried["name"] + "-" + recovery,
                                                 "frames": retried["frames"] + control,
                                                 "times_us": retried["times_us"] + [start, start + 1000],
                                                 "expected_frames": retried["expected_frames"] + control,
                                                 "expected_reassemblies": 1, "recovery": recovery}


def write_capture(path, frames, times):
    assert len(frames) == len(times)
    capture = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    # Fractional origin tests that deadline comparisons retain microseconds.
    for frame, time in zip(frames, times):
        seconds, micros = divmod(time + 750000, 1000000)
        capture += struct.pack("<IIII", 1700000000 + seconds, micros, len(frame), len(frame)) + frame
    path.write_bytes(capture)


def verify_wire_oracle(case):
    def valid_sum(data):
        return sum(int.from_bytes(data[i:i + 2].ljust(2, b"\0"), "big")
                   for i in range(0, len(data), 2)) % 65535 == 0
    pieces, terminal = {}, None
    for frame in case["frames"][:case["original_fragment_count"]]:
        ip = frame[14:]
        if case["version"] == 4:
            assert frame[12:14] == b"\x08\0" and ip[0] == 0x45 and valid_sum(ip[:20])
            assert len(ip) == int.from_bytes(ip[2:4], "big")
            field = int.from_bytes(ip[6:8], "big")
            offset, more, data = (field & 8191) * 8, bool(field & 8192), ip[20:]
            src, dst, proto = ip[12:16], ip[16:20], ip[9]
        else:
            assert frame[12:14] == b"\x86\xdd" and ip[0] == 0x60 and ip[6] == 44
            assert len(ip) == 40 + int.from_bytes(ip[4:6], "big")
            field = int.from_bytes(ip[42:44], "big")
            offset, more, data = field & 65528, bool(field & 1), ip[48:]
            src, dst, proto = ip[8:24], ip[24:40], ip[40]
        assert proto == case["protocol"] and offset not in pieces
        assert not more or len(data) % 8 == 0
        pieces[offset] = data
        if not more:
            assert terminal is None
            terminal = offset + len(data)
    data = b""
    for offset, part in sorted(pieces.items()):
        assert offset == len(data)
        data += part
    assert len(data) == terminal == 72
    trailer = struct.pack("!BBH", 0, proto, len(data)) if case["version"] == 4 else struct.pack("!I3xB", len(data), proto)
    assert valid_sum(data if proto == 1 else src + dst + trailer + data)
    absolute = [1700000000000000 + 750000 + time for time in case["times_us"]]
    assert absolute == sorted(absolute)
    deadline = absolute[0] + case["deadline_seconds"] * 1000000
    rejected = next((i for i, value in enumerate(absolute[:case["original_fragment_count"]]) if value >= deadline), None)
    assert rejected == case["first_rejection"]


def run_case(snort, plugin, config, directory, case, environment):
    capture, output = (directory / (case["name"] + suffix) for suffix in (".pcap", "-forwarded.pcap"))
    write_capture(capture, case["frames"], case["times_us"])
    command = [str(snort), "--plugin-path", str(plugin), "-c", str(config), "--daq", "pcap",
               "--daq-mode", "read-file", "--daq", "dump", "--daq-mode", "inline", "--daq-var", "file=" + str(output),
               "-Q", "-r", str(capture), "-s", "65535", "-A", "alert_json"]
    result = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=30)
    assert result.returncode == 0 and not result.stderr.strip(), result.stdout + result.stderr
    assert "dump:pcap DAQ configured to inline." in result.stdout
    section = re.search(r"(?m)^daq\n((?:[ \t].*\n)*)", result.stdout)
    assert section
    counts = {key: int(value) for key, value in re.findall(r"(?m)^\s+(\w+):\s+(\d+)\b", section[1])}
    assert counts.get("received") == counts.get("analyzed") == len(case["frames"])
    verdicts = {key: counts[key] for key in sorted(VERDICTS) if counts.get(key)}
    assert sum(verdicts.values()) == len(case["frames"])
    assert not any(verdicts.get(key) for key in ("ignore", "retry", "replace", "whitelist", "blacklist"))
    forwarded = pcap_packets(output.read_bytes())
    assert len(forwarded) == verdicts.get("allow", 0)
    expected = case["expected_frames"]
    desired = {"allow": len(expected)}
    if len(expected) < len(case["frames"]):
        desired["block"] = len(case["frames"]) - len(expected)
    counters = {key: module_count(result.stdout, "stream_ip", key) for key in
                ("reassembled", "frag_timeouts", "drops", "discards", "timeouts")}
    protocol, version = case["protocol"], case["version"]
    module, counter = ("tcp", f"bad_tcp{version}_checksum") if protocol == 6 else ("udp", f"bad_udp{version}_checksum") if protocol == 17 else ("icmp4", "bad_checksum") if version == 4 else ("icmp6", "bad_icmp6_checksum")
    checksum_errors = module_count(result.stdout, module, counter)
    enforcement = verdicts == desired and forwarded == expected
    counter_pass = (counters["reassembled"] == case["expected_reassemblies"] and
                    counters["frag_timeouts"] == case["expected_timeouts"] and
                    counters["drops"] == desired.get("block", 0) and checksum_errors == 0)
    return {key: value for key, value in case.items() if key not in ("frames", "expected_frames")} | {
        "passed": enforcement and counter_pass, "enforcement_passed": enforcement, "counter_passed": counter_pass,
        "daq_verdicts": verdicts, "expected_verdicts": desired, "counters": counters,
        "checksum_errors": checksum_errors, "events": [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")],
        "input_pcap_sha256": digest(capture.read_bytes()), "output_pcap_sha256": digest(output.read_bytes()),
        "input_packet_sha256": [digest(frame) for frame in case["frames"]],
        "expected_output_packet_sha256": [digest(frame) for frame in expected],
        "output_packet_sha256": [digest(frame) for frame in forwarded]}


def validate(snort, plugin):
    snort, plugin = snort.resolve(strict=True), plugin.resolve(strict=True)
    binary = digest(snort.read_bytes())
    sources = [Path(__file__), HERE / "fragment_checksum_replay.py", HERE / "checksum_replay.py",
               HERE / "generate_pcaps.py", HERE / "next_header_policy.py", HERE / "replay.py"]
    hashes = {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in sources}
    profiles = load_validator().validate(snort, plugin)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("AX_")}
    configurations = {}
    with tempfile.TemporaryDirectory(prefix="ax-fragment-lifetime-") as temporary:
        directory = Path(temporary)
        for name in CONFIG_FILES:
            (directory / name).write_bytes((HERE.parent / name).read_bytes())
        original = (HERE.parent / "protocol-ips.lua").read_text()
        assert original.count("min_frag_length = 0, min_ttl = 1, session_timeout = 30,") == 1
        for timeout in (1, 30, 60, 120):
            config = directory / f"timeout-{timeout}.lua"
            config.write_text(original.replace("min_frag_length = 0, min_ttl = 1, session_timeout = 30,",
                                              f"min_frag_length = 0, min_ttl = 1, session_timeout = {timeout},"))
            configurations[str(timeout)] = digest(config.read_bytes())
        cases = list(fixtures())
        assert len({case["name"] for case in cases}) == len(cases)
        for case in cases:
            verify_wire_oracle(case)
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda case: run_case(snort, plugin,
                                directory / f"timeout-{case['configured_seconds']}.lua", directory, case, environment), cases))
    assert binary == digest(snort.read_bytes())
    for relative, expected in hashes.items() | profiles["sha256"].items():
        assert digest((ROOT / relative).read_bytes()) == expected
    libraries = [plugin] if plugin.is_file() else sorted(set(plugin.rglob("*.so")) | set(plugin.rglob("*.dylib")))
    assert profiles["plugin_sha256"] == {path.name: digest(path.read_bytes()) for path in libraries}
    failures = [case["name"] for case in results if not case["passed"]]
    return {"status": "conformance_failure" if failures else "verified_expected_behavior",
            "scope": "Timestamped synthetic file-only inline DAQ, not wall-clock scheduling, endpoints or deployment.",
            "snort_binary_sha256": binary, "configuration": profiles, "fixture_source_sha256": hashes,
            "special_configuration_sha256": configurations,
            "summary": {"cases": len(results), "passed": len(results) - len(failures), "failures": failures,
                        "valid_controls": sum(case["valid_control"] for case in results),
                        "retry_cases": sum(case["retries"] for case in results),
                        "recovery_cases": sum(bool(case["recovery"]) for case in results)},
            "limitations": ["Existing fragments cannot be recalled; local quarantine depends on tracker retention.",
                            "Cache pressure, failover, path delay and endpoint-specific longer timers remain separate requirements.",
                            "Deadline is enforced on packet processing; eager cleanup of idle payload memory is not established.",
                            "Packet timestamps represent trusted DAQ time; live clock behavior and timer scheduling are not tested."],
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
