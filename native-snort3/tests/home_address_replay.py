#!/usr/bin/env python3
"""Audit Home Address wire semantics, checksums and fragment handling."""
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

from checksum_replay import module_count
from fragment_lifetime_replay import write_capture
from generate_pcaps import checksum, ip6, packet
from next_header_policy import CONFIG_FILES, VERDICTS, pcap_packets
from replay import load_validator
from type2_repair_replay import chain, route

if not __debug__:
    raise RuntimeError("validation requires assertions")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
CARE, HOME, DEST, FINAL = "2001:db8::1", "2001:db8::9", "2001:db8::2", "2001:db8::3"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def home(address=HOME, position=6, length=16, kind=60, type_=0xc9):
    options = b"\0" * (position - 2) + bytes([type_, length]) + ipaddress.IPv6Address(address).packed[:length]
    if length > 16:
        options += b"\0" * (length - 16)
    header = b"\0\0" + options
    header += b"\0" * (-len(header) % 8)
    return kind, bytes([0, len(header) // 8 - 1]) + header[2:]


def transport(protocol, source, destination, corrupt=False, reserved=False, echo_code=0, replacement=False):
    if protocol == 6:
        data = struct.pack("!HHIIBBHHH", 50000, 80, 100, 0, 82 if reserved else 80, 2, 65535, 0, 0) + b"t" * 52
        offset = 16
    elif protocol == 17:
        data = struct.pack("!HHHH", 50000, 9999, 72, 0) + (b"vvvv" if replacement else b"uuuu") + b"u" * 60
        offset = 6
    else:
        data = struct.pack("!BBHHH", 128, echo_code, 0, 1, 1) + (b"vvvv" if replacement else b"iiii") + b"i" * 60
        offset = 2
    pseudo = ipaddress.IPv6Address(source).packed + ipaddress.IPv6Address(destination).packed + struct.pack("!I3xB", len(data), protocol)
    value = checksum(pseudo + data)
    if protocol == 17:
        value = value or 65535
    if corrupt:
        value ^= 1
    return data[:offset] + struct.pack("!H", value) + data[offset + 2:]


def frame(headers, protocol, data):
    first, payload = chain(headers, protocol, data)
    return packet(ip6(payload, first, source=CARE, destination=DEST), 6)


def fixture(name, frames, expected, protocol, *, structural=False, checksum_valid=True,
            source=HOME, destination=DEST, fragments=False, retry=False, normalization="",
            reassembled=0, checksum_errors=None):
    return {"name": name, "frames": frames, "expected_frames": expected, "protocol": protocol,
            "structural_rejection": structural, "checksum_valid": checksum_valid,
            "checksum_source": source, "checksum_destination": destination,
            "fragmented": fragments, "retry": retry, "normalization": normalization,
            "expected_reassemblies": reassembled,
            "expected_checksum_errors": int(not checksum_valid) if checksum_errors is None else checksum_errors}


def fixtures():
    pad, hop = (60, bytes(8)), (0, bytes(8))
    ah = (51, bytes([0, 2]) + struct.pack("!HII", 0, 256, 1) + bytes(4))
    layouts = [("home", [home()], HOME, DEST), ("hop-home", [hop, home()], HOME, DEST),
               ("route-home", [route(), home()], HOME, FINAL),
               ("route-pad-home", [route(), pad, home()], HOME, FINAL),
               ("home-ah", [home(), ah], HOME, DEST),
               ("destination-home", [pad, home()], HOME, DEST),
               ("home-destination", [home(), pad], HOME, DEST),
               ("eight-last", [pad] * 7 + [home()], HOME, DEST),
               ("eight-first", [home()] + [pad] * 7, HOME, DEST),
               ("largest-destination", [home(position=2030)], HOME, DEST),
               ("second-aligned-position", [home(position=14)], HOME, DEST),
               ("ula-home", [home("fd00::9")], "fd00::9", DEST),
               ("ordinary", [], CARE, DEST), ("padding-only", [pad], CARE, DEST)]
    for protocol in (6, 17, 58):
        for name, headers, source, destination in layouts:
            variants = ("correct", "bit-error") if source == CARE else ("correct", "base", "bit-error")
            for variant in variants:
                data = transport(protocol, CARE if variant == "base" else source, destination, variant == "bit-error")
                wire = frame(headers, protocol, data)
                valid = variant == "correct"
                yield fixture(f"p{protocol}-{name}-{variant}", [wire], [wire] if valid else [], protocol,
                              checksum_valid=valid, source=source, destination=destination)
        invalid = [("length-zero", [home(length=0)]), ("length-short", [home(length=15)]),
                   ("length-long", [home(length=17)]), ("length-max", [home(length=255)]),
                   ("alignment-two", [home(position=2)]), ("alignment-seven", [home(position=7)]),
                   ("hop-placement", [home(kind=0)]), ("routing-after", [home(), route()]),
                   ("ah-before", [ah, home()]), ("duplicate-headers", [home(), home()])]
        duplicate = home()[1] + bytes(6) + home()[1][6:]
        assert len(duplicate) == 48
        invalid.append(("duplicate-one-header", [(60, bytes([0, 5]) + duplicate[2:])]))
        for label, address in (("unspecified", "::"), ("loopback", "::1"), ("link-local", "fe80::9"),
                               ("link-local-last-prefix", "febf::9"), ("multicast", "ff02::9")):
            invalid.append((label, [home(address)]))
        for name, headers in invalid:
            destination = FINAL if name == "routing-after" else DEST
            # A base-address checksum isolates the structural rule from the
            # former checksum-selection failure. Malformed HAO is not selected.
            wire = frame(headers, protocol, transport(protocol, CARE, destination))
            yield fixture(f"p{protocol}-malformed-{name}", [wire], [], protocol, structural=True,
                          source=CARE, destination=destination)
        # First fragment contains the complete HAO and transport header, but
        # placing HAO after Fragment violates its specific ordering requirement.
        data = home()[1]
        data = bytes([protocol]) + data[1:] + transport(protocol, CARE, DEST)
        frag = (44, bytes([0, 0, 0, 1]) + struct.pack("!I", 1234))
        wire = frame([frag], 60, data[:48])
        yield fixture(f"p{protocol}-malformed-after-first-fragment", [wire, wire], [], protocol,
                      structural=True, source=CARE, fragments=True, retry=True)
        # Opaque option data contains an HAO byte pattern but is not another TLV.
        embedded = home()[1][6:]
        opaque = bytes([0, 2, 0x1e, len(embedded)]) + embedded + bytes(2)
        assert len(opaque) == 24
        wire = frame([(60, opaque)], protocol, transport(protocol, CARE, DEST))
        yield fixture(f"p{protocol}-opaque-option-lookalike", [wire], [wire], protocol, source=CARE)
        for routed in (False, True):
            headers = ([route()] if routed else []) + [home()]
            destination = FINAL if routed else DEST
            for cuts in ((24,), (24, 48)):
                count = len(cuts) + 1
                orders = list(itertools.permutations(range(count)))
                for order in orders:
                    for variant in ("correct", "base", "bit-error"):
                        data = transport(protocol, CARE if variant == "base" else HOME, destination, variant == "bit-error")
                        offsets = [0, *cuts, 72]
                        wires = []
                        for start, end in zip(offsets, offsets[1:]):
                            frag = (44, bytes([0, 0]) + struct.pack("!HI", start | int(end < 72), 1234))
                            wires.append(frame(headers + [frag], protocol, data[start:end]))
                        wires = [wires[index] for index in order]
                        valid = variant == "correct"
                        yield fixture(f"p{protocol}-fragment-{'route-' if routed else ''}" + "".join(map(str, order)) + "-" + variant,
                                      wires, wires if valid else wires[:-1], protocol, checksum_valid=valid,
                                      destination=destination, fragments=True, reassembled=1)
                        if not valid and len(order) == 2:
                            yield fixture(f"p{protocol}-fragment-{'route-' if routed else ''}" + "".join(map(str, order)) + "-" + variant + "-retry",
                                          wires + [wires[-1], *wires], wires[:-1], protocol, checksum_valid=False,
                                          destination=destination, fragments=True, reassembled=1, retry=True)
    for routed in (False, True):
        headers = ([route()] if routed else []) + [home()]
        destination = FINAL if routed else DEST
        for valid in (False, True):
            wire = frame(headers, 6, transport(6, HOME if valid else CARE, destination, reserved=True))
            normalized = frame(headers, 6, transport(6, HOME, destination))
            yield fixture("normalize-tcp-" + ("route-" if routed else "") + ("correct" if valid else "base"),
                          [wire], [normalized] if valid else [], 6, checksum_valid=valid,
                          destination=destination, normalization="tcp")
            for protocol in (17, 58):
                wire = frame(headers, protocol, transport(protocol, HOME if valid else CARE, destination))
                normalized = frame(headers, protocol, transport(protocol, HOME, destination, replacement=True))
                yield fixture(f"rewrite-p{protocol}-" + ("route-" if routed else "") + ("correct" if valid else "base"),
                              [wire], [normalized] if valid else [], protocol, checksum_valid=valid,
                              destination=destination, normalization="rewrite")


def verify_oracle(item):
    def sum16(data):
        return sum(int.from_bytes(data[index:index + 2].ljust(2, b"\0"), "big")
                   for index in range(0, len(data), 2)) % 65535
    pieces, unfragmented, end = {}, None, None
    for wire in item["frames"]:
        ip = wire[14:]
        assert wire[12:14] == b"\x86\xdd" and ip[0] == 0x60
        assert int.from_bytes(ip[4:6], "big") + 40 == len(ip)
        next_, offset = ip[6], 40
        while next_ in (0, 43, 60, 51):
            size = (ip[offset + 1] + (2 if next_ == 51 else 1)) * (4 if next_ == 51 else 8)
            assert offset + size <= len(ip)
            next_, offset = ip[offset], offset + size
        if next_ == 44:
            field = int.from_bytes(ip[offset + 2:offset + 4], "big")
            data = ip[offset + 8:]
            fragment_offset, more = field & 65528, field & 1
            assert not more or len(data) % 8 == 0
            pieces[fragment_offset] = data
            if not more:
                end = fragment_offset + len(data)
        else:
            assert next_ == item["protocol"]
            unfragmented = ip[offset:]
    if item["structural_rejection"] and item["fragmented"]:
        return  # Incomplete first fragments intentionally have no transport checksum yet.
    if pieces:
        payload = b""
        for offset, data in sorted(pieces.items()):
            assert offset == len(payload)
            payload += data
        assert len(payload) == end == 72
    else:
        payload = unfragmented
    pseudo = ipaddress.IPv6Address(item["checksum_source"]).packed + ipaddress.IPv6Address(item["checksum_destination"]).packed
    pseudo += struct.pack("!I3xB", len(payload), item["protocol"])
    assert (sum16(pseudo + payload) == 0) == item["checksum_valid"]


def run_case(snort, plugin, config, directory, item, environment):
    capture = directory / (item["name"] + ".pcap")
    output = directory / (item["name"] + "-out.pcap")
    write_capture(capture, item["frames"], [i * 100 for i in range(len(item["frames"]))])
    command = [str(snort), "--plugin-path", str(plugin), "-c", str(config), "--daq", "pcap", "--daq-mode", "read-file",
               "--daq", "dump", "--daq-mode", "inline", "--daq-var", "file=" + str(output), "-Q", "-r", str(capture),
               "-s", "65535", "-A", "alert_json"]
    run = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=30)
    assert run.returncode == 0 and not run.stderr.strip(), run.stdout + run.stderr
    assert "dump:pcap DAQ configured to inline." in run.stdout
    section = re.search(r"(?m)^daq\n((?:[ \t].*\n)*)", run.stdout)
    assert section
    counts = {key: int(value) for key, value in re.findall(r"(?m)^\s+(\w+):\s+(\d+)\b", section[1])}
    assert counts.get("received") == counts.get("analyzed") == len(item["frames"])
    verdicts = {key: counts[key] for key in sorted(VERDICTS) if counts.get(key)}
    assert sum(verdicts.values()) == len(item["frames"])
    assert not any(verdicts.get(key) for key in ("ignore", "retry", "whitelist", "blacklist"))
    assert not verdicts.get("replace") or item["normalization"]
    output_packets = pcap_packets(output.read_bytes())
    assert len(output_packets) == verdicts.get("allow", 0) + verdicts.get("replace", 0)
    expected = item["expected_frames"]
    desired = {"replace" if item["normalization"] else "allow": len(expected)} if expected else {}
    if len(expected) < len(item["frames"]):
        desired["block"] = len(item["frames"]) - len(expected)
    module, counter = {6: ("tcp", "bad_tcp6_checksum"), 17: ("udp", "bad_udp6_checksum"),
                       58: ("icmp6", "bad_icmp6_checksum")}[item["protocol"]]
    counters = {"checksum_errors": module_count(run.stdout, module, counter),
                "checksum_bypassed": module_count(run.stdout, module, "checksum_bypassed"),
                "reassembled": module_count(run.stdout, "stream_ip", "reassembled")}
    events = [json.loads(line) for line in run.stdout.splitlines() if line.startswith("{")]
    structural = not item["structural_rejection"] or any(event["rule"].startswith("1:9201013:") and event["action"] == "drop" for event in events)
    enforcement = verdicts == desired and output_packets == expected
    counter_pass = counters["checksum_errors"] == item["expected_checksum_errors"] and counters["checksum_bypassed"] == 0 and counters["reassembled"] == item["expected_reassemblies"]
    return {key: value for key, value in item.items() if key not in ("frames", "expected_frames")} | {
        "passed": enforcement and counter_pass and structural, "enforcement_passed": enforcement,
        "counter_passed": counter_pass, "structural_guard_passed": structural, "counters": counters,
        "events": events, "daq_verdicts": verdicts, "expected_verdicts": desired,
        "input_pcap_sha256": digest(capture.read_bytes()), "output_pcap_sha256": digest(output.read_bytes()),
        "input_packet_sha256": [digest(data) for data in item["frames"]],
        "output_packet_sha256": [digest(data) for data in output_packets],
        "expected_output_packet_sha256": [digest(data) for data in expected]}


def validate(snort, plugin, case_generator=fixtures, additional_sources=()):
    snort, plugin = snort.resolve(strict=True), plugin.resolve(strict=True)
    binary = digest(snort.read_bytes())
    sources = [Path(__file__), *[HERE / name for name in ("checksum_replay.py", "fragment_lifetime_replay.py",
        "fragment_checksum_replay.py", "generate_pcaps.py", "next_header_policy.py", "replay.py", "type2_repair_replay.py")]]
    sources.extend(additional_sources)
    hashes = {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in sources}
    profiles = load_validator().validate(snort, plugin)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("AX_")}
    with tempfile.TemporaryDirectory(prefix="ax-home-address-replay-") as temporary:
        directory = Path(temporary)
        for name in CONFIG_FILES:
            (directory / name).write_bytes((HERE.parent / name).read_bytes())
        original = (HERE.parent / "protocol-ips.lua").read_text()
        assert original.count("ips = true, block = true, trim_win = true") == 1
        special = original.replace("ips = true, block = true, trim_win = true", "rsv = true, ips = true, block = true, trim_win = true")
        (directory / "normalize-tcp.lua").write_text(special)
        rewrite = original + '''
ips.rules = ips.rules .. [[
rewrite udp any any -> any any (msg:"AX Home Address checksum update fixture"; content:"uuuu"; replace:"vvvv"; sid:2999001; rev:1;)
rewrite icmp any any -> any any (msg:"AX Home Address checksum update fixture"; content:"iiii"; replace:"vvvv"; sid:2999002; rev:1;)
]]
ips.states = ips.states .. [[
rewrite ( gid:1; sid:2999001; enable:yes; )
rewrite ( gid:1; sid:2999002; enable:yes; )
]]
'''
        (directory / "normalize-rewrite.lua").write_text(rewrite)
        cases = list(case_generator())
        assert len({item["name"] for item in cases}) == len(cases)
        for item in cases:
            verify_oracle(item)
            if item["normalization"] and item["expected_frames"]:
                verify_oracle(item | {"frames": item["expected_frames"], "checksum_valid": True})
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda item: run_case(snort, plugin,
                directory / ("normalize-" + item["normalization"] + ".lua" if item["normalization"] else "protocol-ips.lua"), directory, item, environment), cases))
    assert binary == digest(snort.read_bytes())
    for relative, expected in hashes.items() | profiles["sha256"].items():
        assert digest((ROOT / relative).read_bytes()) == expected
    libraries = [plugin] if plugin.is_file() else sorted(set(plugin.rglob("*.so")) | set(plugin.rglob("*.dylib")))
    assert profiles["plugin_sha256"] == {path.name: digest(path.read_bytes()) for path in libraries}
    failures = [item["name"] for item in results if not item["passed"]]
    return {"status": "conformance_failure" if failures else "verified_expected_behavior",
            "scope": "Synthetic file-only inline DAQ; stateless option/checksum behavior, not binding ownership or deployment.",
            "snort_binary_sha256": binary, "configuration": profiles, "fixture_source_sha256": hashes,
            "normalizer_configuration_sha256": {"tcp": digest(special.encode()), "rewrite": digest(rewrite.encode())},
            "summary": {"cases": len(results), "passed": len(results) - len(failures), "failures": failures,
                "structural_cases": sum(item["structural_rejection"] for item in results),
                "fragment_cases": sum(item["fragmented"] for item in results),
                "retry_cases": sum(item["retry"] for item in results),
                "normalization_cases": sum(bool(item["normalization"]) for item in results)},
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
