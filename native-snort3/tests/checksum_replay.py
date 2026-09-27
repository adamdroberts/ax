#!/usr/bin/env python3
"""Check checksum enforcement with offline inline DAQ; never open an interface.

The pcap DAQ reads one synthetic frame and the dump DAQ writes accepted frames
into a temporary capture. Unlike inline simulation, this exercises checksum
blocking and checks both the real DAQ verdict and the emitted packet count.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import struct
import tempfile

from generate_pcaps import checksum, icmp4, ip4, ip6, packet, tcp, udp
from replay import load_validator

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent


def pseudoheader(version, protocol, length):
    if version == 4:
        source, destination = "192.0.2.10", "198.51.100.20"
        trailer = struct.pack("!BBH", 0, protocol, length)
    else:
        source, destination = "2001:db8::1", "2001:db8::2"
        trailer = struct.pack("!I3xB", length, protocol)
    return (ipaddress.ip_address(source).packed
            + ipaddress.ip_address(destination).packed + trailer)


def with_checksum(body, offset, pseudo=b"", udp_checksum=False):
    body = body[:offset] + b"\0\0" + body[offset + 2:]
    value = checksum(pseudo + body)
    if udp_checksum and value == 0:
        value = 0xffff
    return body[:offset] + struct.pack("!H", value) + body[offset + 2:]


def checksum_cases():
    """Each corrupt pair differs in exactly one checksum bit, not payload."""
    bodies = [("ipv4-header", 4, 17, udp(), 10, "ipv4", "bad_checksum"),
              ("tcpv4", 4, 6, tcp(), 20 + 16, "tcp", "bad_tcp4_checksum"),
              ("icmpv4", 4, 1, icmp4(), 20 + 2, "icmp4", "bad_checksum")]
    for version in (4, 6):
        body = udp()
        body = with_checksum(body, 6, pseudoheader(version, 17, len(body)), True)
        bodies.append((f"udpv{version}", version, 17, body,
                       (20 if version == 4 else 40) + 6,
                       "udp", f"bad_udp{version}_checksum"))
    tcp6 = with_checksum(tcp(), 16, pseudoheader(6, 6, len(tcp())))
    bodies.append(("tcpv6", 6, 6, tcp6, 40 + 16, "tcp", "bad_tcp6_checksum"))
    icmp6 = struct.pack("!BBHHH", 128, 0, 0, 1, 1) + b"hello"
    icmp6 = with_checksum(icmp6, 2, pseudoheader(6, 58, len(icmp6)))
    bodies.append(("icmpv6", 6, 58, icmp6, 40 + 2, "icmp6", "bad_icmp6_checksum"))
    for name, version, protocol, body, offset, module, counter in bodies:
        network = ip4(body, protocol) if version == 4 else ip6(body, protocol)
        frame = packet(network, version)
        if name == "ipv4-header":
            covered = network[:20]
        else:
            covered = body if protocol == 1 else pseudoheader(version, protocol, len(body)) + body
        if checksum(covered) != 0:
            raise RuntimeError("Generator produced an invalid baseline checksum: " + name)
        corrupt = bytearray(frame)
        corrupt[14 + offset] ^= 1
        difference = sum((first ^ second).bit_count() for first, second in zip(frame, corrupt))
        if difference != 1:
            raise RuntimeError("Checksum pair must differ in exactly one bit")
        for invalid, data in ((False, frame), (True, bytes(corrupt))):
            yield {"name": name + ("-one-bit-error" if invalid else "-correct"),
                   "pair": name, "frame": data, "expected_verdict": "block" if invalid else "allow",
                   "checksum_counter": [module, counter],
                   "expected_checksum_errors": int(invalid),
                   "mutation": "one checksum bit" if invalid else None}
    for version in (4, 6):
        network = ip4(udp()) if version == 4 else ip6(udp(ipv6=True, zero=True))
        yield {"name": f"udpv{version}-zero-checksum", "pair": None,
               "frame": packet(network, version),
               "expected_verdict": "allow" if version == 4 else "block",
               "checksum_counter": ["udp", f"bad_udp{version}_checksum"],
               "expected_checksum_errors": int(version == 6), "mutation": "checksum omitted (zero)"}


def write_pcap(path, frames):
    capture = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for index, frame in enumerate(frames):
        capture += struct.pack("<IIII", 1700000000, index * 1000, len(frame), len(frame)) + frame
    path.write_bytes(capture)


def module_count(stdout, module, key):
    # Statistics sections are isolated by dashed separator lines. Never accept
    # a same-named counter from a different decoder or from an alert message.
    matches = re.findall(r"(?m)^" + re.escape(module) + r"\n(.*?)(?=^[-]{10,}\s*$)",
                         stdout, flags=re.DOTALL)
    if len(matches) > 1:
        raise RuntimeError("Ambiguous statistics section: " + module)
    if not matches:
        return 0
    values = re.findall(r"(?m)^\s+" + re.escape(key) + r":\s+(\d+)\s*$", matches[0])
    if len(values) > 1:
        raise RuntimeError("Ambiguous counter: " + module + "." + key)
    return int(values[0]) if values else 0


def replay_checksums(snort, plugin_path):
    # The shared native runner validates dump:pcap mode and parses actual DAQ
    # verdicts and both emitted PCAP record counts and record integrity.
    from next_header_policy import run_capture
    profiles = load_validator().validate(snort, plugin_path)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("AX_")}
    engine_hash = hashlib.sha256(snort.read_bytes()).hexdigest()
    results = []
    with tempfile.TemporaryDirectory(prefix="ax-snort-checksums-") as temporary:
        directory = Path(temporary)
        for case in checksum_cases():
            frame = case["frame"]
            source = directory / (case["name"] + ".pcap")
            output = directory / (case["name"] + "-accepted.pcap")
            write_pcap(source, [frame])
            observed = run_capture(snort, plugin_path, HERE.parent / "protocol-ips.lua",
                                   source, output, environment, include_stdout=True)
            error_count = module_count(observed["stdout"], *case["checksum_counter"])
            counters = observed["daq_counters"]
            accepted = case["expected_verdict"] == "allow"
            passed = (counters["received"] == counters["analyzed"] == 1
                      and counters.get("allow", 0) == int(accepted)
                      and counters.get("block", 0) == int(not accepted)
                      and observed["output_packets"] == int(accepted)
                      and observed["output_packet_sha256"] == ([hashlib.sha256(frame).hexdigest()] if accepted else [])
                      and error_count == case["expected_checksum_errors"])
            results.append({key: value for key, value in case.items() if key != "frame"} | {
                "input_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "input_packets": 1, "daq": counters,
                "output_packets": observed["output_packets"],
                "observed_checksum_errors": error_count,
                "output_pcap_sha256": observed["output_pcap_sha256"],
                "output_packet_sha256": observed["output_packet_sha256"],
                "alerts": observed["events"], "passed": passed})
    for relative, expected in profiles["sha256"].items():
        if hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() != expected:
            raise RuntimeError("Configuration changed during checksum validation: " + relative)
    plugin_files = [plugin_path] if plugin_path.is_file() else sorted(
        set(plugin_path.rglob("*.so")) | set(plugin_path.rglob("*.dylib")))
    if profiles["plugin_sha256"] != {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in plugin_files}:
        raise RuntimeError("Plugin changed during checksum validation")
    if hashlib.sha256(snort.read_bytes()).hexdigest() != engine_hash:
        raise RuntimeError("Snort binary changed during checksum validation")
    files = [HERE / name for name in ("checksum_replay.py", "generate_pcaps.py", "replay.py", "next_header_policy.py")]
    failures = [case["name"] for case in results if not case["passed"]]
    return {"snort_version": profiles["snort_version"], "snort_binary_sha256": engine_hash,
            "source_commit": profiles["source_commit"],
            "scope": "Offline inline dump:pcap DAQ. Actual engine DAQ allow/block verdicts and emitted packet counts are checked; no network interfaces or deployed enforcement are tested.",
            "configuration": profiles,
            "fixture_source_sha256": {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                                      for path in files},
            "summary": {"cases": len(results), "passed": len(results) - len(failures),
                        "allowed": sum(case["expected_verdict"] == "allow" for case in results),
                        "blocked": sum(case["expected_verdict"] == "block" for case in results),
                        "failures": failures}, "cases": results,
            "limitations": ["The fixtures cover seven checksum classes with correct/one-bit-corrupt pairs and the IPv4/IPv6 UDP-zero distinction; they do not exhaust packet layouts or fragmentation.",
                            "Checksum correctness is error detection, not authentication or protection against checksum-preserving malicious content.",
                            "File DAQ supplies no hardware checksum-offload metadata; live-interface offload behavior and deployment routing remain unverified.",
                            "IPv6 UDP zero is rejected for this ordinary datagram profile; specialized zero-checksum tunnel exceptions are not enabled."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snort", type=Path, required=True)
    parser.add_argument("--plugin-path", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = replay_checksums(args.snort.resolve(strict=True), args.plugin_path.resolve(strict=True))
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"summary": report["summary"], "limitations": report["limitations"]}, indent=2))
    if report["summary"]["failures"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
