#!/usr/bin/env python3
"""Check DNS endpoint policy using native inline file DAQ verdicts and bytes.

These are synthetic local captures, not traffic sent to a network interface.
"""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
NATIVE = HERE.parent
ROOT = NATIVE.parent
sys.path.insert(0, str(NATIVE))
import generate_dns_perimeter as generator
import validate_dns_perimeter as profiles
from next_header_policy import checksum, pcap_packets, VERDICTS

ADDRESSES = {4: ("10.20.0.2", "10.30.0.53", "10.30.0.10", "198.51.100.9"),
             6: ("fd00:20::2", "fd00:30::53", "fd00:30::10", "2001:db8::9")}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pseudo(source, destination, protocol, length):
    src, dst = map(ipaddress.ip_address, (source, destination))
    assert src.version == dst.version
    tail = struct.pack("!BBH", 0, protocol, length) if src.version == 4 else struct.pack("!I3xB", length, protocol)
    return src.packed + dst.packed + tail


def transport(source, destination, protocol, sport=45000, dport=53, data=None, flags=2, seq=100, ack=0):
    if data is None:
        data = dns_query() if protocol == 17 else b""
    if protocol == 17:
        raw, offset = struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data, 6
    elif protocol == 6:
        raw, offset = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 32768, 0, 0) + data, 16
    else:
        assert protocol in (1, 58)
        raw, offset = struct.pack("!BBHHH", 8 if protocol == 1 else 128, 0, 0, 1, 1) + b"echo", 2
    value = checksum((b"" if protocol == 1 else pseudo(source, destination, protocol, len(raw))) + raw)
    if protocol == 17:
        value = value or 0xffff
    return raw[:offset] + struct.pack("!H", value) + raw[offset + 2:]


def dns_query():
    return bytes.fromhex("123401000001000000000000") + b"\x03api\x07company\x07example\0\0\1\0\1"


def frame(source, destination, protocol, body, *, options=b"", extensions=b"", first=None,
          fragment=None):
    src, dst = map(ipaddress.ip_address, (source, destination))
    if src.version == 4:
        assert len(options) % 4 == 0
        frag = 0 if fragment is None else fragment[0] // 8 | (0x2000 if fragment[1] else 0)
        header = struct.pack("!BBHHHBBH4s4s", 0x45 + len(options) // 4, 0, 20 + len(options) + len(body),
                             1234, frag, 64, protocol, 0, src.packed, dst.packed) + options
        header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
        return bytes.fromhex("0200000000020200000000010800") + header + body
    assert not options
    if fragment is not None:
        frag = struct.pack("!BBHI", protocol, 0, fragment[0] | int(fragment[1]), 0x12345678)
        body, protocol = frag + body, 44
    payload = extensions + body
    header = struct.pack("!IHBB16s16s", 6 << 28, len(payload), protocol if first is None else first,
                         64, src.packed, dst.packed)
    return bytes.fromhex("02000000000202000000000186dd") + header + payload


def case(name, frames, allowed, sid=None, kind="single", **extra):
    return {"name": name, "frames": frames, "allowed": allowed, "expected_sid": sid, "kind": kind, **extra}


def fixtures():
    for version, (agent, dns, broker, outside) in ADDRESSES.items():
        for destination, role in ((dns, "dns"), (broker, "broker"), (outside, "outside")):
            for protocol in (6, 17):
                for port in (53, 443, 853, 5353, 784, 8853, 8443, 5443, 12345):
                    allowed = (role == "dns" and port == 53) or (role == "broker" and protocol == 6 and port == 443)
                    sid = (9202001 if role == "outside" else 9202002 if role == "broker" and protocol != 6 else
                           9202004 if role == "broker" else 9202005 if protocol == 6 else 9202006)
                    payload = transport(agent, destination, protocol, dport=port)
                    yield case(f"v{version}-out-{role}-p{protocol}-port{port}", [frame(agent, destination, protocol, payload)],
                               allowed, None if allowed else sid)
            icmp = 1 if version == 4 else 58
            yield case(f"v{version}-out-{role}-icmp", [frame(agent, destination, icmp, transport(agent, destination, icmp))],
                       False, {"outside": 9202001, "broker": 9202002, "dns": 9202003}[role])
        for source, role in ((dns, "dns"), (broker, "broker"), (outside, "outside")):
            for protocol in (6, 17):
                for port in (53, 443, 853):
                    allowed = (role == "dns" and port == 53) or (role == "broker" and protocol == 6 and port == 443)
                    sid = (9202010 if protocol == 17 and role != "dns" else 9202011 if protocol == 17 else
                           {"dns": 9202009, "broker": 9202008, "outside": 9202007}[role])
                    yield case(f"v{version}-in-{role}-p{protocol}-port{port}",
                               [frame(source, agent, protocol, transport(source, agent, protocol, sport=port, dport=45000))],
                               allowed, None if allowed else sid)
        # The perimeter must not inadvertently capture the separate inspected HTTP hop.
        source, destination = ("10.40.0.2", "10.50.0.10") if version == 4 else ("fd00:40::2", "fd00:50::10")
        yield case(f"v{version}-unrelated-scope", [frame(source, destination, 17, transport(source, destination, 17))], True)
        # TCP establishment, split DNS length prefix, pipelining and response reuse.
        frames = [frame(agent, dns, 6, transport(agent, dns, 6)),
                  frame(dns, agent, 6, transport(dns, agent, 6, sport=53, dport=45000, flags=0x12, seq=500, ack=101)),
                  frame(agent, dns, 6, transport(agent, dns, 6, flags=0x10, seq=101, ack=501))]
        payload = struct.pack("!H", len(dns_query())) + dns_query()
        seq = 101
        for chunk in (payload[:1], payload[1:], payload * 2):
            frames.append(frame(agent, dns, 6, transport(agent, dns, 6, data=chunk, flags=0x18, seq=seq, ack=501)))
            seq += len(chunk)
        frames.append(frame(dns, agent, 6, transport(dns, agent, 6, sport=53, dport=45000, data=payload,
                                                   flags=0x18, seq=501, ack=seq)))
        yield case(f"v{version}-dns-tcp-split-reuse", frames, True, kind="stream")
        # Ports become visible after reassembly, including reverse arrival order.
        for protocol in (6, 17):
            for destination, role, goodport in ((dns, "dns", 53), (broker, "broker", 443)):
                for bad in (False, True):
                    port = 853 if bad else goodport
                    allowed = not bad and (role == "dns" or protocol == 6)
                    sid = 9202002 if role == "broker" and protocol == 17 else 9202004 if role == "broker" else (
                        9202005 if protocol == 6 else 9202006)
                    payload = transport(agent, destination, protocol, dport=port, data=dns_query() * 2)
                    fragments = [frame(agent, destination, protocol, payload[:24], fragment=(0, True)),
                                 frame(agent, destination, protocol, payload[24:], fragment=(24, False))]
                    for reverse in (False, True):
                        yield case(f"v{version}-fragment-{role}-p{protocol}-bad{int(bad)}-reverse{int(reverse)}",
                                   list(reversed(fragments)) if reverse else fragments, allowed, None if allowed else sid,
                                   kind="fragments")
        # A first-hop trusted address cannot relay source-routed traffic elsewhere.
        for protocol in (6, 17):
            for active in (False, True):
                final = outside if active else dns
                payload = transport(agent, final, protocol, data=dns_query() * 2)
                if version == 4:
                    for option, sid in ((131, 9202014), (137, 9202015)):
                        options = bytes([option, 7, 4 if active else 8]) + ipaddress.ip_address(outside).packed + b"\0"
                        yield case(f"v4-route{option}-p{protocol}-active{int(active)}",
                                   [frame(agent, dns, protocol, payload, options=options)], False, sid)
                        parts = [frame(agent, dns, protocol, payload[:24], options=options, fragment=(0, True)),
                                 frame(agent, dns, protocol, payload[24:], options=options, fragment=(24, False))]
                        for reverse in (False, True):
                            yield case(f"v4-route{option}-fragment-p{protocol}-active{int(active)}-reverse{int(reverse)}",
                                       list(reversed(parts)) if reverse else parts, False, sid, kind="fragments")
                else:
                    routing = bytes([protocol, 2, 2, int(active)]) + b"\0" * 4 + ipaddress.ip_address(outside).packed
                    yield case(f"v6-route2-p{protocol}-active{int(active)}",
                               [frame(agent, dns, protocol, payload, extensions=routing, first=43)], False, 9202013)
                    routing = bytes([44]) + routing[1:]
                    parts = [frame(agent, dns, protocol, payload[:24], extensions=routing, first=43, fragment=(0, True)),
                             frame(agent, dns, protocol, payload[24:], extensions=routing, first=43, fragment=(24, False))]
                    for reverse in (False, True):
                        yield case(f"v6-route2-fragment-p{protocol}-active{int(active)}-reverse{int(reverse)}",
                                   list(reversed(parts)) if reverse else parts, False, 9202013, kind="fragments")
        if version == 6:
            for first in (0, 60):
                for protocol in (6, 17):
                    extension = bytes([protocol, 0]) + b"\0" * 6
                    yield case(f"v6-option{first}-p{protocol}",
                               [frame(agent, dns, protocol, transport(agent, dns, protocol), extensions=extension, first=first)], True)
            # Unknown routing types with Segments Left=0 are not malformed, but are locally disallowed.
            route = bytes([17, 0, 253, 0]) + b"\0" * 4
            yield case("v6-route-unknown-inactive", [frame(agent, dns, 17, transport(agent, dns, 17), extensions=route, first=43)],
                       False, 9202013)
        # The optional HTTP hop keeps its own scope and enforcement with DNS enabled.
        source, destination = ("10.40.0.2", "10.50.0.10") if version == 4 else ("fd00:40::2", "fd00:50::10")
        for bad in (False, True):
            body = bytes.fromhex("1603030001ff") if bad else b"GET / HTTP/1.1\r\nHost: company.example\r\n\r\n"
            frames = [frame(source, destination, 6, transport(source, destination, 6, dport=8080)),
                      frame(destination, source, 6, transport(destination, source, 6, sport=8080, dport=45000, flags=0x12, seq=500, ack=101)),
                      frame(source, destination, 6, transport(source, destination, 6, dport=8080, flags=0x10, seq=101, ack=501)),
                      frame(source, destination, 6, transport(source, destination, 6, dport=8080, data=body, flags=0x18, seq=101, ack=501))]
            yield case(f"v{version}-http-overlay-tls{int(bad)}", frames, not bad, 9120003 if bad else None,
                       kind="stream_deny" if bad else "stream", http=True)


def write_capture(path, frames):
    data = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for i, packet in enumerate(frames):
        data += struct.pack("<IIII", 1 + i // 1000, i % 1000 * 1000, len(packet), len(packet)) + packet
    path.write_bytes(data)


def run_case(snort, plugin, config, directory, item, env):
    capture, output = (directory / (item["name"] + suffix) for suffix in (".pcap", "-forwarded.pcap"))
    frames = item["frames"]
    write_capture(capture, frames)
    command = [str(snort), "--plugin-path", str(plugin), "-c", str(config), "--daq", "pcap", "--daq-mode", "read-file",
               "--daq", "dump", "--daq-mode", "inline", "--daq-var", "file=" + str(output), "-Q", "-r", str(capture),
               "-s", "65535", "-A", "alert_json"]
    run = subprocess.run(command, env=env, text=True, capture_output=True, timeout=30)
    result = {key: value for key, value in item.items() if key != "frames"}
    result.update(input_pcap_sha256=digest(capture.read_bytes()), input_packet_sha256=[digest(wire) for wire in frames])
    if run.returncode or run.stderr.strip():
        return result | {"passed": False, "diagnostic_tail": (run.stdout + run.stderr)[-4000:]}
    assert "dump:pcap DAQ configured to inline." in run.stdout
    section = re.search(r"(?m)^daq\n((?:[ \t].*\n)*)", run.stdout)
    assert section
    counts = {key: int(value) for key, value in re.findall(r"(?m)^\s+(\w+):\s+(\d+)\b", section[1])}
    assert counts.get("received") == counts.get("analyzed") == len(frames)
    verdicts = {key: counts[key] for key in sorted(VERDICTS) if counts.get(key)}
    assert sum(verdicts.values()) == len(frames)
    assert not set(verdicts) - {"allow", "block", "blacklist", "replace"}, "unreviewed DAQ verdict"
    forwarded = pcap_packets(output.read_bytes())
    events = [json.loads(line) for line in run.stdout.splitlines() if line.startswith("{")]
    matched = item["expected_sid"] is None or any(event["rule"] == f"1:{item['expected_sid']}:1" for event in events)
    if item["allowed"]:
        passed = forwarded == frames and verdicts == {"allow": len(frames)}
    elif item["kind"] == "stream_deny":
        passed = forwarded == frames[:3] and verdicts.get("block", 0) + verdicts.get("blacklist", 0) == len(frames) - 3
    elif item["kind"] == "fragments":
        # A previously forwarded orphan cannot complete a datagram at the endpoint.
        # Require an actual native blocking verdict and an exact subset of input bytes.
        passed = len(forwarded) < len(frames) and bool(verdicts.get("block", 0) + verdicts.get("blacklist", 0))
        passed &= all(wire in frames for wire in forwarded) and len(set(forwarded)) == len(forwarded)
    else:
        passed = not forwarded and verdicts.get("block", 0) + verdicts.get("blacklist", 0) == len(frames)
    passed &= matched
    result.update(passed=passed, expected_rule_observed=matched, daq_verdicts=verdicts,
                  output_packet_sha256=[digest(wire) for wire in forwarded], events=events)
    if not passed:
        result["diagnostic_tail"] = run.stdout[-3000:]
    return result


def validate(snort, plugin, workers=4):
    assert __debug__, "validation requires Python assertions"
    snort, plugin = snort.resolve(strict=True), plugin.resolve(strict=True)
    profile_result = profiles.validate(snort, plugin)
    sources = [Path(__file__), HERE / "next_header_policy.py"]
    hashes = {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in sources}
    items = list(fixtures())
    assert len({item["name"] for item in items}) == len(items)
    with tempfile.TemporaryDirectory(prefix="ax-dns-perimeter-replay-") as temporary:
        directory = Path(temporary)
        configs = {}
        for http in (False, True):
            config = directory / ("dns-http.lua" if http else "dns.lua")
            config.write_text(generator.render(generator.load(NATIVE / "dns-perimeter.example.json"), http))
            configs[http] = config
        config_hashes = {"dns-and-http" if http else "dns": digest(config.read_bytes()) for http, config in configs.items()}
        with ThreadPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(lambda item: run_case(snort, plugin, configs[item.get("http", False)], directory,
                                       item, profiles.environment(item.get("http", False))), items))
    assert hashes == {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in sources}
    assert digest(snort.read_bytes()) == profile_result["snort_binary_sha256"]
    assert {path.name: digest(path.read_bytes()) for path in sorted(plugin.glob("*.so"))} == profile_result["plugin_sha256"]
    assert profile_result["source_sha256"] == {name: digest((ROOT / name).read_bytes()) for name in profile_result["source_sha256"]}
    failures = [item["name"] for item in results if not item["passed"]]
    return {"scope": "Synthetic file-only inline dump:pcap DAQ verdicts and forwarded bytes; no deployed sandbox or live interface.",
            "profiles": profile_result, "source_sha256": hashes, "config_sha256": config_hashes,
            "summary": {"cases": len(results), "passed": len(results) - len(failures), "failures": failures,
                        "categories": dict(Counter(item["kind"] for item in results))},
            "limitations": ["The agent source networks require anti-spoofing and an unavoidable host network boundary.",
                            "Inbound control traffic requires trusted router and connection-state policy outside these signatures.",
                            "The DNS proxy rejects encrypted or unauthorized application data at its allowed socket; these rules constrain routing only.",
                            "Blocked fragment captures may forward an orphan fragment; the complete denied datagram must never reach the endpoint.",
                            "HTTP content policy and actual DNS application behavior have separate tests; this is finite network fixture coverage."],
            "cases": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snort", type=Path, required=True)
    parser.add_argument("--plugin-path", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4, choices=range(1, 9))
    args = parser.parse_args()
    report = validate(args.snort, args.plugin_path, args.workers)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["summary"]))
    if report["summary"]["failures"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
