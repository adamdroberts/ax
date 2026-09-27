#!/usr/bin/env python3
"""Compare the IPv6 base Next Header policy using file-only inline DAQ runs.

The comparison policy is reconstructed from the current files: restore the
116:281 drop and remove only supplement 9201011. Both sides use the same Snort
binary and plugin. This is not a replay of a historical binary or deployment.
"""
import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile

if not __debug__:
    raise RuntimeError("validation requires Python assertions; do not use -O or PYTHONOPTIMIZE")

HERE = Path(__file__).resolve().parent
NATIVE = HERE.parent
ROOT = NATIVE.parent
CONFIG_FILES = ("protocol-ips.lua", "protocol.states", "protocol-builtins.rules",
                "protocol-validation.rules")
# Exact base-header admission set in the pinned Snort 3.12.2.0 ipv6.h.
PREVIOUS_ADMITTED = {0, 6, 17, 43, 44, 47, 50, 58, 59, 60, 135, 137}
VERDICTS = {"allow", "block", "replace", "whitelist", "blacklist", "ignore", "retry"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def checksum(data):
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def fixture(next_header):
    source = ipaddress.IPv6Address("fe80::1").packed
    destination = ipaddress.IPv6Address("fe80::2").packed
    payload = b"A" * 64
    if next_header == 51:
        # Structural AH control followed by checksum-valid Neighbor Discovery.
        # No security association, integrity value or replay state is verified.
        nd = struct.pack("!BBHI", 135, 0, 0, 0) + destination
        pseudo = source + destination + struct.pack("!I3xB", len(nd), 58)
        nd = nd[:2] + struct.pack("!H", checksum(pseudo + nd)) + nd[4:]
        payload = bytes([58, 2]) + struct.pack("!HII", 0, 256, 1) + b"\0" * 4 + nd
    ipv6 = struct.pack("!IHBB16s16s", 6 << 28, len(payload), next_header,
                       255, source, destination) + payload
    packet = bytes.fromhex("02000000000202000000000186dd") + ipv6
    pcap = (struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
            + struct.pack("<IIII", 1, 0, len(packet), len(packet)) + packet)
    return packet, pcap


def pcap_packets(data):
    assert len(data) >= 24, "output PCAP global header missing"
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(data[:4])
    assert endian, "unsupported output PCAP format"
    _, major, minor, _, _, snaplen, linktype = struct.unpack(endian + "IHHIIII", data[:24])
    assert (major, minor, linktype) == (2, 4, 1) and snaplen >= 118, "unexpected PCAP format"
    packets, offset = [], 24
    while offset < len(data):
        assert len(data) - offset >= 16, "truncated output PCAP record"
        _, _, captured, original = struct.unpack(endian + "IIII", data[offset:offset + 16])
        offset += 16
        assert captured == original and captured <= snaplen, "truncated output capture"
        assert captured <= len(data) - offset, "truncated output PCAP packet"
        packets.append(data[offset:offset + captured])
        offset += captured
    return packets


def reconstruct_previous(current):
    previous = dict(current)
    for filename in ("protocol.states", "protocol-builtins.rules"):
        expression = r"(?m)^alert(?= \( gid:116; sid:281;)"
        previous[filename], count = re.subn(expression, "drop", current[filename])
        assert count == 1, "expected exactly one advisory 116:281 in " + filename
    lines = current["protocol-validation.rules"].splitlines(keepends=True)
    supplement = [line for line in lines if re.search(r"; sid:9201011;", line)]
    assert len(supplement) == 1, "expected exactly one replacement Next Header rule"
    assert supplement[0].startswith("drop ip ") and "; ax_ip6_base_next_header;" in supplement[0]
    previous["protocol-validation.rules"] = "".join(line for line in lines if line != supplement[0])
    assert previous["protocol-ips.lua"] == current["protocol-ips.lua"]
    return previous


def rule_actions(snort, plugin, config, environment):
    result = subprocess.run([str(snort), "--plugin-path", str(plugin), "-c", str(config),
                             "-T", "--dump-rule-state"], env=environment,
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr + result.stdout
    actions = {}
    for line in result.stdout.splitlines():
        rule = json.loads(line)
        key = rule["gid"], rule["sid"]
        assert key not in actions, "duplicate rule ID"
        assert len(rule["states"]) == 1 and rule["states"][0]["enable"] == "yes"
        actions[key] = rule["states"][0]["action"]
    return actions


def run_capture(snort, plugin, config, capture, output, environment, include_stdout=False):
    # The lower DAQ reads the supplied file. The inline wrapper writes forwarded
    # packets to another file; no network interface is opened or transmitted to.
    command = [str(snort), "--plugin-path", str(plugin), "-c", str(config),
               "--daq", "pcap", "--daq-mode", "read-file", "--daq", "dump",
               "--daq-mode", "inline", "--daq-var", "file=" + str(output),
               "-Q", "-r", str(capture), "-s", "65535", "-A", "alert_json"]
    result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0 and not result.stderr.strip(), result.stderr + result.stdout
    assert "dump:pcap DAQ configured to inline." in result.stdout, "incorrect DAQ execution mode"
    section = re.search(r"(?m)^daq\n((?:[ \t].*\n)*)", result.stdout)
    assert section, "DAQ statistics missing"
    counters = {name: int(value) for name, value in re.findall(
        r"(?m)^\s+(\w+):\s+(\d+)\b", section[1])}
    assert counters.get("received") == 1 and counters.get("analyzed") == 1
    verdicts = {name: counters[name] for name in sorted(VERDICTS) if counters.get(name)}
    assert sum(verdicts.values()) == 1, "expected one native DAQ verdict"
    verdict = next(iter(verdicts))
    assert verdict not in {"ignore", "retry"}, "unreviewed native DAQ verdict"
    output_data = output.read_bytes()
    packets = pcap_packets(output_data)
    blocked = verdict in {"block", "blacklist"}
    assert len(packets) == (0 if blocked else 1), "DAQ verdict disagrees with forwarded packets"
    events = []
    for line in result.stdout.splitlines():
        if line.startswith("{"):
            event = json.loads(line)
            events.append({key: event[key] for key in ("rule", "action", "msg")})
    evidence = {"blocked": blocked, "daq_verdict": verdict, "daq_counters": counters,
                "output_pcap_sha256": digest(output_data), "output_packets": len(packets),
                "output_packet_sha256": [digest(packet) for packet in packets], "events": events}
    if include_stdout:
        evidence["stdout"] = result.stdout
    return evidence


def validate(snort, plugin):
    snort, plugin = snort.resolve(strict=True), plugin.resolve(strict=True)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("AX_")}
    version = subprocess.check_output([str(snort), "--dump-version"], env=environment, text=True).strip()
    binary_hash = digest(snort.read_bytes())
    inventory_data = (NATIVE / "builtin-inventory.json").read_bytes()
    inventory = json.loads(inventory_data)
    assert version == "3.12.2.0" == inventory["snort_version"], "unreviewed Snort version"
    plugin_files = ([plugin] if plugin.is_file() else
                    sorted(set(plugin.rglob("*.so")) | set(plugin.rglob("*.dylib"))))
    assert plugin_files, "native plugin library missing"
    plugin_hashes = {str(path): digest(path.read_bytes()) for path in plugin_files}
    current = {name: (NATIVE / name).read_text() for name in CONFIG_FILES}
    previous = reconstruct_previous(current)
    config_hashes = {name: digest(text.encode()) for name, text in current.items()}
    previous_hashes = {name: digest(text.encode()) for name, text in previous.items()}
    with tempfile.TemporaryDirectory(prefix="ax-next-header-policy-") as temporary:
        directory = Path(temporary)
        for label, files in (("current", current), ("reconstructed_previous", previous)):
            (directory / label).mkdir()
            for name, text in files.items():
                (directory / label / name).write_text(text)
        current_actions = rule_actions(snort, plugin, directory / "current/protocol-ips.lua", environment)
        previous_actions = rule_actions(snort, plugin, directory / "reconstructed_previous/protocol-ips.lua", environment)
        assert current_actions[(116, 281)] == "alert" and current_actions[(1, 9201011)] == "drop"
        expected_previous = current_actions | {(116, 281): "drop"}
        del expected_previous[(1, 9201011)]
        assert previous_actions == expected_previous, "unintended reconstructed policy difference"

        def compare(next_header):
            packet, pcap = fixture(next_header)
            capture = directory / f"next-{next_header:03}.pcap"
            capture.write_bytes(pcap)
            results = {}
            for label in ("reconstructed_previous", "current"):
                results[label] = run_capture(snort, plugin, directory / label / "protocol-ips.lua",
                                            capture, directory / label / f"out-{next_header:03}.pcap", environment)
            before, after = results["reconstructed_previous"], results["current"]
            if next_header == 51:
                passed = before["blocked"] and not after["blocked"]
                passed = passed and after["output_packet_sha256"] == [digest(packet)]
            else:
                passed = before["blocked"] == after["blocked"]
                passed = passed and before["daq_verdict"] == after["daq_verdict"]
                passed = passed and before["output_packet_sha256"] == after["output_packet_sha256"]
                if next_header not in PREVIOUS_ADMITTED:
                    passed = passed and before["blocked"] and after["blocked"]
            return {"next_header": next_header, "capture_sha256": digest(pcap),
                    "passed": passed, **results}

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            cases = list(executor.map(compare, range(256)))
    assert plugin_hashes == {str(path): digest(path.read_bytes()) for path in plugin_files}, "plugin changed during validation"
    assert binary_hash == digest(snort.read_bytes()), "Snort binary changed during validation"
    assert config_hashes == {name: digest((NATIVE / name).read_bytes()) for name in CONFIG_FILES}, "configuration changed during validation"
    failures = [case["next_header"] for case in cases if not case["passed"]]
    rejected = [case for case in cases if case["next_header"] not in PREVIOUS_ADMITTED | {51}]
    assert len(rejected) == 243
    return {
        "snort_version": version, "source_commit": inventory["source_commit"],
        "snort_binary_sha256": binary_hash,
        "scope": "File-only inline dump:pcap DAQ verdicts and forwarded-output captures. No live network interface, deployment route or endpoint is tested.",
        "comparison": {
            "baseline": "Reconstructed previous Next Header predicate using the same current Snort binary and plugin, not a historical binary or deployment.",
            "changes": ["protocol-builtins.rules: only 116:281 alert becomes drop",
                        "protocol.states: only 116:281 alert becomes drop",
                        "protocol-validation.rules: remove only rule 9201011",
                        "protocol-ips.lua: unchanged"],
            "loaded_rule_difference_verified": True,
            "reconstructed_previous_config_sha256": previous_hashes,
            "previous_admitted_base_values": sorted(PREVIOUS_ADMITTED),
            "newly_admitted_base_values": [51],
        },
        "summary": {"cases": len(cases), "native_runs": len(cases) * 2,
                    "passed": len(cases) - len(failures), "failures": failures,
                    "retained_non_ah_rejections": sum(case["current"]["blocked"] for case in rejected),
                    "previous_blocked": sum(case["reconstructed_previous"]["blocked"] for case in cases),
                    "current_blocked": sum(case["current"]["blocked"] for case in cases)},
        "limitations": ["One bounded packet shape per base Next Header value; this is not exhaustive protocol conformance or payload coverage.",
                        "All values except AH use 64 opaque octets, which can independently violate their upper-layer protocol.",
                        "The AH control checks framing and following ND checksum only; no SA, ICV or replay-window authentication is performed.",
                        "Native DAQ verdicts and output PCAPs are checked independently of alert actions. Default read-file inline simulation omits some checksum drops and is not used for this comparison."],
        "plugin_sha256": {path.name: plugin_hashes[str(path)] for path in plugin_files},
        "sha256": {**{"native-snort3/" + name: value for name, value in config_hashes.items()},
                   "native-snort3/builtin-inventory.json": digest(inventory_data),
                   HERE.joinpath("next_header_policy.py").relative_to(ROOT).as_posix(): digest(Path(__file__).read_bytes())},
        "cases": cases,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snort", type=Path, required=True)
    parser.add_argument("--plugin-path", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    report = validate(args.snort, args.plugin_path)
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"summary": report["summary"], "scope": report["scope"]}, indent=2))
    if report["summary"]["failures"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
