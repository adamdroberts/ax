#!/usr/bin/env python3
"""Compare matched clean/repaired engines with actual file-only inline verdicts."""
import argparse
import concurrent.futures
import ipaddress
import json
import os
from pathlib import Path
import struct
import tempfile

from checksum_replay import module_count, write_pcap
from generate_pcaps import checksum, ip6, packet
from next_header_policy import CONFIG_FILES, digest, run_capture
from replay import load_validator

if not __debug__:
    raise RuntimeError("validation requires assertions")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SOURCE, BASE, HOME, INTERMEDIATE = "2001:db8::1", "2001:db8::2", "2001:db8::3", "2001:db8::4"


def pseudo(destination, protocol, length):
    return (ipaddress.IPv6Address(SOURCE).packed + ipaddress.IPv6Address(destination).packed
            + struct.pack("!I3xB", length, protocol))


def route(home=HOME, kind=2, segments=1):
    return (43, bytes([0, 2, kind, segments]) + b"\0" * 4 + ipaddress.IPv6Address(home).packed)


def chain(headers, protocol, body):
    for kind, header in reversed(headers):
        body = bytes([protocol]) + header[1:] + body
        protocol = kind
    return protocol, body


def checked(body, offset, destination, protocol):
    value = checksum(pseudo(destination, protocol, len(body)) + body)
    if protocol == 17:
        value = value or 0xffff
    return body[:offset] + struct.pack("!H", value) + body[offset + 2:]


def fixtures():
    hop, dest = (0, b"\0" * 8), (60, b"\0" * 8)
    ah = (51, bytes([0, 2]) + struct.pack("!HII", 0, 256, 1) + b"\0" * 4)
    routes = (("direct", []), ("destination-only", [dest]),
              ("type2", [route()]), ("hop-type2", [hop, route()]),
              ("destination-type2", [dest, route()]), ("type2-destination", [route(), dest]),
              ("ah-type2", [ah, route()]), ("type2-ah", [route(), ah]),
              ("two-type2", [route(INTERMEDIATE), route()]),
              ("ignored-route-type2", [route(INTERMEDIATE, 253, 0), route()]),
              ("type2-ignored-route", [route(INTERMEDIATE, 253, 0), route(), route(INTERMEDIATE, 253, 0)]),
              ("active-outer-route-type2", [route(INTERMEDIATE, 253, 1), route()]),
              ("eight-extensions-type2-last", [dest] * 7 + [route()]),
              ("eight-extensions-type2-first", [route()] + [dest] * 7))
    # UDP payload deliberately resembles a further Type 2 header; it must not
    # become a destination selector after the exact upper-layer boundary.
    fake = route(INTERMEDIATE)[1]
    protocols = (("tcp", 6, struct.pack("!HHIIBBHHH", 50000, 80, 100, 0, 80, 2, 65535, 0, 0), 16),
                 ("udp", 17, struct.pack("!HHHH", 50000, 9999, 8 + len(fake), 0) + fake, 6),
                 ("icmp6", 58, struct.pack("!BBHHH", 128, 0, 0, 1, 1), 2))
    for route_name, headers in routes:
        routed = any(kind == 43 and data[2] == 2 for kind, data in headers)
        final = HOME if routed else BASE
        for module, protocol, plain, offset in protocols:
            pair = []
            for valid in (True, False):
                body = checked(plain, offset, final if valid else BASE, protocol)
                if not routed and not valid:
                    body = body[:offset] + bytes([body[offset] ^ 1]) + body[offset + 1:]
                assert (checksum(pseudo(final, protocol, len(body)) + body) == 0) == valid
                first, network = chain(headers, protocol, body)
                frame = packet(ip6(network, first, source=SOURCE, destination=BASE), 6)
                pair.append(frame)
                yield {"name": route_name + "-" + module + ("-correct" if valid else "-incorrect"),
                       "frame": frame, "expected_frame": frame, "valid": valid,
                       "routed": routed, "normalization": False, "counter": [module,
                       {6: "bad_tcp6_checksum", 17: "bad_udp6_checksum", 58: "bad_icmp6_checksum"}[protocol]]}
            # All packet fields except the checksum octets are held constant.
            where = 14 + 40 + sum(len(data) for _, data in headers) + offset
            assert pair[0][:where] == pair[1][:where]
            assert pair[0][where + 2:] == pair[1][where + 2:]
            assert pair[0][where:where + 2] != pair[1][where:where + 2]
    # Exercise encode_update after a real normalizer edit. This extra fixture
    # profile enables tcp.rsv and IPv6 option normalization. The production
    # profile is unchanged; no options are removed from its allowed traffic.
    plain = bytearray(protocols[0][2])
    plain[12] |= 2
    for valid in (True, False):
        body = checked(bytes(plain), 16, HOME if valid else BASE, 6)
        first, network = chain([route()], 6, body)
        frame = packet(ip6(network, first), 6)
        normalized = checked(protocols[0][2], 16, HOME, 6)
        assert (checksum(pseudo(HOME, 6, len(body)) + body) == 0) == valid
        assert checksum(pseudo(HOME, 6, len(normalized)) + normalized) == 0
        changed = {i for i, (a, b) in enumerate(zip(body, normalized)) if a != b}
        assert 12 in changed and changed <= {12, 16, 17}
        if valid:
            assert changed & {16, 17}
        _, expected = chain([route()], 6, normalized)
        yield {"name": "normalizer-tcp-reserved-" + ("correct" if valid else "incorrect"),
               "frame": frame, "expected_frame": packet(ip6(expected, first), 6),
               "valid": valid, "routed": True, "normalization": True,
               "counter": ["tcp", "bad_tcp6_checksum"]}
    # An extension-only normalization still triggers transport update(). The
    # valid checksum must survive, using HOME rather than the IPv6 base address.
    for module, protocol, plain, offset in protocols[1:]:
        for valid in (True, False):
            body = checked(plain, offset, HOME if valid else BASE, protocol)
            first, network = chain([route(), dest], protocol, body)
            frame = packet(ip6(network, first), 6)
            normalized = checked(plain, offset, HOME, protocol)
            padded = (60, bytes([0, 0, 1, 4, 0, 0, 0, 0]))
            _, expected = chain([route(), padded], protocol, normalized)
            assert (checksum(pseudo(HOME, protocol, len(body)) + body) == 0) == valid
            assert checksum(pseudo(HOME, protocol, len(normalized)) + normalized) == 0
            yield {"name": "normalizer-destination-" + module + ("-correct" if valid else "-incorrect"),
                   "frame": frame, "expected_frame": packet(ip6(expected, first), 6),
                   "valid": valid, "routed": True, "normalization": True,
                   "counter": [module, "bad_udp6_checksum" if protocol == 17 else "bad_icmp6_checksum"]}


def validate(baseline, repaired, plugin, repair_source, build_manifest):
    baseline, repaired, plugin, repair_source = (path.resolve(strict=True) for path in
                                                (baseline, repaired, plugin, repair_source))
    binaries = {"baseline": baseline, "repaired": repaired}
    binary_hashes = {name: digest(path.read_bytes()) for name, path in binaries.items()}
    assert binary_hashes["baseline"] != binary_hashes["repaired"]
    build_data = build_manifest.read_bytes()
    build = json.loads(build_data)
    assert build["binary_sha256"] == binary_hashes, "binary differs from reviewed build evidence"
    assert build["comparison"]["same_configuration"]
    assert build["comparison"]["only_checksum_repair_source_changes"]
    source_report_path = repair_source / "ax-type2-source-validation.json"
    source_report = json.loads(source_report_path.read_text())
    for relative, expected in source_report["repaired_sha256"].items():
        assert digest((repair_source / relative).read_bytes()) == expected
    for name, expected in source_report["local_source_sha256"].items():
        assert digest((HERE.parent / "patches" / name).read_bytes()) == expected
    sources = [Path(__file__), HERE / "checksum_replay.py", HERE / "next_header_policy.py",
               HERE / "generate_pcaps.py", HERE / "replay.py",
               HERE.parent / "patches/ipv6_checksum_destination_test.cc"]
    hashes = {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in sources}
    profiles = {name: load_validator().validate(path, plugin) for name, path in binaries.items()}
    assert profiles["baseline"] == profiles["repaired"], "configuration or enabled rule actions changed"
    environment = {key: value for key, value in os.environ.items() if not key.startswith("AX_")}
    config = {name: (HERE.parent / name).read_bytes() for name in CONFIG_FILES}
    with tempfile.TemporaryDirectory(prefix="ax-type2-repair-replay-") as temporary:
        directory = Path(temporary)
        for name, data in config.items():
            (directory / name).write_bytes(data)
        config_text = config["protocol-ips.lua"].decode()
        before = "normalizer = { tcp = { ips = true, block = true, trim_win = true } }"
        assert config_text.count(before) == 1
        special = config_text.replace(before, before.replace("{ tcp =", "{ ip6 = true, tcp =").replace(
            "ips = true", "rsv = true, ips = true"))
        (directory / "normalize.lua").write_text(special)

        def compare(case):
            capture = directory / (case["name"] + ".pcap")
            write_pcap(capture, [case["frame"]])
            observed = {}
            for label, binary in binaries.items():
                result = run_capture(binary, plugin, directory / (
                    "normalize.lua" if case["normalization"] else "protocol-ips.lua"), capture,
                    directory / (case["name"] + "-" + label + ".pcap"), environment, include_stdout=True)
                stdout = result.pop("stdout")
                result["checksum_errors"] = module_count(stdout, *case["counter"])
                result["checksum_bypassed"] = module_count(stdout, case["counter"][0], "checksum_bypassed")
                assert result["checksum_bypassed"] == 0
                observed[label] = result
            old, new = observed["baseline"], observed["repaired"]
            expected_old_errors = int(case["valid"] if case["routed"] else not case["valid"])
            baseline_matches = old["checksum_errors"] == expected_old_errors and old["blocked"] == bool(expected_old_errors)
            passed = new["checksum_errors"] == int(not case["valid"]) and new["blocked"] == (not case["valid"])
            if not new["blocked"]:
                passed = passed and new["output_packet_sha256"] == [digest(case["expected_frame"])]
            return {key: value for key, value in case.items() if key not in ("frame", "expected_frame")} | {
                "input_packet_sha256": digest(case["frame"]),
                "expected_forwarded_packet_sha256": digest(case["expected_frame"]),
                "baseline_matches_oracle": baseline_matches, "repaired_matches_oracle": passed, **observed}

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(compare, list(fixtures())))
    assert hashes == {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in sources}
    assert binary_hashes == {name: digest(path.read_bytes()) for name, path in binaries.items()}
    assert build_manifest.read_bytes() == build_data
    for relative, expected in profiles["repaired"]["sha256"].items():
        assert digest((ROOT / relative).read_bytes()) == expected
    plugin_files = [plugin] if plugin.is_file() else sorted(set(plugin.rglob("*.so")) | set(plugin.rglob("*.dylib")))
    assert profiles["repaired"]["plugin_sha256"] == {path.name: digest(path.read_bytes()) for path in plugin_files}
    for relative, expected in source_report["repaired_sha256"].items():
        assert digest((repair_source / relative).read_bytes()) == expected
    failures = [case["name"] for case in results if not case["repaired_matches_oracle"] or not case["baseline_matches_oracle"]]
    return {"scope": "File-only inline DAQ; no live interfaces, deployment, routing state, or Mobile IPv6 binding ownership.",
            "configuration": profiles["repaired"], "binary_sha256": binary_hashes,
            "source_repair": source_report, "fixture_source_sha256": hashes,
            "build_manifest_sha256": digest(build_data),
            "normalizer_fixture_configuration_sha256": digest(special.encode()),
            "comparison_limit": "Source and binary hashes are recorded; build provenance is supplied separately. These fixtures do not establish universal IPv6 routing or checksum conformance.",
            "summary": {"cases": len(results), "native_runs": len(results) * 2,
                        "passed": len(results) - len(failures), "failures": failures,
                        "routed_cases": sum(case["routed"] for case in results),
                        "normalization_cases": sum(case["normalization"] for case in results)},
            "cases": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--repaired", type=Path, required=True)
    parser.add_argument("--plugin-path", type=Path, required=True)
    parser.add_argument("--repair-source", type=Path, required=True)
    parser.add_argument("--build-manifest", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = validate(args.baseline, args.repaired, args.plugin_path, args.repair_source, args.build_manifest)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["summary"], indent=2))
    if report["summary"]["failures"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
