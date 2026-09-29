#!/usr/bin/env python3
"""Audit opaque protocols, IP/GRE encapsulation and Mobile IPv6 peer identity.

Uses synthetic file-only inline DAQ runs. The reconstructed comparison policy
removes only the Home Address boundary rule; the general RFC validator is intact.
"""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
from pathlib import Path
import struct
import tempfile

import dns_perimeter_replay as replay
from next_header_policy import rule_actions

HERE, ROOT = replay.HERE, replay.ROOT
HOME_SID = 9202016


def protocol_fixtures():
    for version, (agent, dns, broker, outside) in replay.ADDRESSES.items():
        for destination, role in ((dns, "dns"), (broker, "broker")):
            for protocol in range(256):
                if protocol in (6, 17):
                    continue  # Valid TCP/UDP and extension controls are in the main suite.
                for size in (0, 64):
                    yield replay.case(f"v{version}-{role}-raw-p{protocol}-len{size}",
                        [replay.frame(agent, destination, protocol, bytes(size))], False, category="opaque-protocol")
        for inner_version, (ia, ide, _, _) in replay.ADDRESSES.items():
            for protocol in (6, 17):
                for destination, role in ((dns, "dns"), (broker, "broker"), (outside, "outside")):
                    inner = replay.frame(ia, ide, protocol, replay.transport(ia, ide, protocol))[14:]
                    nxt = 4 if inner_version == 4 else 41
                    yield replay.case(f"v{version}-{role}-ipip-v{inner_version}-p{protocol}",
                        [replay.frame(agent, destination, nxt, inner)], False, category="encapsulation")
                    gre = struct.pack("!HH", 0, 0x0800 if inner_version == 4 else 0x86dd) + inner
                    yield replay.case(f"v{version}-{role}-gre-v{inner_version}-p{protocol}",
                        [replay.frame(agent, destination, 47, gre)], False, category="encapsulation")


def home_extension(protocol, address, position=6):
    assert position >= 2
    extension = bytes([protocol, 0]) + bytes(position - 2) + bytes([0xc9, 16]) + ipaddress.ip_address(address).packed
    extension += bytes(-len(extension) % 8)
    return extension[:1] + bytes([len(extension) // 8 - 1]) + extension[2:]


def mobility_fixtures():
    agent, dns, broker, outside = replay.ADDRESSES[6]
    contexts = [("out-dns", agent, dns, 45000, 53, p) for p in (6, 17)]
    contexts += [("in-dns", dns, agent, 53, 45000, p) for p in (6, 17)]
    contexts += [("out-broker", agent, broker, 45000, 443, 6), ("in-broker", broker, agent, 443, 45000, 6)]
    for role, source, destination, sport, dport, protocol in contexts:
        def transport(logical_source=source, data=None):
            return replay.transport(logical_source, destination, protocol, sport, dport,
                                    data=replay.dns_query() * 2 if data is None else data)

        for label, logical_source in (("same", source), ("other-agent", "fd00:20::9"), ("outside", outside)):
            body = transport(logical_source)
            # Verify the generated transport checksum independently as a folded sum.
            checked = replay.pseudo(logical_source, destination, protocol, len(body)) + body
            assert sum(int.from_bytes(checked[i:i+2].ljust(2, b"\0"), "big") for i in range(0, len(checked), 2)) % 65535 == 0
            for layout in ("base", "aligned14", "large2030", "hop-home", "fragment01", "fragment10"):
                position = {"aligned14": 14, "large2030": 2030}.get(layout, 6)
                extension = home_extension(44 if layout.startswith("fragment") else protocol, logical_source, position)
                first = 60
                if layout == "hop-home":
                    extension, first = bytes([60, 0]) + bytes(6) + extension, 0
                if layout.startswith("fragment"):
                    frames = [replay.frame(source, destination, protocol, body[:24], extensions=extension, first=first, fragment=(0, True)),
                              replay.frame(source, destination, protocol, body[24:], extensions=extension, first=first, fragment=(24, False))]
                    if layout.endswith("10"):
                        frames.reverse()
                else:
                    frames = [replay.frame(source, destination, protocol, body, extensions=extension, first=first)]
                yield replay.case(f"{role}-p{protocol}-home-{label}-{layout}", frames, False, HOME_SID,
                    kind="home", category="home-boundary", baseline_allowed=True, logical_source=logical_source,
                    wire_source=source, changed_source=logical_source != source, layout=layout)

        ordinary = transport()
        patterns = [
            ("plain", [], ordinary, None, True),
            ("padding", [bytes([protocol, 2]) + bytes(22)], ordinary, 60, True),
            ("opaque-option", [bytes([protocol, 2, 0x1e, 18, 0xc9, 16]) + ipaddress.ip_address(outside).packed + bytes(2)], ordinary, 60, True),
            ("payload-lookalike", [], transport(data=home_extension(protocol, outside) + replay.dns_query()), None, True),
            ("malformed-alignment", [home_extension(protocol, outside, position=2)], ordinary, 60, False),
        ]
        corrupt = bytearray(transport(outside))
        corrupt[16 if protocol == 6 else 6] ^= 1
        patterns.append(("bad-checksum", [home_extension(protocol, outside)], bytes(corrupt), 60, False))
        for label, headers, body, first, allowed in patterns:
            frame = replay.frame(source, destination, protocol, body, extensions=b"".join(headers), first=first)
            yield replay.case(f"{role}-p{protocol}-control-{label}", [frame], allowed, category="control",
                              baseline_allowed=allowed, kind="home-control")


def validate(snort, plugin, workers=4, mobility_only=False):
    assert __debug__, "validation requires assertions"
    snort, plugin = snort.resolve(strict=True), plugin.resolve(strict=True)
    configuration = replay.profiles.validate(snort, plugin)
    sources = [Path(__file__), HERE / "dns_perimeter_replay.py", HERE / "next_header_policy.py"]
    source_hashes = {str(path.relative_to(ROOT)): replay.digest(path.read_bytes()) for path in sources}
    items = ([] if mobility_only else list(protocol_fixtures())) + list(mobility_fixtures())
    assert len({item["name"] for item in items}) == len(items)
    with tempfile.TemporaryDirectory(prefix="ax-dns-perimeter-bypass-") as temporary:
        directory = Path(temporary)
        current, previous = directory / "current.lua", directory / "previous.lua"
        current_text = replay.generator.render(replay.generator.load(replay.NATIVE / "dns-perimeter.example.json"))
        previous_lines = [line for line in current_text.splitlines() if f"sid:{HOME_SID};" not in line]
        assert len(current_text.splitlines()) - len(previous_lines) == 2
        current.write_text(current_text)
        previous.write_text("\n".join(previous_lines) + "\n")
        env = replay.profiles.environment()
        observed = rule_actions(snort, plugin, current, env)
        expected_previous = dict(observed)
        assert expected_previous.pop((1, HOME_SID)) == "block"
        assert rule_actions(snort, plugin, previous, env) == expected_previous
        (directory / "current").mkdir()
        (directory / "previous").mkdir()

        def run(item):
            result = replay.run_case(snort, plugin, current, directory / "current", item, env)
            if "baseline_allowed" in item:
                baseline_item = item | {"allowed": item["baseline_allowed"], "expected_sid": None}
                baseline = replay.run_case(snort, plugin, previous, directory / "previous", baseline_item, env)
                result["reconstructed_previous"] = baseline
                result["passed"] &= baseline["passed"]
            return result

        with ThreadPoolExecutor(max_workers=workers) as executor:
            cases = list(executor.map(run, items))
        config_hashes = {"current": replay.digest(current.read_bytes()), "reconstructed_previous": replay.digest(previous.read_bytes())}
    assert source_hashes == {str(path.relative_to(ROOT)): replay.digest(path.read_bytes()) for path in sources}
    assert configuration["snort_binary_sha256"] == replay.digest(snort.read_bytes())
    assert configuration["plugin_sha256"] == {path.name: replay.digest(path.read_bytes()) for path in sorted(plugin.glob("*.so"))}
    assert configuration["source_sha256"] == {name: replay.digest((ROOT / name).read_bytes()) for name in configuration["source_sha256"]}
    failures = [case["name"] for case in cases if not case["passed"]]
    return {"scope": "File-only inline DAQ verdicts and forwarded bytes. No live endpoint, Mobile IPv6 binding state or deployed route is tested.",
            "comparison": "Same engine and plugins; reconstructed previous configuration removes only Home Address boundary SID 9202016 and its enabled state.",
            "configuration": configuration, "source_sha256": source_hashes, "config_sha256": config_hashes,
            "summary": {"cases": len(cases), "passed": len(cases) - len(failures), "failures": failures,
                        "native_runs": len(cases) + sum("baseline_allowed" in case for case in cases),
                        "categories": dict(Counter(case["category"] for case in cases)),
                        "new_home_option_rejections": sum(case["passed"] and case["category"] == "home-boundary" for case in cases),
                        "changed_source_cases": sum(case.get("changed_source", False) for case in cases)},
            "limitations": ["Opaque protocol sweep uses empty and zero-filled payloads; it is not semantic conformance for 254 other protocols.",
                            "Encapsulation coverage is bounded to IP-in-IP and plain GRE with IPv4/IPv6 TCP/UDP inner controls.",
                            "Home Address rejection is fixed-peer local policy. General protocol validation and authenticated Mobile IPv6 support are separate concerns.",
                            "The comparison confirms forwarding changed at the sensor; it does not demonstrate successful application impersonation on a live host.",
                            "Each report case counts once even when two comparison configurations were exercised."],
            "cases": cases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snort", type=Path, required=True)
    parser.add_argument("--plugin-path", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4, choices=range(1, 9))
    parser.add_argument("--mobility-only", action="store_true", help="limit sanitizer repetition to the option and its controls")
    args = parser.parse_args()
    report = validate(args.snort, args.plugin_path, args.workers, args.mobility_only)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["summary"]))
    if report["summary"]["failures"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
