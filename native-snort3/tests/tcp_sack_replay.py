#!/usr/bin/env python3
"""File-only TCP SACK negotiation, rejected-offer and flow-lifetime audit."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import struct
import tempfile

import tcp_options_replay as tcp

replay = tcp.replay


def wire(source, destination, body, version, fragmented=False, reverse=False, identifier=1234, hop=64, hbh=False):
    if fragmented:
        split = 16 if version == 4 else ((body[12] >> 4) * 4 + 7) // 8 * 8
        assert split < len(body)
        frames = [replay.frame(source, destination, 6, body[:split], fragment=(0, True)),
                  replay.frame(source, destination, 6, body[split:], fragment=(split, False))]
    else:
        ext = bytes([6, 0]) + bytes(6) if hbh else b""
        frames = [replay.frame(source, destination, 6, body, extensions=ext, first=0 if hbh else None)]
    adjusted = []
    for raw in frames:
        data = bytearray(raw)
        if version == 4:
            data[18:20] = struct.pack("!H", identifier)
            data[22] = hop
            data[24:26] = b"\0\0"
            data[24:26] = struct.pack("!H", replay.checksum(data[14:34]))
        else:
            data[21] = hop
            if fragmented:
                data[58:62] = struct.pack("!I", identifier)
        adjusted.append(bytes(data))
    return list(reversed(adjusted)) if reverse else adjusted


def conversation(version, agent, target, port, mask, client, variant="plain", poison=None,
                 sport=45000, isn=100, peer_isn=700, id_base=1234):
    # IPv6 first fragments include the whole TCP header. Fast Open SYN data
    # supplies a nonempty second fragment without violating that requirement.
    fragmented_syn = variant.startswith(("syn-", "synack-", "bothsyn-"))
    fast_open = version == 6 and (fragmented_syn or poison == "fragmented")
    syn_data = b"abcdefgh" if fast_open else b""
    fast_option = bytes([34, 6]) + b"cook" if fast_open else b""
    next_client, next_server = isn + 1 + len(syn_data), peer_isn + 1 + len(syn_data)
    client_options = tcp.padded((bytes([4, 2]) if mask & 1 else b"") + fast_option)
    server_options = tcp.padded((bytes([4, 2]) if mask & 2 else b"") + fast_option)
    stages = [
        (agent, target, tcp.tcp(agent, target, sport, port, client_options, 2, isn, 0, syn_data)),
        (target, agent, tcp.tcp(target, agent, port, sport, server_options, 18, peer_isn, next_client, syn_data)),
        (agent, target, tcp.tcp(agent, target, sport, port, b"", 16, next_client, next_server)),
    ]
    src, dst, sp, dp, seq, peer_seq = ((agent, target, sport, port, next_client, next_server) if client
                                     else (target, agent, port, sport, next_server, next_client))
    stages.append((dst, src, tcp.tcp(dst, src, dp, sp, b"", 24, peer_seq + 10, seq, b"1234567890")))
    sack = tcp.padded(bytes([5, 10]) + struct.pack("!II", peer_seq + 10, peer_seq + 20))
    stages.append((src, dst, tcp.tcp(src, dst, sp, dp, sack, 16, seq, peer_seq,
                                  b"abcdefgh" if variant.startswith("subject-") else b"")))
    permission = bool(mask & (2 if client else 1))
    frames, denied, incomplete = [], [], []
    poison_stage = 1 if client else 0
    for index, (source, destination, body) in enumerate(stages):
        def add_poison():
            offer = b"" if poison == "revoke" else bytes([4, 2])
            option = tcp.padded(offer + fast_option)
            bad = tcp.tcp(source, destination, port if index else sport, sport if index else port,
                          option, 18 if index else 2, peer_isn if index else isn,
                          next_client if index else 0, syn_data)
            packets = wire(source, destination, bad, version, poison == "fragmented",
                           False, id_base + 20 + index, hop=13)
            start = len(frames)
            frames.extend(packets)
            if len(packets) == 1:
                denied.append(start)
            else:
                incomplete.append(list(range(start, len(frames))))
        if poison and index == poison_stage and poison != "revoke":
            add_poison()
        fragmented = ((index == 0 and variant.startswith(("syn-", "bothsyn-"))) or
                      (index == 1 and variant.startswith(("synack-", "bothsyn-"))) or
                      (index == 4 and variant.startswith("subject-")))
        packets = wire(source, destination, body, version, fragmented, variant.endswith("reverse"),
                       id_base + index, hbh=variant == "hbh")
        start = len(frames)
        frames.extend(packets)
        if index == 4 and not permission:
            if len(packets) == 1:
                denied.append(start)
            else:
                incomplete.append(list(range(start, len(frames))))
        if poison == "revoke" and index == poison_stage:
            add_poison()
    return {"frames": frames, "denied_indices": denied, "incomplete_groups": incomplete,
            "sack_permitted": permission}


def fixtures():
    for version, (agent, dns, broker, _) in replay.ADDRESSES.items():
        for target, port, role in ((dns, 53, "dns"), (broker, 443, "broker")):
            variants = ["plain", "syn-forward", "syn-reverse", "synack-forward", "synack-reverse",
                        "bothsyn-forward", "bothsyn-reverse", "subject-forward", "subject-reverse"]
            if version == 6:
                variants.append("hbh")
            for mask in range(4):
                for client in (False, True):
                    for variant in variants:
                        name = f"v{version}-{role}-mask{mask}-{'client' if client else 'server'}-{variant}"
                        yield {"name": name, "category": "negotiation", **conversation(version, agent, target, port, mask, client, variant)}
            for client in (False, True):
                for poison, mask in (("grant", 0), ("fragmented", 0), ("revoke", 3)):
                    name = f"v{version}-{role}-poison-{poison}-{'client' if client else 'server'}"
                    yield {"name": name, "category": "rejected-offer", **conversation(version, agent, target, port, mask, client, poison=poison)}
                for reuse in (False, True):
                    first = conversation(version, agent, target, port, 3, client)
                    frames = list(first["frames"])
                    if reuse:
                        frames += wire(target, agent, tcp.tcp(target, agent, port, 45000, b"", 20, 701, 101), version)
                    second = conversation(version, agent, target, port, 0, client,
                                          sport=45000 if reuse else 45002, isn=1000, peer_isn=7000, id_base=2234)
                    offset = len(frames)
                    frames += second["frames"]
                    yield {"name": f"v{version}-{role}-{'reuse' if reuse else 'isolation'}-{'client' if client else 'server'}",
                           "category": "flow-lifetime", "frames": frames,
                           "denied_indices": [offset + i for i in second["denied_indices"]],
                           "incomplete_groups": [], "sack_permitted": False}


def run(snort, plugin, config, directory, item):
    # Reuse packet execution/DAQ parsing; the conversation oracle below handles
    # multiple blocked stages and orphan fragments explicitly.
    probe = replay.case(item["name"], item["frames"], not item["denied_indices"] and not item["incomplete_groups"],
                        kind="conversation", category=item["category"])
    result = replay.run_case(snort, plugin, config, directory, probe, replay.profiles.environment(False))
    result.update({k: v for k, v in item.items() if k not in ("name", "frames", "category")})
    if "daq_verdicts" not in result:
        return result
    inputs, outputs = result["input_packet_sha256"], result["output_packet_sha256"]
    blocked = set(item["denied_indices"])
    # Each incomplete group contains two fragments. Enumerate the acceptable
    # orphan subsets; none may let a rejected datagram become complete.
    choices = [blocked]
    for group in item["incomplete_groups"]:
        assert len(group) == 2
        choices = [choice | extra for choice in choices for extra in ({group[0]}, {group[1]}, set(group))]
    result["passed"] = any(outputs == [p for i, p in enumerate(inputs) if i not in denied]
                           and result["daq_verdicts"].get("allow", 0) == len(inputs) - len(denied)
                           and result["daq_verdicts"].get("block", 0) + result["daq_verdicts"].get("blacklist", 0) == len(denied)
                           for denied in choices)
    if result["passed"]:
        result.pop("diagnostic_tail", None)
    return result


def validate(snort, plugin, workers):
    assert __debug__
    snort, plugin = snort.resolve(strict=True), plugin.resolve(strict=True)
    items = list(fixtures())
    assert len({item["name"] for item in items}) == len(items)
    sources = [Path(__file__), Path(tcp.__file__), Path(replay.__file__),
               replay.NATIVE / "protocol-ips.lua", replay.NATIVE / "protocol-validation.rules",
               replay.NATIVE / "plugins/ax_nd_options.cc", replay.NATIVE / "generate_dns_perimeter.py"]
    hashes = {str(p.relative_to(replay.ROOT)): replay.digest(p.read_bytes()) for p in sources}
    with tempfile.TemporaryDirectory(prefix="ax-tcp-sack-replay-") as tmp:
        directory = Path(tmp)
        config = directory / "dns.lua"
        config.write_text(replay.generator.render(replay.generator.load(replay.NATIVE / "dns-perimeter.example.json"), False)
                          + '\nips.rules = ips.rules .. [[\ndrop tcp any any -> any any (msg:"AX test rejected offer"; ttl:13; sid:9202999; rev:1;)\n]]\n'
                          + 'ips.states = ips.states .. "\\ndrop ( gid:1; sid:9202999; enable:yes; )"\n')
        config_hash = replay.digest(config.read_bytes())
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(lambda item: run(snort, plugin, config, directory, item), items))
    assert hashes == {str(p.relative_to(replay.ROOT)): replay.digest(p.read_bytes()) for p in sources}
    failures = [c["name"] for c in results if not c["passed"]]
    return {"scope": "Synthetic inline file replay only. SID 9202999 is a fixture-only drop of valid handshake offers; it is not part of the deployed ruleset.",
            "source_sha256": hashes, "config_sha256": config_hash,
            "snort_binary_sha256": replay.digest(snort.read_bytes()),
            "plugin_sha256": {p.name: replay.digest(p.read_bytes()) for p in sorted(plugin.glob("*.so"))},
            "summary": {"cases": len(results), "passed": len(results)-len(failures), "failures": failures,
                        "accepted_controls": sum(not i["denied_indices"] and not i["incomplete_groups"] for i in items)},
            "cases": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snort", type=Path, required=True)
    parser.add_argument("--plugin-path", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--workers", type=int, choices=range(1, 9), default=4)
    args = parser.parse_args()
    report = validate(args.snort, args.plugin_path, args.workers)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["summary"]))
    raise SystemExit(bool(report["summary"]["failures"]))


if __name__ == "__main__":
    main()
