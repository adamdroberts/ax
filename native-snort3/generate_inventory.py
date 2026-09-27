#!/usr/bin/env python3
"""Derive release-pinned decoder/stream states from official source and Snort.

Reads source as data; never executes upstream build scripts. A different release
requires deliberate policy review and changing VERSION/COMMIT, not a flag that
silently accepts changed GID:SIDs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

VERSION = "3.12.2.0"
COMMIT = "14aeb09f5a0856812dbe08ead3c21f99e8860aa0"
HERE = Path(__file__).resolve().parent

# These events include legal traffic, compatibility heuristics, or sender-side
# recommendations that receivers must not mistake for universal invalidity.
# Every other event in the chosen groups is an explicit strict-policy drop.
ALERT = {
    "DECODE_TCPOPT_TTCP": "Legacy TCP feature; retire via endpoint policy.",
    "DECODE_TCPOPT_OBSOLETE": "Legacy TCP options are not proof of an attack.",
    "DECODE_TCPOPT_EXPERIMENTAL": "Experimental TCP options can be valid.",
    "DECODE_TCPOPT_WSCALE_INVALID": "RFC 7323 receivers clamp an excessive shift count to 14.",
    "DECODE_BAD_TRAFFIC_SAME_SRCDST": "Equal addresses depend on capture topology.",
    "DECODE_ICMP_ORIG_PAYLOAD_GT_576": "Extended ICMP error messages can exceed legacy sizes.",
    "DECODE_IPV6_BAD_OPT_TYPE": "Unrecognized IPv6 option handling depends on option action bits.",
    "DECODE_IPV6_BAD_NEXT_HEADER": "Pinned decoder omits supported AH from its base-header validity list. Required SID 9201011 preserves its prior rejection set except AH; AH framing is checked separately.",
    "DECODE_IPV6_BAD_MULTICAST_SCOPE": "Scope assignments can evolve; not an authorization policy.",
    "DECODE_IPV6_TWO_ROUTE_HEADERS": "Extension-header repetition is not universally forbidden by RFC 8200.",
    "DECODE_IPV6_DSTOPTS_WITH_ROUTING": "IPv6 extension ordering alone is not universal invalidity.",
    "DECODE_IPV6_UNORDERED_EXTENSIONS": "RFC 8200 receivers accept most extension orders.",
    "DECODE_ICMPV6_UNREACHABLE_NON_RFC_2463_CODE": "Legacy RFC 2463 code heuristic; later standards add codes.",
    "DECODE_ICMPV6_UNREACHABLE_NON_RFC_4443_CODE": "ICMPv6 code registries can evolve.",
    "DECODE_ICMPV6_SOLICITATION_BAD_RESERVED": "RFC 4861 reserved fields are ignored by receivers.",
    "DECODE_ICMPV6_ADVERT_BAD_REACHABLE": "Router advertisement timing policy needs local network context.",
    "DECODE_IP4_SRC_THIS_NET": "DHCP and bootstrapping can use unspecified source addresses.",
    "DECODE_IP4_DST_THIS_NET": "Address validity depends on local topology and bootstrapping.",
    "DECODE_IP4_SRC_RESERVED": "Reserved-address registry and lab traffic need deployment context.",
    "DECODE_IP4_DST_RESERVED": "Reserved-address registry and lab traffic need deployment context.",
    "DECODE_IP4_DST_BROADCAST": "Broadcast is valid network traffic.",
    "DECODE_ICMP4_DST_MULTICAST": "Multicast ICMP can be legitimate network control.",
    "DECODE_ICMP4_DST_BROADCAST": "Broadcast ICMP policy is deployment-specific.",
    "DECODE_ICMP4_TYPE_OTHER": "Unimplemented ICMP types are not automatically malicious.",
    "DECODE_TCP_BAD_URP": "RFC 9293 urgent information can extend beyond one segment; endpoint support differs.",
    "DECODE_ICMP6_TYPE_OTHER": "Unimplemented ICMPv6 types are not automatically malicious.",
    "DECODE_ICMP6_DST_MULTICAST": "Neighbor Discovery and other IPv6 control traffic use multicast.",
    "DECODE_ICMP_PING_NMAP": "Fingerprint heuristic can coincide with legitimate echo traffic.",
    "DECODE_ICMP_ICMPENUM": "Fingerprint heuristic can coincide with legitimate echo traffic.",
    "DECODE_ICMP_REDIRECT_HOST": "Redirect policy depends on network design.",
    "DECODE_ICMP_REDIRECT_NET": "Redirect policy depends on network design.",
    "DECODE_ICMP_TRACEROUTE_IPOPTS": "Traceroute is not inherently hostile.",
    "DECODE_ICMP_BROADSCAN_SMURF_SCANNER": "Fingerprint heuristic needs local traffic context.",
    "DECODE_ICMP_DST_UNREACH_ADMIN_PROHIBITED": "Valid network error feedback.",
    "DECODE_ICMP_DST_UNREACH_DST_HOST_PROHIBITED": "Valid network error feedback.",
    "DECODE_ICMP_DST_UNREACH_DST_NET_PROHIBITED": "Valid network error feedback.",
    "DECODE_IP_OPTION_SET": "IPv4 options are legal; endpoint policy may separately prohibit them.",
    "DECODE_UDP_LARGE_PACKET": "UDP payloads above 4000 bytes can be valid.",
    "DECODE_IP_UNASSIGNED_PROTO": "Unknown protocol is not an egress authorization decision.",
    "DECODE_IPV6_SRC_RESERVED": "IPv6 address allocation evolves; local policy must authorize addresses.",
    "DECODE_IPV6_DST_RESERVED": "IPv6 address allocation evolves; local policy must authorize addresses.",
    "STREAM_TCP_DATA_ON_SYN": "TCP Fast Open permits data on SYN; compatibility requires endpoint review.",
    "STREAM_TCP_SMALL_SEGMENT": "Small segments can be legitimate; detector left disabled by default.",
    "STREAM_TCP_4WAY_HANDSHAKE": "TCP simultaneous open can be legitimate.",
}

DROP_REASON = {
    "DECODE_IPV6_BAD_FRAG_PKT": "This decoder event flags every atomic IPv6 fragment (offset=0, M=0). Strict deployment policy drops them all, including valid non-ND traffic; this is broader than RFC 6980.",
    "DECODE_ICMPV6_TOO_BIG_BAD_MTU": "RFC 8201 section 4 requires discarding Packet Too Big messages below the IPv6 minimum MTU.",
    "DECODE_IP_MULTIPLE_ENCAPSULATION": "Deployment policy permits one IP layer; legitimate IP tunnels need a different reviewed policy.",
    "DECODE_IP6_EXCESS_EXT_HDR": "Deployment inspection budget permits eight IPv6 extension headers, not an RFC universal maximum.",
    "DECODE_TOO_MANY_LAYERS": "Deployment inspection budget permits sixteen decoded layers, not an RFC universal maximum.",
    "DEFRAG_EXCESSIVE_OVERLAP": "Configured fragment overlap budget, not a universal protocol maximum.",
    "STREAM_TCP_EXCESSIVE_TCP_OVERLAPS": "Configured TCP overlap budget, not a universal protocol maximum.",
    "STREAM_TCP_NO_3WHS": "Requires visibility of a full handshake from startup; already-open or asymmetric sessions are outside this policy.",
    "STREAM_TCP_MAX_QUEUED_BYTES_EXCEEDED": "Configured per-direction reassembly queue budget exceeded.",
    "STREAM_TCP_MAX_QUEUED_SEGS_EXCEEDED": "Configured per-direction segment queue budget exceeded.",
}


def run(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout


def no_comments(text):
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)


def derive(upstream, snort):
    if run("git", "-C", str(upstream), "rev-parse", "HEAD").strip() != COMMIT:
        raise ValueError("official source checkout must be pinned to " + COMMIT)
    run("git", "-C", str(upstream), "diff", "--exit-code", "HEAD", "--", "src")
    version = run(str(snort), "--dump-version").strip()
    if version != VERSION:
        raise ValueError(f"requires Snort {VERSION}, got {version!r}")
    constants = {}
    enum_text = no_comments((upstream / "src/codecs/codec_module.h").read_text())
    enum_text = re.search(r"enum CodecSid[^\{]*\{(.*?)\};", enum_text, re.S).group(1)
    value = -1
    for token in enum_text.split(","):
        match = re.fullmatch(r"\s*(\w+)\s*(?:=\s*(\d+))?\s*", token)
        if not match:
            if token.strip():
                raise ValueError("unrecognized source enum: " + token)
            continue
        value = int(match[2]) if match[2] else value + 1
        constants[match[1]] = value
    for filename in ("src/stream/ip/ip_module.h", "src/stream/tcp/tcp_module.h"):
        constants.update({key: int(value) for key, value in re.findall(
            r"^\s*#define\s+(\w+)\s+(\d+)\b", no_comments((upstream / filename).read_text()), re.M)})

    files = sorted((upstream / "src/codecs").rglob("*.cc")) + [
        upstream / "src/stream/ip/ip_module.cc", upstream / "src/stream/tcp/tcp_module.cc"]
    source_events = {}
    source_hashes = {}
    for path in files:
        contents = path.read_text()
        rel = path.relative_to(upstream).as_posix()
        maps = list(re.finditer(r"(?:static\s+)?const RuleMap \w+\[\]\s*=\s*\{(.*?)\n\};", contents, re.S))
        for rule_map in maps:
            for symbol in re.findall(r"\{\s*((?:DECODE_|DEFRAG_|STREAM_TCP_)\w+)\s*,", rule_map[1]):
                gid = 116 if symbol.startswith("DECODE_") else 123 if symbol.startswith("DEFRAG_") else 129
                key = (gid, constants[symbol])
                if key in source_events:
                    raise ValueError(f"duplicate source event {key}")
                source_events[key] = (symbol, rel)
                source_hashes[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    for filename in ("src/codecs/codec_module.h", "src/codecs/ip/cd_frag.cc",
                     "src/stream/ip/ip_module.h", "src/stream/tcp/tcp_module.h",
                     "src/events/sfeventq.cc", "src/detection/detection_engine.cc",
                     "src/detection/fp_detect.cc", "src/main/modules.cc",
                     "src/parser/parser.cc", "src/parser/parse_rule.cc",
                     "src/managers/module_manager.cc", "src/framework/codec.cc",
                     "src/protocols/ipv6.h", "src/protocols/protocol_ids.h"):
        source_hashes[filename] = hashlib.sha256((upstream / filename).read_bytes()).hexdigest()

    entries = []
    runtime_keys = set()
    for line in run(str(snort), "--dump-builtin-rules").splitlines():
        match = re.fullmatch(r'alert \( gid:(\d+); sid:(\d+); msg:"\(([^)]+)\) (.*)"; \)', line)
        if not match:
            raise ValueError("unexpected builtin output: " + line)
        gid, sid = int(match[1]), int(match[2])
        if gid not in (116, 123, 129):
            continue
        key = gid, sid
        if key in runtime_keys:
            raise ValueError(f"duplicate runtime event {key}")
        runtime_keys.add(key)
        symbol, rel = source_events[key]
        action = "alert" if symbol in ALERT else "drop"
        entries.append({"gid": gid, "sid": sid, "module": match[3], "symbol": symbol,
                        "message": match[4], "action": action, "enabled": True,
                        "reason": ALERT.get(symbol, DROP_REASON.get(symbol, "Strict packet/stream anomaly policy; not a claim of universal RFC invalidity.")),
                        "source": rel,
                        "source_url": f"https://github.com/snort3/snort3/blob/{COMMIT}/{rel}"})
    if runtime_keys != source_events.keys():
        raise ValueError(f"source/runtime event mismatch: {source_events.keys() ^ runtime_keys}")
    unknown = (set(ALERT) | set(DROP_REASON)) - {entry["symbol"] for entry in entries}
    if unknown:
        raise ValueError(f"unmatched alert exceptions: {unknown}")
    entries.sort(key=lambda entry: (entry["gid"], entry["sid"]))
    manifest = {"snort_version": VERSION, "source_commit": COMMIT,
                "source_repository": "https://github.com/snort3/snort3",
                "generator": "generate_inventory.py", "source_sha256": source_hashes,
                "selective_builtin_loading": {
                    "enable_builtin_rules": False,
                    "rules_file": "protocol-builtins.rules",
                    "behavior": "Only selected builtin OTNs are loaded as explicit headerless rules. DetectionEngine::queue_event(gid,sid) returns before queue allocation when OtnLookup finds no rule; disabled unrelated builtins therefore cannot consume this profile's event queue.",
                    "source_files": ["src/parser/parser.cc", "src/parser/parse_rule.cc",
                                     "src/managers/module_manager.cc", "src/detection/detection_engine.cc"]},
                "atomic_fragment_provenance": {
                    "source": "src/codecs/ip/cd_frag.cc",
                    "source_url": f"https://github.com/snort3/snort3/blob/{COMMIT}/src/codecs/ip/cd_frag.cc",
                    "behavior": "Ipv6FragCodec::decode queues DECODE_IPV6_BAD_FRAG_PKT (116:458) when fragment offset and M flag are both zero; this is independent of payload length and protocol."},
                "scope": "All registered GID 116 decoder, GID 123 stream_ip and GID 129 stream_tcp events in this release.",
                "counts": {action: sum(entry["action"] == action for entry in entries) for action in ("drop", "alert")},
                "rules": entries}
    states = f"# Generated for Snort {VERSION}, source commit {COMMIT}.\n"
    states += "# States override builtin actions; enable is required. See builtin-inventory.json.\n"
    rules = f"# Generated for Snort {VERSION}, source commit {COMMIT}.\n"
    rules += "# Explicit selected builtins only; global builtin loading must remain disabled.\n"
    for entry in entries:
        states += f'# {entry["symbol"]}: {entry["message"]}\n'
        states += f'{entry["action"]} ( gid:{entry["gid"]}; sid:{entry["sid"]}; enable:yes; )\n'
        message = f'({entry["module"]}) {entry["message"]}'.replace('\\', '\\\\').replace('"', '\\"')
        rules += (f'{entry["action"]} ( gid:{entry["gid"]}; sid:{entry["sid"]}; '
                  f'msg:"{message}"; rev:1; priority:3; )\n')
    return {"builtin-inventory.json": json.dumps(manifest, indent=2) + "\n",
            "protocol.states": states, "protocol-builtins.rules": rules}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--snort", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    for filename, data in derive(args.upstream.resolve(), args.snort.resolve()).items():
        path = HERE / filename
        if args.check:
            if not path.exists() or path.read_text() != data:
                raise SystemExit(f"generated file differs: {path}")
        else:
            path.write_text(data)
    print("Pinned builtin source/runtime inventory and explicit states agree.")


if __name__ == "__main__":
    main()
