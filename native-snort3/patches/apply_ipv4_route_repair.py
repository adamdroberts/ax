#!/usr/bin/env python3
"""Repair IPv4 source-route checksums after the Type 2 and fragment repairs.

Only modifies a separate source copy with the exact reviewed prior repairs.
Does not build, install, deploy, open interfaces, or transmit packets.
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import subprocess

import apply_type2_repair as type2
import apply_fragment_checksum_repair as fragment

HERE = Path(__file__).resolve().parent
FILES = ("src/codecs/ip/cd_tcp.cc", "src/codecs/ip/cd_udp.cc")
HEADER = "src/codecs/ip/ipv4_checksum_destination.h"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def patched(relative, original):
    source = original.decode()
    source = type2.replace_once(source, '#include "ipv6_checksum_destination.h"',
                               '#include "ipv6_checksum_destination.h"\n#include "ipv4_checksum_destination.h"')
    before = "    ph.hdr.dip = ip4h->get_dst();"
    source = type2.replace_once(source, before,
        "    const auto* final = ax_checksum::ipv4_destination(\n"
        "        reinterpret_cast<const uint8_t*>(ip4h), raw.data);\n"
        "    if (!final)\n"
        "        return false;\n"
        "    memcpy(&ph.hdr.dip, final, sizeof(ph.hdr.dip));")
    before = "            ps.hdr.dip = ip4h->get_dst();"
    source = type2.replace_once(source, before, before + "\n"
        "            if (const auto* final = ax_checksum::ipv4_destination(\n"
        "                    reinterpret_cast<const uint8_t*>(ip4h), raw_pkt))\n"
        "                memcpy(&ps.hdr.dip, final, sizeof(ps.hdr.dip));")
    # A malformed route is an IPv4 option error, independently of transport
    # checksum policy or IPv4 UDP checksum omission. Keep its event/counters
    # separate from transport checksum failures.
    protocol = "tcp" if relative.endswith("cd_tcp.cc") else "udp"
    before = "    if (snort::get_network_policy()->" + protocol + "_checksums() &&"
    source = type2.replace_once(source, before,
        "    if (snort.ip_api.is_ip4() && snort.ip_api.get_ip4h()->has_options() &&\n"
        "        !ax_checksum::ipv4_destination(\n"
        "            reinterpret_cast<const uint8_t*>(snort.ip_api.get_ip4h()), raw.data))\n"
        "    {\n"
        "        codec_event(codec, DECODE_IPV4OPT_BADLEN);\n"
        "        return false;\n"
        "    }\n\n" + before)
    # Generic DAQ checksum metadata does not describe source-route support.
    # With options, calculate the checksum rather than trusting a base-address
    # checksum indication.
    source = type2.replace_once(source,
        "        (codec.is_cooked() || !valid_checksum_from_daq(raw)))",
        "        (codec.is_cooked() ||\n"
        "         (snort.ip_api.is_ip4() && snort.ip_api.get_ip4h()->has_options()) ||\n"
        "         !valid_checksum_from_daq(raw)))")
    return source.encode()


def apply(upstream, target):
    upstream, target = upstream.resolve(strict=True), target.resolve(strict=True)
    if upstream == target or upstream in target.parents or target in upstream.parents:
        raise ValueError("target must be a separate source copy")
    commit = subprocess.check_output(["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True).strip()
    if commit != type2.COMMIT:
        raise ValueError("not the reviewed Snort commit")
    originals = {}
    for relative in fragment.FILES:
        clean = subprocess.check_output(["git", "-C", str(upstream), "show", "HEAD:" + relative])
        if (upstream / relative).read_bytes() != clean:
            raise ValueError("upstream changed: " + relative)
        prior = type2.patched(relative, clean) if relative in type2.FILES else clean
        prior = fragment.patched(relative, prior)
        if (target / relative).read_bytes() != prior:
            raise ValueError("target must contain exactly the Type 2 and fragment repairs: " + relative)
        if relative in FILES:
            originals[relative] = prior
    if (target / "src/codecs/ip/ipv6_checksum_destination.h").read_bytes() != (HERE / "ipv6_checksum_destination.h").read_bytes():
        raise ValueError("prior Type 2 helper changed")
    if (target / HEADER).exists():
        raise ValueError("IPv4 helper already exists")
    updates = {name: patched(name, data) for name, data in originals.items()}
    updates[HEADER] = (HERE / "ipv4_checksum_destination.h").read_bytes()
    patch = "".join("".join(difflib.unified_diff(
        originals.get(name, b"").decode().splitlines(keepends=True), data.decode().splitlines(keepends=True),
        fromfile="a/" + name if name in originals else "/dev/null", tofile="b/" + name))
        for name, data in updates.items())
    for name in updates:
        if not (target / name).resolve().is_relative_to(target):
            raise ValueError("target path escapes source copy")
    report = {"upstream_commit": commit, "requires": "Reviewed Type 2 and fragment checksum repairs",
              "scope": "Local source changes only; separate build and actual inline replay required.",
              "before_sha256": {name: digest(data) for name, data in originals.items()},
              "after_sha256": {name: digest(data) for name, data in updates.items()},
              "local_source_sha256": {path.name: digest(path.read_bytes()) for path in
                                      (Path(__file__), HERE / "apply_type2_repair.py",
                                       HERE / "apply_fragment_checksum_repair.py",
                                       HERE / "ipv4_checksum_destination.h", HERE / "ipv6_checksum_destination.h")},
              "patch_sha256": digest(patch.encode())}
    for name, data in updates.items():
        (target / name).write_bytes(data)
    (target / "ax-ipv4-route-checksum.patch").write_text(patch)
    (target / "ax-ipv4-route-source-validation.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--target-source", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(apply(args.upstream, args.target_source), indent=2))


if __name__ == "__main__":
    main()
