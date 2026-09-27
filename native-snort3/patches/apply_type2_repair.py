#!/usr/bin/env python3
"""Apply the reviewed Type 2 checksum repair to a separate pinned source copy.

Does not modify the upstream checkout, compile, install, or deploy Snort.
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
COMMIT = "14aeb09f5a0856812dbe08ead3c21f99e8860aa0"
FILES = ("src/codecs/ip/cd_tcp.cc", "src/codecs/ip/cd_udp.cc", "src/codecs/ip/cd_icmp6.cc")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise ValueError("reviewed patch context changed: " + repr(before))
    return source.replace(before, after)


def patched(relative, original):
    source = original.decode()
    source = replace_once(source, '#include "checksum.h"',
                          '#include "checksum.h"\n#include "ipv6_checksum_destination.h"')
    indent = "        " if relative.endswith("cd_icmp6.cc") else "    "
    before = indent + "COPY4(ph6.hdr.dip, ip6h->get_dst()->u6_addr32);"
    source = replace_once(source, before, before + "\n" + indent +
        "if (const auto* final = ax_checksum::destination(\n" + indent +
        "        reinterpret_cast<const uint8_t*>(ip6h), raw.data,\n" + indent +
        "        static_cast<uint8_t>(codec.ip6_csum_proto)))\n" + indent +
        "    memcpy(ph6.hdr.dip, final, sizeof(ph6.hdr.dip));")
    protocol = "ICMPV6" if relative.endswith("cd_icmp6.cc") else (
        "TCP" if relative.endswith("cd_tcp.cc") else "UDP")
    if protocol == "ICMPV6":
        before = "        memcpy(ps6.hdr.dip, api.get_dst()->get_ip6_ptr(), sizeof(ps6.hdr.dip));"
        pointer = "api.get_ip6h()"
        indent = "        "
    else:
        before = "            memcpy(ps6.hdr.dip, ip6h->get_dst()->u6_addr32, sizeof(ps6.hdr.dip));"
        pointer = "ip6h"
        indent = "            "
    source = replace_once(source, before, before + "\n" + indent +
        "if (const auto* final = ax_checksum::destination(\n" + indent +
        "        reinterpret_cast<const uint8_t*>(" + pointer + "), raw_pkt,\n" + indent +
        "        static_cast<uint8_t>(IpProtocol::" + protocol + ")))\n" + indent +
        "    memcpy(ps6.hdr.dip, final, sizeof(ps6.hdr.dip));")
    return source.encode()


def apply(upstream, target):
    upstream, target = upstream.resolve(strict=True), target.resolve(strict=True)
    if upstream == target or upstream in target.parents or target in upstream.parents:
        raise ValueError("target must be a separate source copy")
    commit = subprocess.check_output(["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True).strip()
    if commit != COMMIT:
        raise ValueError("upstream is not the reviewed Snort commit")
    originals = {}
    for relative in FILES:
        original = subprocess.check_output(["git", "-C", str(upstream), "show", "HEAD:" + relative])
        if (upstream / relative).read_bytes() != original:
            raise ValueError("upstream source has local changes: " + relative)
        if (target / relative).read_bytes() != original:
            raise ValueError("target is not a clean copy: " + relative)
        originals[relative] = original
    updates = {relative: patched(relative, data) for relative, data in originals.items()}
    header = "src/codecs/ip/ipv6_checksum_destination.h"
    if (target / header).exists():
        raise ValueError("target helper already exists")
    updates[header] = (HERE / "ipv6_checksum_destination.h").read_bytes()
    patch = "".join("".join(difflib.unified_diff(
        originals.get(relative, b"").decode().splitlines(keepends=True),
        data.decode().splitlines(keepends=True),
        fromfile="a/" + relative if relative in originals else "/dev/null",
        tofile="b/" + relative)) for relative, data in updates.items())
    # Resolve and validate every path/context before the first mutation.
    for relative in updates:
        if not (target / relative).resolve().is_relative_to(target):
            raise ValueError("target path escapes the source copy: " + relative)
    for relative, data in updates.items():
        (target / relative).write_bytes(data)
    report = {"upstream_commit": commit,
              "scope": "Local source patch only; separate build and native replay are required.",
              "upstream_sha256": {relative: sha(data) for relative, data in originals.items()},
              "repaired_sha256": {relative: sha(data) for relative, data in updates.items()},
              "local_source_sha256": {path.name: sha(path.read_bytes()) for path in
                                      (Path(__file__), HERE / "ipv6_checksum_destination.h")},
              "patch_sha256": sha(patch.encode())}
    (target / "ax-type2-checksum.patch").write_text(patch)
    (target / "ax-type2-source-validation.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--target-source", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(apply(args.upstream, args.target_source), indent=2))


if __name__ == "__main__":
    main()
