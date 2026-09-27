#!/usr/bin/env python3
"""Require complete-datagram checksum checks after IP fragment reassembly.

Apply after the reviewed Type 2 repair, to a separate source copy. No build,
system installation, interface changes, or packet transmission is performed.
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import subprocess

import apply_type2_repair as type2

HERE = Path(__file__).resolve().parent
FILES = (*type2.FILES, "src/codecs/ip/cd_icmp4.cc")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def patched(relative, original):
    source = original.decode()
    protocol = "tcp" if relative.endswith("cd_tcp.cc") else "udp" if relative.endswith("cd_udp.cc") else "icmp"
    before = "get_network_policy()->" + protocol + "_checksums() && !valid_checksum_from_daq(raw)"
    source = type2.replace_once(source, before,
        "get_network_policy()->" + protocol + "_checksums() &&\n"
        "        (codec.is_cooked() || !valid_checksum_from_daq(raw))")
    # The only cooked decode entry point in this pinned source is IP fragment
    # reassembly. It contains a complete original transport datagram. Its DAQ
    # message belongs to a parent fragment and cannot attest this checksum.
    if protocol == "udp":
        source = type2.replace_once(source, "if (!valid && !codec.is_cooked())", "if (!valid)")
    elif protocol == "icmp":
        source = type2.replace_once(source, "if (csum && !codec.is_cooked())", "if (csum)")
    return source.encode()


def apply(upstream, target):
    upstream, target = upstream.resolve(strict=True), target.resolve(strict=True)
    if upstream == target or upstream in target.parents or target in upstream.parents:
        raise ValueError("target must be a separate source copy")
    commit = subprocess.check_output(["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True).strip()
    if commit != type2.COMMIT:
        raise ValueError("not the reviewed Snort commit")
    originals = {}
    for relative in FILES:
        pristine = subprocess.check_output(["git", "-C", str(upstream), "show", "HEAD:" + relative])
        if (upstream / relative).read_bytes() != pristine:
            raise ValueError("upstream changed: " + relative)
        expected = type2.patched(relative, pristine) if relative in type2.FILES else pristine
        if (target / relative).read_bytes() != expected:
            raise ValueError("target must contain exactly the prior Type 2 repair: " + relative)
        originals[relative] = expected
    if (target / "src/codecs/ip/ipv6_checksum_destination.h").read_bytes() != (HERE / "ipv6_checksum_destination.h").read_bytes():
        raise ValueError("prior Type 2 helper changed")
    updates = {relative: patched(relative, data) for relative, data in originals.items()}
    patch = "".join("".join(difflib.unified_diff(originals[relative].decode().splitlines(keepends=True),
                                              data.decode().splitlines(keepends=True),
                                              fromfile="a/" + relative, tofile="b/" + relative))
                    for relative, data in updates.items())
    for relative in updates:
        if not (target / relative).resolve().is_relative_to(target):
            raise ValueError("target path escapes source copy")
    report = {"upstream_commit": commit, "requires": "Reviewed Type 2 checksum source repair",
              "scope": "Source changes only; build and actual inline fragment replay are required.",
              "before_sha256": {name: digest(data) for name, data in originals.items()},
              "after_sha256": {name: digest(data) for name, data in updates.items()},
              "local_source_sha256": {path.name: digest(path.read_bytes()) for path in
                                      (Path(__file__), HERE / "apply_type2_repair.py", HERE / "ipv6_checksum_destination.h")},
              "patch_sha256": digest(patch.encode())}
    for relative, data in updates.items():
        (target / relative).write_bytes(data)
    (target / "ax-fragment-checksum.patch").write_text(patch)
    (target / "ax-fragment-source-validation.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--target-source", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(apply(args.upstream, args.target_source), indent=2))


if __name__ == "__main__":
    main()
