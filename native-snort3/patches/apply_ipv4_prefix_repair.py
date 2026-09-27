#!/usr/bin/env python3
"""Preserve IPv4 first headers and enforce reassembly ECN and total size bounds."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import subprocess

import apply_ipv6_prefix_repair as ipv6

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
FILES = ("src/stream/ip/ip_defrag.cc", "src/stream/ip/ip_session.h")
HELPERS = {"src/stream/ip/ipv4_fragment_prefix.h": HERE / "ipv4_fragment_prefix.h",
           "src/stream/ip/ipv4_fragment_prefix.inc": HERE / "ipv4_fragment_prefix.inc"}
COMMIT = ipv6.COMMIT


def digest(data):
    return hashlib.sha256(data).hexdigest()


def prior_source(relative, clean):
    prior = ipv6.prior_source(relative, clean)
    return ipv6.patched(relative, prior) if relative in ipv6.FILES else prior


def patched(relative, original):
    source = original.decode()
    replace = ipv6.home.pressure.lifetime.options.type2.replace_once
    if relative.endswith("ip_session.h"):
        source = replace(source, '#include "ipv4_fragment_options.h"',
                         '#include "ipv4_fragment_options.h"\n#include "ipv4_fragment_prefix.h"')
        return replace(source, "    bool ip_options_first_seen;", "    bool ip_options_first_seen;\n"
                       "    ax_fragment::Ip4Prefix ip4_prefix;").encode()
    source = replace(source, '#include "ipv6_fragment_prefix.inc"',
                     '#include "ipv6_fragment_prefix.inc"\n#include "ipv4_fragment_prefix.inc"')
    source = replace(source, "        (p->is_ip6() && !RestoreIp6Prefix(ft, dpkt)))",
                     "        (p->is_ip6() && !RestoreIp6Prefix(ft, dpkt)) ||\n"
                     "        (p->is_ip4() && !RestoreIp4Prefix(ft, dpkt)))")
    source = replace(source, "    ft->ip6_ecn_seen = 0;", "    ft->ip6_ecn_seen = 0;\n    ft->ip4_prefix = {};")
    source = replace(source, 'set_drop_reason("ip6_reassembly_ecn")', 'set_drop_reason("ip_reassembly_ecn")')
    source = replace(source, "    if (p->is_ip6() && !CaptureIp6Prefix(ft, p, net_frag_offset))",
                     "    if (p->is_ip4() && !CaptureIp4Prefix(ft, p, net_frag_offset))\n"
                     "        return FRAG_INSERT_PREFIX_INVALID;\n\n"
                     "    if (p->is_ip6() && !CaptureIp6Prefix(ft, p, net_frag_offset))")
    source = replace(source, "    if (p->is_ip6() && !CaptureIp6Prefix(ft, p, frag_off))",
                     "    if (p->is_ip4() && !CaptureIp4Prefix(ft, p, frag_off))\n    {\n"
                     "        ip_stats.discards++;\n        return 1;\n    }\n\n"
                     "    if (p->is_ip6() && !CaptureIp6Prefix(ft, p, frag_off))")
    return source.encode()


def apply(upstream, target):
    upstream, target = upstream.resolve(strict=True), target.resolve(strict=True)
    if upstream == target or upstream in target.parents or target in upstream.parents:
        raise ValueError("target must be a separate source copy")
    commit = subprocess.check_output(["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True).strip()
    if commit != COMMIT:
        raise ValueError("not the reviewed upstream commit")
    home = ipv6.home
    pressure, lifetime, opts = home.pressure, home.pressure.lifetime, home.pressure.lifetime.options
    originals = {}
    for relative in dict.fromkeys((*opts.fragment.FILES, *opts.FILES, *lifetime.FILES, *pressure.FILES,
                                  *home.FILES, *ipv6.FILES, *FILES)):
        clean = subprocess.check_output(["git", "-C", str(upstream), "show", "HEAD:" + relative])
        if (upstream / relative).read_bytes() != clean:
            raise ValueError("upstream changed: " + relative)
        prior = prior_source(relative, clean)
        if (target / relative).read_bytes() != prior:
            raise ValueError("unexpected preceding source: " + relative)
        if relative in FILES:
            originals[relative] = prior
    helpers = {pressure.HEADER: HERE / "fragment_pressure.h", lifetime.HEADER: HERE / "fragment_lifetime.h",
               opts.HEADER: HERE / "ipv4_fragment_options.h", home.HEADER: home.HELPER,
               "src/codecs/ip/ipv4_checksum_destination.h": HERE / "ipv4_checksum_destination.h",
               "src/codecs/ip/ipv6_checksum_destination.h": HERE / "ipv6_checksum_destination.h", **ipv6.HELPERS}
    for relative, path in helpers.items():
        if (target / relative).read_bytes() != path.read_bytes():
            raise ValueError("preceding helper changed: " + relative)
    if any((target / name).exists() for name in HELPERS):
        raise ValueError("prefix helpers already exist")
    updates = {name: patched(name, data) for name, data in originals.items()}
    updates.update({name: path.read_bytes() for name, path in HELPERS.items()})
    patch = "".join("".join(difflib.unified_diff(
        originals.get(name, b"").decode().splitlines(keepends=True), data.decode().splitlines(keepends=True),
        fromfile="a/" + name if name in originals else "/dev/null", tofile="b/" + name))
        for name, data in updates.items())
    for name in updates:
        if not (target / name).resolve().is_relative_to(target):
            raise ValueError("target path escapes source copy")
    local = [Path(__file__), *HELPERS.values(), *helpers.values(), *[HERE / name for name in (
        "apply_type2_repair.py", "apply_fragment_checksum_repair.py", "apply_ipv4_route_repair.py",
        "apply_fragment_options_repair.py", "apply_fragment_lifetime_repair.py", "apply_fragment_pressure_repair.py",
        "apply_home_address_repair.py", "apply_ipv6_prefix_repair.py")]]
    report = {"upstream_commit": commit, "requires": "All preceding repairs through IPv6 prefix/ECN/size",
              "scope": "Separate local source copy only; native build and replay required.",
              "before_sha256": {name: digest(data) for name, data in originals.items()},
              "after_sha256": {name: digest(data) for name, data in updates.items()},
              "local_source_sha256": {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in local},
              "patch_sha256": digest(patch.encode())}
    for name, data in updates.items():
        (target / name).write_bytes(data)
    (target / "ax-ipv4-prefix.patch").write_text(patch)
    (target / "ax-ipv4-prefix-source-validation.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--target-source", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(apply(args.upstream, args.target_source), indent=2))


if __name__ == "__main__":
    main()
