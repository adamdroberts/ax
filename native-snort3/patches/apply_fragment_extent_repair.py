#!/usr/bin/env python3
"""Reject contradictory fragment lengths and require contiguous reconstruction."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import subprocess

import apply_fragment_overlap_repair as overlap

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
FILES = ("src/stream/ip/ip_defrag.cc", "src/stream/ip/ip_module.h",
         "src/stream/ip/ip_session.cc", "src/stream/ip/ip_session.h")
HELPERS = {"src/stream/ip/fragment_extent.h": HERE / "fragment_extent.h"}
COMMIT = overlap.COMMIT


def digest(data):
    return hashlib.sha256(data).hexdigest()


def prior_source(relative, clean):
    prior = overlap.prior_source(relative, clean)
    return overlap.patched(relative, prior) if relative in overlap.FILES else prior


EXTENT_OBSERVER = """static bool ObserveFragmentExtent(FragTracker* ft, Packet* p, uint16_t offset)
{
    if (ax_fragment::observe_extent(ft->extent, offset, p->dsize,
        p->ptrs.decode_flags & DECODE_MF))
        return true;
    EventAnomOversize(ft->engine);
    ft->frag_flags |= FRAG_BAD | FRAG_DROP_FRAGMENTS | FRAG_EXTENT_BAD;
    return false;
}

"""

COMPLETE_CHECK = """static inline int FragIsComplete(FragTracker* ft)
{
    if (!(ft->frag_flags & FRAG_GOT_FIRST) || !(ft->frag_flags & FRAG_GOT_LAST) ||
        !ft->extent.final_seen || ft->calculated_size != ft->extent.final_end ||
        !ax_fragment::complete_ranges(ft->fraglist, ft->extent.final_end))
        return 0;
    ip_stats.trackers_completed++;
    return 1;
}
"""


def patched(relative, original):
    source = original.decode()
    replace = overlap.ipv4.ipv6.home.pressure.lifetime.options.type2.replace_once
    if relative.endswith("ip_module.h"):
        return replace(source, "    PegCount overlap_drops;", "    PegCount overlap_drops;\n    PegCount extent_drops;").encode()
    if relative.endswith("ip_session.cc"):
        return replace(source, '    { CountType::END, nullptr, nullptr }',
            '    { CountType::SUM, "extent_drops", "fragments rejected after contradictory datagram length" },\n'
            '    { CountType::END, nullptr, nullptr }').encode()
    if relative.endswith("ip_session.h"):
        source = replace(source, '#include "ipv4_fragment_prefix.h"',
            '#include "ipv4_fragment_prefix.h"\n#include "fragment_extent.h"')
        return replace(source, '    ax_fragment::Ip4Prefix ip4_prefix;',
            '    ax_fragment::Ip4Prefix ip4_prefix;\n    ax_fragment::Extent extent;').encode()
    source = replace(source, "#define FRAG_OVERLAP_BAD    0x00000800",
        "#define FRAG_OVERLAP_BAD    0x00000800\n#define FRAG_EXTENT_BAD     0x00001000")
    source = replace(source, "#define FRAG_INSERT_OVERLAP_REJECTED 10",
        "#define FRAG_INSERT_OVERLAP_REJECTED 10\n#define FRAG_INSERT_EXTENT_INVALID 11")
    source = replace(source, "    if (ft->frag_flags & FRAG_OVERLAP_BAD)\n",
        "    if (ft->frag_flags & FRAG_EXTENT_BAD)\n    {\n"
        '        p->active->set_drop_reason("ip_reassembly_extent");\n'
        "        ip_stats.extent_drops++;\n    }\n"
        "    else if (ft->frag_flags & FRAG_OVERLAP_BAD)\n")
    source = replace(source, "        case FRAG_INSERT_OVERLAP_REJECTED:\n",
        "        case FRAG_INSERT_EXTENT_INVALID:\n        case FRAG_INSERT_OVERLAP_REJECTED:\n")
    source = replace(source, "    ft->ip4_prefix = {};", "    ft->ip4_prefix = {};\n    ft->extent = {};")
    source = replace(source, "static inline bool frag_timed_out(", EXTENT_OBSERVER + "static inline bool frag_timed_out(")
    guard = "    if (p->is_ip6() && !CaptureIp6Prefix(ft, p, net_frag_offset))\n        return FRAG_INSERT_PREFIX_INVALID;\n"
    source = replace(source, guard, guard + "\n    if (!ObserveFragmentExtent(ft, p, net_frag_offset))\n        return FRAG_INSERT_EXTENT_INVALID;\n")
    guard = "    if (p->is_ip6() && !CaptureIp6Prefix(ft, p, frag_off))\n    {\n        ip_stats.discards++;\n        return 1;\n    }\n"
    source = replace(source, guard, guard + "\n    if (!ObserveFragmentExtent(ft, p, frag_off))\n    {\n        delete_tracker(ft);\n        ip_stats.discards++;\n        return 1;\n    }\n")
    start = source.index("static inline int FragIsComplete(FragTracker* ft)")
    end = source.index("\n/*\n * Reassemble the packet", start)
    previous = source[start:end]
    assert "ft->frag_bytes > ft->calculated_size" in previous
    source = replace(source, previous, COMPLETE_CHECK)
    return source.encode()


def apply(upstream, target):
    upstream, target = upstream.resolve(strict=True), target.resolve(strict=True)
    if upstream == target or upstream in target.parents or target in upstream.parents:
        raise ValueError("target must be a separate source copy")
    commit = subprocess.check_output(["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True).strip()
    if commit != COMMIT:
        raise ValueError("not the reviewed upstream commit")
    ipv4 = overlap.ipv4
    ipv6 = ipv4.ipv6
    home = ipv6.home
    pressure, lifetime, opts = home.pressure, home.pressure.lifetime, home.pressure.lifetime.options
    originals = {}
    for relative in dict.fromkeys((*opts.fragment.FILES, *opts.FILES, *lifetime.FILES, *pressure.FILES,
                                  *home.FILES, *ipv6.FILES, *ipv4.FILES, *overlap.FILES, *FILES)):
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
               "src/codecs/ip/ipv6_checksum_destination.h": HERE / "ipv6_checksum_destination.h", **ipv6.HELPERS, **ipv4.HELPERS}
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
        "apply_home_address_repair.py", "apply_ipv6_prefix_repair.py", "apply_ipv4_prefix_repair.py",
        "apply_fragment_overlap_repair.py")]]
    report = {"upstream_commit": commit, "requires": "All preceding repairs through fragment overlap rejection",
              "scope": "Separate local source copy only; native build and replay required.",
              "before_sha256": {name: digest(data) for name, data in originals.items()},
              "after_sha256": {name: digest(data) for name, data in updates.items()},
              "local_source_sha256": {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in local},
              "patch_sha256": digest(patch.encode())}
    for name, data in updates.items():
        (target / name).write_bytes(data)
    (target / "ax-fragment-extent.patch").write_text(patch)
    (target / "ax-fragment-extent-source-validation.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--target-source", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(apply(args.upstream, args.target_source), indent=2))


if __name__ == "__main__":
    main()
