#!/usr/bin/env python3
"""Reject prohibited overlaps before reassembly mutation and free fragment buffers."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import subprocess

import apply_ipv4_prefix_repair as ipv4

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
FILES = ("src/stream/ip/ip_defrag.cc", "src/stream/ip/ip_module.h",
         "src/stream/ip/ip_session.cc", "src/stream/ip/ip_module.cc")
HELPERS = {}
COMMIT = ipv4.COMMIT


def digest(data):
    return hashlib.sha256(data).hexdigest()


def prior_source(relative, clean):
    prior = ipv4.prior_source(relative, clean)
    return ipv4.patched(relative, prior) if relative in ipv4.FILES else prior


OVERLAP_GUARD = """    // RFC 8200 abandons an IPv6 datagram on any overlap. IPv4's configured
    // threshold of one requests the same strict local policy. Test before
    // first/last bookkeeping, prefix capture, trimming or node allocation.
    if ((p->is_ip6() || fe->max_overlaps == 1) && p->dsize)
    {
        const uint32_t end = static_cast<uint32_t>(net_frag_offset) + p->dsize;
        for (const Fragment* saved = ft->fraglist; saved && saved->offset < end; saved = saved->next)
        {
            if (saved->size && net_frag_offset < static_cast<uint32_t>(saved->offset) + saved->size)
            {
                ip_stats.overlaps++;
                ft->overlap_count++;
                EventAnomOverlap(fe);
                ft->frag_flags |= FRAG_BAD | FRAG_DROP_FRAGMENTS | FRAG_OVERLAP_BAD;
                return FRAG_INSERT_OVERLAP_REJECTED;
            }
        }
    }

"""


def patched(relative, original):
    source = original.decode()
    replace = ipv4.ipv6.home.pressure.lifetime.options.type2.replace_once
    if relative.endswith("ip_module.h"):
        return replace(source, "    PegCount ecn_drops;", "    PegCount ecn_drops;\n    PegCount overlap_drops;").encode()
    if relative.endswith("ip_session.cc"):
        return replace(source, '    { CountType::END, nullptr, nullptr }',
            '    { CountType::SUM, "overlap_drops", "fragments rejected after a prohibited overlap" },\n'
            '    { CountType::END, nullptr, nullptr }').encode()
    if relative.endswith("ip_module.cc"):
        return replace(source, '"maximum allowed overlaps per datagram; 0 is unlimited"',
            '"IPv4 overlap threshold; 0 is unlimited, 1 rejects first overlap; IPv6 always rejects overlaps"').encode()
    source = replace(source, "#define FRAG_ECN_BAD        0x00000400",
        "#define FRAG_ECN_BAD        0x00000400\n#define FRAG_OVERLAP_BAD    0x00000800")
    source = replace(source, "#define FRAG_INSERT_PREFIX_INVALID 9",
        "#define FRAG_INSERT_PREFIX_INVALID 9\n#define FRAG_INSERT_OVERLAP_REJECTED 10")
    source = replace(source, "    if (ft->frag_flags & FRAG_ECN_BAD)\n",
        "    if (ft->frag_flags & FRAG_OVERLAP_BAD)\n    {\n"
        '        p->active->set_drop_reason("ip_reassembly_overlap");\n'
        "        ip_stats.overlap_drops++;\n    }\n"
        "    else if (ft->frag_flags & FRAG_ECN_BAD)\n")
    source = replace(source, "        case FRAG_INSERT_PREFIX_INVALID:\n",
        "        case FRAG_INSERT_OVERLAP_REJECTED:\n        case FRAG_INSERT_PREFIX_INVALID:\n")
    option_guard = "    if (p->is_ip4() && !FragHandleIPOptions(ft, p, net_frag_offset))\n        return FRAG_INSERT_ANOMALY;\n\n"
    # An existing IPv4 option rejection must retain its reason on every retry.
    # Options are validated first; any temporary option storage is freed by the
    # overlap-rejection cleanup before a payload node can be inserted.
    source = replace(source, option_guard, option_guard + OVERLAP_GUARD)
    return source.encode()


def apply(upstream, target):
    upstream, target = upstream.resolve(strict=True), target.resolve(strict=True)
    if upstream == target or upstream in target.parents or target in upstream.parents:
        raise ValueError("target must be a separate source copy")
    commit = subprocess.check_output(["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True).strip()
    if commit != COMMIT:
        raise ValueError("not the reviewed upstream commit")
    ipv6 = ipv4.ipv6
    home = ipv6.home
    pressure, lifetime, opts = home.pressure, home.pressure.lifetime, home.pressure.lifetime.options
    originals = {}
    for relative in dict.fromkeys((*opts.fragment.FILES, *opts.FILES, *lifetime.FILES, *pressure.FILES,
                                  *home.FILES, *ipv6.FILES, *ipv4.FILES, *FILES)):
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
        "apply_home_address_repair.py", "apply_ipv6_prefix_repair.py", "apply_ipv4_prefix_repair.py")]]
    report = {"upstream_commit": commit, "requires": "All preceding repairs through IPv4 header/ECN/size",
              "scope": "Separate local source copy only; native build and replay required.",
              "before_sha256": {name: digest(data) for name, data in originals.items()},
              "after_sha256": {name: digest(data) for name, data in updates.items()},
              "local_source_sha256": {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in local},
              "patch_sha256": digest(patch.encode())}
    for name, data in updates.items():
        (target / name).write_bytes(data)
    (target / "ax-fragment-overlap.patch").write_text(patch)
    (target / "ax-fragment-overlap-source-validation.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--target-source", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(apply(args.upstream, args.target_source), indent=2))


if __name__ == "__main__":
    main()
