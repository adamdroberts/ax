#!/usr/bin/env python3
"""Preserve offset-zero IPv6 prefixes and aggregate fragment ECN in a source copy."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import re
import subprocess

import apply_home_address_repair as home

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
FILES = ("src/stream/ip/ip_defrag.cc", "src/stream/ip/ip_defrag.h", "src/stream/ip/ip_session.h",
         "src/stream/ip/ip_module.h", "src/stream/ip/ip_session.cc", "src/protocols/packet_manager.cc")
HELPERS = {"src/stream/ip/ipv6_fragment_prefix.h": HERE / "ipv6_fragment_prefix.h",
           "src/stream/ip/ipv6_fragment_prefix.inc": HERE / "ipv6_fragment_prefix.inc"}
COMMIT = home.pressure.lifetime.options.type2.COMMIT


def digest(data):
    return hashlib.sha256(data).hexdigest()


def prior_source(relative, clean):
    prior = home.prior_source(relative, clean)
    return home.patched(relative, prior) if relative in home.FILES else prior


def patched(relative, original):
    source = original.decode()
    replace = home.pressure.lifetime.options.type2.replace_once
    if relative.endswith(("ip_defrag.cc", "ip_defrag.h")):
        # A valid fragment can carry over 32767 bytes. Keep signed overlap
        # adjustments signed, but wide enough for the full IPv6 payload range.
        source = re.sub(r"\bint16_t\b", "int32_t", source)
        if relative.endswith("ip_defrag.h"):
            return source.encode()
    if relative.endswith("ip_session.h"):
        source = replace(source, "struct Fragment;", "struct Fragment;\nstruct SavedIp6Prefix;")
        return replace(source, "    bool ip_options_first_seen;", "    bool ip_options_first_seen;\n"
                       "    SavedIp6Prefix* ip6_prefix;\n    uint8_t ip6_ecn_seen;").encode()
    if relative.endswith("ip_module.h"):
        return replace(source, "    PegCount premature_state_losses;", "    PegCount premature_state_losses;\n"
                       "    PegCount prefix_drops;\n    PegCount ecn_drops;").encode()
    if relative.endswith("ip_session.cc"):
        return replace(source, '    { CountType::END, nullptr, nullptr }',
            '    { CountType::SUM, "prefix_drops", "fragments rejected because reconstruction headers or size are invalid" },\n'
            '    { CountType::SUM, "ecn_drops", "fragments rejected because CE and Not-ECT conflict" },\n'
            '    { CountType::END, nullptr, nullptr }').encode()
    if relative.endswith("packet_manager.cc"):
        source = replace(source, "    if ( num_layers == 0 )", "    if ( num_layers == 0 || num_layers > p->num_layers )")
        source = replace(source, "    int len = lyr->start - p->pkt + lyr->length;\n",
            "    int len = lyr->start - p->pkt + lyr->length;\n"
            "    if (len < 0 || static_cast<unsigned>(len) > p->pktlen ||\n"
            "        static_cast<unsigned>(len) > Codec::PKT_MAX)\n        return -1;\n")
        source = replace(source, "    // len < ETHERNET_HEADER_LEN + VLAN_HEADER + ETHERNET_MTU\n"
                         "    assert((unsigned)len < Codec::PKT_MAX - c->max_dsize);",
                         "    // Long IPv6 extension prefixes are valid. The caller bounds the\n"
                         "    // resulting payload against both its IP length and actual capacity.\n"
                         "    assert((unsigned)len <= Codec::PKT_MAX);")
        return source.encode()
    source = replace(source, '#include "fragment_pressure.h"', '#include "fragment_pressure.h"\n#include "ipv6_fragment_prefix.h"')
    source = replace(source, "#define FRAG_STATE_LOST     0x00000100", "#define FRAG_STATE_LOST     0x00000100\n"
                     "#define FRAG_PREFIX_BAD     0x00000200\n#define FRAG_ECN_BAD        0x00000400")
    source = replace(source, "#define FRAG_INSERT_RESOURCE_LIMIT 8", "#define FRAG_INSERT_RESOURCE_LIMIT 8\n#define FRAG_INSERT_PREFIX_INVALID 9")
    source = replace(source, "/*  G L O B A L S  **************************************************/",
                     '#include "ipv6_fragment_prefix.inc"\n\n/*  G L O B A L S  **************************************************/')
    source = replace(source, "    PacketManager::encode_format(ENC_FLAG_DEF|ENC_FLAG_FWD, p, dpkt, PSEUDO_PKT_IP, nullptr, p->pkth->opaque);",
        "    if (PacketManager::encode_format(ENC_FLAG_DEF|ENC_FLAG_FWD, p, dpkt, PSEUDO_PKT_IP, nullptr, p->pkth->opaque) < 0 ||\n"
        "        (p->is_ip6() && !RestoreIp6Prefix(ft, dpkt)))\n    {\n"
        "        RejectIp6Rebuild(ft, p);\n        return;\n    }")
    source = replace(source, "    ft->calculated_size = 0;\n    ft->ip_options_len = 0;",
        "    ft->calculated_size = 0;\n    delete ft->ip6_prefix;\n    ft->ip6_prefix = nullptr;\n"
        "    ft->ip6_ecn_seen = 0;\n    ft->ip_options_len = 0;")
    source = replace(source, "    if (ft->frag_flags & FRAG_RESOURCE_DROP)\n",
        "    if (ft->frag_flags & FRAG_ECN_BAD)\n    {\n"
        '        p->active->set_drop_reason("ip6_reassembly_ecn");\n'
        "        ip_stats.ecn_drops++;\n    }\n"
        "    else if (ft->frag_flags & FRAG_PREFIX_BAD)\n    {\n"
        '        p->active->set_drop_reason("ip_reassembly_headers");\n'
        "        ip_stats.prefix_drops++;\n    }\n"
        "    else if (ft->frag_flags & FRAG_RESOURCE_DROP)\n")
    source = replace(source, "        case FRAG_INSERT_RESOURCE_LIMIT:\n",
        "        case FRAG_INSERT_PREFIX_INVALID:\n            delete_tracker(ft);\n"
        "            DropTrackedFragment(p, ft);\n            ip_stats.discards++;\n            return;\n\n"
        "        case FRAG_INSERT_RESOURCE_LIMIT:\n")
    source = replace(source, '''    if (p->is_ip6() && (net_frag_offset == 0))
    {
        const ip::IP6Frag* const fragHdr = layer::get_inner_ip6_frag();
        if (fragHdr)
            ft->ip_proto = fragHdr->ip6f_nxt;
    }
''', '''    if (p->is_ip6() && !CaptureIp6Prefix(ft, p, net_frag_offset))
        return FRAG_INSERT_PREFIX_INVALID;
''')
    source = replace(source, "    /* initialize the fragment list */\n",
        "    if (p->is_ip6() && !CaptureIp6Prefix(ft, p, frag_off))\n    {\n"
        "        ip_stats.discards++;\n        return 1;\n    }\n\n"
        "    /* initialize the fragment list */\n")
    return source.encode()


def apply(upstream, target):
    upstream, target = upstream.resolve(strict=True), target.resolve(strict=True)
    if upstream == target or upstream in target.parents or target in upstream.parents:
        raise ValueError("target must be a separate source copy")
    commit = subprocess.check_output(["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True).strip()
    if commit != COMMIT:
        raise ValueError("not the reviewed upstream commit")
    pressure = home.pressure
    lifetime = pressure.lifetime
    opts = lifetime.options
    originals = {}
    for relative in dict.fromkeys((*opts.fragment.FILES, *opts.FILES, *lifetime.FILES, *pressure.FILES, *home.FILES, *FILES)):
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
               "src/codecs/ip/ipv6_checksum_destination.h": HERE / "ipv6_checksum_destination.h"}
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
    local = [Path(__file__), *HELPERS.values(), *helpers.values(),
             *[HERE / name for name in ("apply_type2_repair.py", "apply_fragment_checksum_repair.py",
                "apply_ipv4_route_repair.py", "apply_fragment_options_repair.py", "apply_fragment_lifetime_repair.py",
                "apply_fragment_pressure_repair.py", "apply_home_address_repair.py")]]
    report = {"upstream_commit": commit, "requires": "All preceding repairs through Home Address",
              "scope": "Separate local source copy only; native build and replay required.",
              "before_sha256": {name: digest(data) for name, data in originals.items()},
              "after_sha256": {name: digest(data) for name, data in updates.items()},
              "local_source_sha256": {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in local},
              "patch_sha256": digest(patch.encode())}
    for name, data in updates.items():
        (target / name).write_bytes(data)
    (target / "ax-ipv6-prefix.patch").write_text(patch)
    (target / "ax-ipv6-prefix-source-validation.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--target-source", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(apply(args.upstream, args.target_source), indent=2))


if __name__ == "__main__":
    main()
