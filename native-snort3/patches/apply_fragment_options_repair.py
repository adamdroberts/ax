#!/usr/bin/env python3
"""Apply bounded IPv4 fragment-option consistency after the checksum repairs.

Only changes a separate source copy; no build, installation or live traffic.
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import subprocess

import apply_type2_repair as type2
import apply_fragment_checksum_repair as fragment
import apply_ipv4_route_repair as route

HERE = Path(__file__).resolve().parent
FILES = ("src/stream/ip/ip_session.h", "src/stream/ip/ip_defrag.cc")
HEADER = "src/stream/ip/ipv4_fragment_options.h"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def patched(relative, original):
    source = original.decode()
    replace = type2.replace_once
    if relative.endswith("ip_session.h"):
        source = replace(source, '#include "stream/ip/ip_module.h"',
                         '#include "stream/ip/ip_module.h"\n#include "ipv4_fragment_options.h"')
        return replace(source, "    uint8_t copied_ip_options_len;  /* length of 'copied' ip options */",
                       "    ax_fragment::CopiedOptions copied_ip_options;\n"
                       "    bool ip_options_first_seen;").encode()
    source = replace(source, '#include "ip_defrag.h"',
                     '#include "ip_defrag.h"\n\n#include "codecs/ip/ipv4_checksum_destination.h"')
    start = source.index("static int FragHandleIPOptions(")
    end = source.index("/** checks for tiny fragments", start)
    source = source[:start] + '''static int FragHandleIPOptions(
    FragTracker* ft,
    const Packet* const p,
    const uint16_t frag_offset)
{
    const uint16_t length = p->ptrs.ip_api.get_ip_opt_len();
    const uint8_t* options = p->ptrs.ip_api.get_ip_opt_data();
    const auto* destination = ax_checksum::ipv4_destination(
        reinterpret_cast<const uint8_t*>(p->ptrs.ip_api.get_ip4h()), options + length);
    if (!ax_fragment::observe(ft->copied_ip_options, options, length,
            frag_offset != 0, destination))
    {
        // Re-queue on every retry, so the existing 123:1 drop action applies
        // to each packet. Never reconstruct an inconsistent tracked datagram.
        EventAnomIpOpts(ft->engine);
        ft->frag_flags |= FRAG_BAD;
        return 0;
    }
    if (!frag_offset && !ft->ip_options_first_seen)
    {
        ft->ip_options_first_seen = true;
        if (length)
        {
            ft->ip_options_data = (uint8_t*)snort_calloc(length);
            memcpy(ft->ip_options_data, options, length);
            ft->ip_options_len = length;
        }
    }
    return 1;
}

''' + source[end:]
    source = replace(source, '''        else if (ft->copied_ip_options_len)
        {
            /* should we log a warning here?  there were IP options copied
             * across all fragments, EXCEPT the offset 0 fragment.
             */
        }
''', "")
    source = replace(source, '''    const uint16_t net_frag_offset = p->ptrs.ip_api.off();
''', '''    const uint16_t net_frag_offset = p->ptrs.ip_api.off();

    // Validate before changing reassembly geometry or storing fragment data.
    if (p->is_ip4() && !FragHandleIPOptions(ft, p, net_frag_offset))
        return FRAG_INSERT_ANOMALY;
''')
    source = replace(source, '''    /*
     * This may alert on bad options, but we still want to
     * insert the packet
     */
    if ( p->is_ip4() )
        FragHandleIPOptions(ft, p, frag_offset);

''', "")
    source = replace(source, "    ft->copied_ip_options_len = 0;\n", "")
    source = replace(source, '''    ft->engine = &engine;

    /* initialize the fragment list */''', '''    ft->engine = &engine;

    // A nonzero fragment may be the first arrival. Keep a rejection in its
    // tracker, but do not allocate or insert its payload.
    if (p->is_ip4() && !FragHandleIPOptions(ft, p, frag_off))
    {
        ip_stats.discards++;
        return 1;
    }

    /* initialize the fragment list */''')
    source = replace(source, '''    if ( p->is_ip4() )
        FragHandleIPOptions(ft, p, frag_off);

''', "")
    return source.encode()


def apply(upstream, target):
    upstream, target = upstream.resolve(strict=True), target.resolve(strict=True)
    if upstream == target or upstream in target.parents or target in upstream.parents:
        raise ValueError("target must be a separate source copy")
    commit = subprocess.check_output(["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True).strip()
    if commit != type2.COMMIT:
        raise ValueError("not the reviewed Snort commit")
    originals = {}
    for relative in (*fragment.FILES, *FILES):
        clean = subprocess.check_output(["git", "-C", str(upstream), "show", "HEAD:" + relative])
        if (upstream / relative).read_bytes() != clean:
            raise ValueError("upstream changed: " + relative)
        prior = clean
        if relative in fragment.FILES:
            prior = type2.patched(relative, prior) if relative in type2.FILES else prior
            prior = fragment.patched(relative, prior)
            prior = route.patched(relative, prior) if relative in route.FILES else prior
        if (target / relative).read_bytes() != prior:
            raise ValueError("unexpected preceding source: " + relative)
        if relative in FILES:
            originals[relative] = prior
    for name in ("ipv6_checksum_destination.h", "ipv4_checksum_destination.h"):
        if (target / "src/codecs/ip" / name).read_bytes() != (HERE / name).read_bytes():
            raise ValueError("preceding checksum helper changed: " + name)
    if (target / HEADER).exists():
        raise ValueError("fragment option helper already exists")
    updates = {name: patched(name, data) for name, data in originals.items()}
    updates[HEADER] = (HERE / "ipv4_fragment_options.h").read_bytes()
    patch = "".join("".join(difflib.unified_diff(
        originals.get(name, b"").decode().splitlines(keepends=True), data.decode().splitlines(keepends=True),
        fromfile="a/" + name if name in originals else "/dev/null", tofile="b/" + name))
        for name, data in updates.items())
    for name in updates:
        if not (target / name).resolve().is_relative_to(target):
            raise ValueError("target path escapes source copy")
    local = [Path(__file__), HERE / "ipv4_fragment_options.h", HERE / "apply_type2_repair.py",
             HERE / "apply_fragment_checksum_repair.py", HERE / "apply_ipv4_route_repair.py",
             HERE / "ipv4_checksum_destination.h", HERE / "ipv6_checksum_destination.h"]
    report = {"upstream_commit": commit, "requires": "Type 2, fragment checksum and IPv4 route checksum repairs",
              "scope": "Separate local source copy only; native build and inline replay required.",
              "before_sha256": {name: digest(data) for name, data in originals.items()},
              "after_sha256": {name: digest(data) for name, data in updates.items()},
              "local_source_sha256": {path.name: digest(path.read_bytes()) for path in local},
              "patch_sha256": digest(patch.encode())}
    for name, data in updates.items():
        (target / name).write_bytes(data)
    (target / "ax-fragment-options.patch").write_text(patch)
    (target / "ax-fragment-options-source-validation.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--target-source", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(apply(args.upstream, args.target_source), indent=2))


if __name__ == "__main__":
    main()
