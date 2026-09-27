#!/usr/bin/env python3
"""Repair fixed fragment lifetimes after the reviewed fragment-option repair.

Only changes a separate, verified source copy. No installation or live traffic.
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import subprocess

import apply_fragment_options_repair as options

HERE = Path(__file__).resolve().parent
FILES = ("src/stream/ip/ip_defrag.cc", "src/stream/ip/ip_session.cc")
HEADER = "src/stream/ip/fragment_lifetime.h"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def patched(relative, original):
    source = original.decode()
    replace = options.type2.replace_once
    include = '#include "ip_defrag.h"' if relative.endswith("ip_defrag.cc") else '#include "ip_session.h"'
    source = replace(source, include, include + '\n#include "fragment_lifetime.h"')
    if relative.endswith("ip_session.cc"):
        source = replace(source,
            "    flow->set_default_session_timeout(pc->session_timeout, false);",
            "    flow->set_default_session_timeout(pc->session_timeout, false);\n"
            "    if (p->is_fragment())\n"
            "    {\n"
            "        const auto retention = ax_fragment::retention_seconds(\n"
            "            p->is_ip6(), pc->session_timeout);\n"
            "        if (flow->default_session_timeout < retention)\n"
            "            flow->set_default_session_timeout(retention, true);\n"
            "        if (flow->idle_timeout < retention)\n"
            "            flow->set_idle_timeout(retention);\n"
            "    }")
        return source.encode()
    source = replace(source, "#define FRAG_DROP_FRAGMENTS 0x00000020",
                     "#define FRAG_DROP_FRAGMENTS 0x00000020\n#define FRAG_TIMED_OUT      0x00000040")
    start = source.index("static inline bool frag_timed_out(")
    end = source.index("/**\n * Check to see if we've got the first or last fragment", start)
    source = source[:start] + '''static inline bool frag_timed_out(
    const timeval* current_time, const timeval* start_time, FragEngine* engine, bool ipv6)
{
    return ax_fragment::lifetime_expired(current_time->tv_sec, current_time->tv_usec,
        start_time->tv_sec, start_time->tv_usec,
        ax_fragment::reassembly_seconds(ipv6, engine->frag_timeout));
}

''' + source[end:]
    source = replace(source, "    ft->fraglist = nullptr;\n    if (ft->ip_options_data)",
                     "    ft->fraglist = nullptr;\n"
                     "    ft->fraglist_tail = nullptr;\n"
                     "    ft->fraglist_count = 0;\n"
                     "    ft->frag_bytes = 0;\n"
                     "    ft->calculated_size = 0;\n"
                     "    ft->ip_options_len = 0;\n"
                     "    if (ft->ip_options_data)")
    start = source.index("    else if (expired(p, ft, fe) )")
    end = source.index("    //don't forward fragments", start)
    source = source[:start] + '''    // The datagram deadline is measured from its first arriving fragment.
    // Do not slide it forward on activity or restart it after abandonment.
    expired(p, ft, fe);

''' + source[end:]
    source = replace(source, '''        p->active->daq_drop_packet(p);
        ip_stats.drops++;
    }
''', '''        p->active->daq_drop_packet(p);
        if (ft->frag_flags & FRAG_TIMED_OUT)
            p->active->set_drop_reason("ip_reassembly_timeout");
        ip_stats.drops++;
        return;
    }
''')
    source = replace(source,
        "    if ( frag_timed_out(&p->pkth->ts, &(ft)->frag_time, fe) )",
        "    if (ft->frag_flags & FRAG_TIMED_OUT)\n"
        "        return true;\n\n"
        "    if ( frag_timed_out(&p->pkth->ts, &(ft)->frag_time, fe, p->is_ip6()) )")
    source = replace(source, '''        delete_tracker(ft);

        ip_stats.frag_timeouts++;''', '''        delete_tracker(ft);
        // Retain a small rejection record, not stale geometry or payload.
        // Late arrivals and retries cannot reconstruct this abandoned datagram.
        ft->frag_flags = FRAG_BAD | FRAG_DROP_FRAGMENTS | FRAG_TIMED_OUT;

        ip_stats.frag_timeouts++;''')
    return source.encode()


def apply(upstream, target):
    upstream, target = upstream.resolve(strict=True), target.resolve(strict=True)
    if upstream == target or upstream in target.parents or target in upstream.parents:
        raise ValueError("target must be a separate source copy")
    commit = subprocess.check_output(["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True).strip()
    if commit != options.type2.COMMIT:
        raise ValueError("not the reviewed upstream commit")
    originals = {}
    for relative in dict.fromkeys((*options.fragment.FILES, *options.FILES, *FILES)):
        clean = subprocess.check_output(["git", "-C", str(upstream), "show", "HEAD:" + relative])
        if (upstream / relative).read_bytes() != clean:
            raise ValueError("upstream changed: " + relative)
        prior = clean
        if relative in options.fragment.FILES:
            prior = options.type2.patched(relative, prior) if relative in options.type2.FILES else prior
            prior = options.fragment.patched(relative, prior)
            prior = options.route.patched(relative, prior) if relative in options.route.FILES else prior
        if relative in options.FILES:
            prior = options.patched(relative, prior)
        if (target / relative).read_bytes() != prior:
            raise ValueError("unexpected preceding source: " + relative)
        if relative in FILES:
            originals[relative] = prior
    for relative, name in ((options.HEADER, "ipv4_fragment_options.h"),
                           ("src/codecs/ip/ipv4_checksum_destination.h", "ipv4_checksum_destination.h"),
                           ("src/codecs/ip/ipv6_checksum_destination.h", "ipv6_checksum_destination.h")):
        if (target / relative).read_bytes() != (HERE / name).read_bytes():
            raise ValueError("preceding helper changed: " + relative)
    if (target / HEADER).exists():
        raise ValueError("lifetime helper already exists")
    updates = {name: patched(name, data) for name, data in originals.items()}
    updates[HEADER] = (HERE / "fragment_lifetime.h").read_bytes()
    patch = "".join("".join(difflib.unified_diff(
        originals.get(name, b"").decode().splitlines(keepends=True), data.decode().splitlines(keepends=True),
        fromfile="a/" + name if name in originals else "/dev/null", tofile="b/" + name))
        for name, data in updates.items())
    for name in updates:
        if not (target / name).resolve().is_relative_to(target):
            raise ValueError("target path escapes source copy")
    local = [Path(__file__), HERE / "fragment_lifetime.h", HERE / "apply_type2_repair.py",
             HERE / "apply_fragment_checksum_repair.py", HERE / "apply_ipv4_route_repair.py",
             HERE / "apply_fragment_options_repair.py", HERE / "ipv4_fragment_options.h",
             HERE / "ipv4_checksum_destination.h", HERE / "ipv6_checksum_destination.h"]
    report = {"upstream_commit": commit, "requires": "All preceding checksum and IPv4 fragment-option repairs",
              "scope": "Separate local source copy only; native build and inline replay required.",
              "before_sha256": {name: digest(data) for name, data in originals.items()},
              "after_sha256": {name: digest(data) for name, data in updates.items()},
              "local_source_sha256": {path.name: digest(path.read_bytes()) for path in local},
              "patch_sha256": digest(patch.encode())}
    for name, data in updates.items():
        (target / name).write_bytes(data)
    (target / "ax-fragment-lifetime.patch").write_text(patch)
    (target / "ax-fragment-lifetime-source-validation.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--target-source", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(apply(args.upstream, args.target_source), indent=2))


if __name__ == "__main__":
    main()
