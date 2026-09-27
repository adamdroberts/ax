#!/usr/bin/env python3
"""Enforce fragment allocation budgets and quarantine premature state loss.

Requires a separate source copy containing all reviewed preceding repairs.
Does not build, install, deploy or open an interface.
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import subprocess

import apply_fragment_lifetime_repair as lifetime

HERE = Path(__file__).resolve().parent
FILES = ("src/stream/ip/ip_defrag.cc", "src/stream/ip/ip_session.cc",
         "src/stream/ip/ip_session.h", "src/stream/ip/ip_module.h")
HEADER = "src/stream/ip/fragment_pressure.h"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def prior_source(relative, clean):
    opts = lifetime.options
    prior = clean
    if relative in opts.fragment.FILES:
        prior = opts.type2.patched(relative, prior) if relative in opts.type2.FILES else prior
        prior = opts.fragment.patched(relative, prior)
        prior = opts.route.patched(relative, prior) if relative in opts.route.FILES else prior
    if relative in opts.FILES:
        prior = opts.patched(relative, prior)
    if relative in lifetime.FILES:
        prior = lifetime.patched(relative, prior)
    return prior


def patched(relative, original):
    source = original.decode()
    replace = lifetime.options.type2.replace_once
    if relative.endswith("ip_session.h"):
        return replace(source, "    bool ip_options_first_seen;",
                       "    bool ip_options_first_seen;\n"
                       "    bool quarantine_only; // No fragment of this tracker was admitted.\n"
                       "    int64_t fragment_last_seen; // Not refreshed by lookup of an expired flow.").encode()
    if relative.endswith("ip_module.h"):
        return replace(source, "    PegCount fragmented_bytes;", "    PegCount fragmented_bytes;\n"
                       "    PegCount max_fragment_nodes;\n"
                       "    PegCount resource_drops;\n"
                       "    PegCount state_lost_drops;\n"
                       "    PegCount premature_state_losses;").encode()
    source = replace(source, '#include "fragment_lifetime.h"',
                     '#include "fragment_lifetime.h"\n#include "fragment_pressure.h"\n#include "time/packet_time.h"')
    if relative.endswith("ip_session.cc"):
        source = replace(source, '#include "framework/data_bus.h"',
                         '#include "framework/data_bus.h"\n#include "flow/flow_key.h"')
        source = replace(source, '    { CountType::END, nullptr, nullptr }',
            '    { CountType::MAX, "max_fragment_nodes", "maximum concurrently allocated fragment nodes" },\n'
            '    { CountType::SUM, "resource_drops", "fragments rejected because reassembly resources are unavailable" },\n'
            '    { CountType::SUM, "state_lost_drops", "new fragment trackers rejected during loss-of-state quarantine" },\n'
            '    { CountType::SUM, "premature_state_losses", "fragment trackers discarded before retention elapsed" },\n'
            '    { CountType::END, nullptr, nullptr }')
        source = replace(source, '''static void IpSessionCleanup(Flow* lws, FragTracker* tracker)
{
''', '''static void IpSessionCleanup(Flow* lws, FragTracker* tracker)
{
    // Completion releases engine before cleanup. Quarantine-only trackers
    // forwarded no fragments and must not prolong the global quarantine.
    if (tracker->engine && !tracker->quarantine_only)
    {
        const bool ipv6 = lws->key->version == 6;
        const auto retention = ax_fragment::retention_seconds(ipv6, tracker->engine->frag_timeout);
        if (ax_fragment::remember_state_loss(ipv6, tracker->fragment_last_seen, packet_time(), retention))
            ip_stats.premature_state_losses++;
    }
''')
        return source.encode()
    source = replace(source, "#define FRAG_TIMED_OUT      0x00000040",
                     "#define FRAG_TIMED_OUT      0x00000040\n"
                     "#define FRAG_RESOURCE_DROP  0x00000080\n#define FRAG_STATE_LOST     0x00000100")
    source = replace(source, "#define FRAG_INSERT_OVERLAP_LIMIT  7",
                     "#define FRAG_INSERT_OVERLAP_LIMIT  7\n#define FRAG_INSERT_RESOURCE_LIMIT 8")
    source = replace(source, "struct Fragment\n{", "// Separate from resettable statistics; owned by each packet thread.\n"
                     "static THREAD_LOCAL uint64_t live_fragment_nodes = 0;\n\nstruct Fragment\n{")
    source = replace(source, "        delete[] fptr;\n        ip_stats.nodes_released++;",
                     "        delete[] fptr;\n        assert(live_fragment_nodes);\n"
                     "        --live_fragment_nodes;\n        ip_stats.nodes_released++;")
    source = replace(source, "        ip_stats.nodes_created++;", "        ++live_fragment_nodes;\n"
                     "        if (ip_stats.max_fragment_nodes < live_fragment_nodes)\n"
                     "            ip_stats.max_fragment_nodes = live_fragment_nodes;\n"
                     "        ip_stats.nodes_created++;")
    source = replace(source, "static void release_tracker(FragTracker* ft)", '''static void DropTrackedFragment(Packet* p, const FragTracker* ft)
{
    DetectionEngine::disable_content(p);
    p->active->daq_drop_packet(p);
    ip_stats.drops++;
    if (ft->frag_flags & FRAG_RESOURCE_DROP)
    {
        p->active->set_drop_reason("ip_reassembly_resources");
        ip_stats.resource_drops++;
    }
    else if (ft->frag_flags & FRAG_STATE_LOST)
    {
        p->active->set_drop_reason("ip_reassembly_state_lost");
        ip_stats.state_lost_drops++;
    }
    else if (ft->frag_flags & FRAG_TIMED_OUT)
        p->active->set_drop_reason("ip_reassembly_timeout");
}

static void release_tracker(FragTracker* ft)''')
    source = replace(source, '''    if (!ft->engine )
    {
        new_tracker(p, ft);
        return;
    }
''', '''    if (!ft->engine )
    {
        if (!new_tracker(p, ft))
        {
            // Failed admission must not forward a fragment without a tracker.
            // Both failure paths precede payload/option allocation.
            memset(ft, 0, sizeof(*ft));
            ft->engine = fe;
            ft->frag_time = p->pkth->ts;
            ft->fragment_last_seen = packet_time();
            ft->quarantine_only = true;
            ft->frag_flags = FRAG_BAD | FRAG_DROP_FRAGMENTS | FRAG_RESOURCE_DROP;
        }
        if (ft->frag_flags & FRAG_DROP_FRAGMENTS)
            DropTrackedFragment(p, ft);
        return;
    }
''')
    source = replace(source, "    // The datagram deadline is measured from its first arriving fragment.",
                     "    // FlowCache::find refreshes last_data_seen before expired-session cleanup.\n"
                     "    // Keep the old tracker's clock separate so normal expiry is not state loss.\n"
                     "    if (ft->fragment_last_seen < packet_time())\n"
                     "        ft->fragment_last_seen = packet_time();\n\n"
                     "    // The datagram deadline is measured from its first arriving fragment.")
    source = replace(source, '''        DetectionEngine::disable_content(p);
        p->active->daq_drop_packet(p);
        if (ft->frag_flags & FRAG_TIMED_OUT)
            p->active->set_drop_reason("ip_reassembly_timeout");
        ip_stats.drops++;
        return;
''', '''        DropTrackedFragment(p, ft);
        return;
''')
    source = replace(source, '''        case FRAG_INSERT_FAILED:
''', '''        case FRAG_INSERT_RESOURCE_LIMIT:
            delete_tracker(ft);
            ft->frag_flags |= FRAG_BAD | FRAG_DROP_FRAGMENTS | FRAG_RESOURCE_DROP;
            DropTrackedFragment(p, ft);
            ip_stats.discards++;
            return;

        case FRAG_INSERT_FAILED:
            delete_tracker(ft);
            ft->frag_flags |= FRAG_BAD | FRAG_DROP_FRAGMENTS | FRAG_RESOURCE_DROP;
            DropTrackedFragment(p, ft);
''')
    source = replace(source, '''    ft->engine = &engine;

    // A nonzero fragment may be the first arrival.''', '''    ft->engine = &engine;

    ft->fragment_last_seen = packet_time();
    if (ax_fragment::state_loss_quarantine(p->is_ip6(), packet_time()))
    {
        ft->quarantine_only = true;
        ft->frag_flags = FRAG_BAD | FRAG_DROP_FRAGMENTS | FRAG_STATE_LOST;
        return 1;
    }
    if (live_fragment_nodes >= engine.max_frags)
        return 0;

    // A nonzero fragment may be the first arrival.''')
    source = replace(source, "    newfrag = new Fragment(fragLength, fragStart, ft->ordinal++);",
                     "    if (live_fragment_nodes >= fe->max_frags)\n"
                     "        return FRAG_INSERT_RESOURCE_LIMIT;\n\n"
                     "    newfrag = new Fragment(fragLength, fragStart, ft->ordinal++);")
    source = replace(source, "    Fragment* newfrag = new Fragment(left, ft->ordinal++);",
                     "    if (live_fragment_nodes >= ft->engine->max_frags)\n"
                     "        return FRAG_INSERT_RESOURCE_LIMIT;\n\n"
                     "    Fragment* newfrag = new Fragment(left, ft->ordinal++);")
    return source.encode()


def apply(upstream, target):
    upstream, target = upstream.resolve(strict=True), target.resolve(strict=True)
    if upstream == target or upstream in target.parents or target in upstream.parents:
        raise ValueError("target must be a separate source copy")
    commit = subprocess.check_output(["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True).strip()
    if commit != lifetime.options.type2.COMMIT:
        raise ValueError("not the reviewed upstream commit")
    originals = {}
    for relative in dict.fromkeys((*lifetime.options.fragment.FILES, *lifetime.options.FILES, *lifetime.FILES, *FILES)):
        clean = subprocess.check_output(["git", "-C", str(upstream), "show", "HEAD:" + relative])
        if (upstream / relative).read_bytes() != clean:
            raise ValueError("upstream changed: " + relative)
        prior = prior_source(relative, clean)
        if (target / relative).read_bytes() != prior:
            raise ValueError("unexpected preceding source: " + relative)
        if relative in FILES:
            originals[relative] = prior
    helpers = {lifetime.HEADER: "fragment_lifetime.h", lifetime.options.HEADER: "ipv4_fragment_options.h",
               "src/codecs/ip/ipv4_checksum_destination.h": "ipv4_checksum_destination.h",
               "src/codecs/ip/ipv6_checksum_destination.h": "ipv6_checksum_destination.h"}
    for relative, name in helpers.items():
        if (target / relative).read_bytes() != (HERE / name).read_bytes():
            raise ValueError("preceding helper changed: " + relative)
    if (target / HEADER).exists():
        raise ValueError("pressure helper already exists")
    updates = {name: patched(name, data) for name, data in originals.items()}
    updates[HEADER] = (HERE / "fragment_pressure.h").read_bytes()
    patch = "".join("".join(difflib.unified_diff(
        originals.get(name, b"").decode().splitlines(keepends=True), data.decode().splitlines(keepends=True),
        fromfile="a/" + name if name in originals else "/dev/null", tofile="b/" + name))
        for name, data in updates.items())
    for name in updates:
        if not (target / name).resolve().is_relative_to(target):
            raise ValueError("target path escapes source copy")
    local = [Path(__file__), HERE / "fragment_pressure.h", *[HERE / name for name in helpers.values()],
             *[HERE / name for name in ("apply_type2_repair.py", "apply_fragment_checksum_repair.py",
               "apply_ipv4_route_repair.py", "apply_fragment_options_repair.py", "apply_fragment_lifetime_repair.py")]]
    report = {"upstream_commit": commit, "requires": "All preceding checksum, fragment-option and fragment-lifetime repairs",
              "scope": "Separate local source copy only; native build and replay required.",
              "before_sha256": {name: digest(data) for name, data in originals.items()},
              "after_sha256": {name: digest(data) for name, data in updates.items()},
              "local_source_sha256": {path.name: digest(path.read_bytes()) for path in local}, "patch_sha256": digest(patch.encode())}
    for name, data in updates.items():
        (target / name).write_bytes(data)
    (target / "ax-fragment-pressure.patch").write_text(patch)
    (target / "ax-fragment-pressure-source-validation.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--target-source", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(apply(args.upstream, args.target_source), indent=2))


if __name__ == "__main__":
    main()
