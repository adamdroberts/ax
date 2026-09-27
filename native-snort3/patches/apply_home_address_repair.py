#!/usr/bin/env python3
"""Apply Home Address checksum selection to a separate cumulative Snort tree."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import subprocess

import apply_fragment_pressure_repair as pressure

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
FILES = pressure.lifetime.options.type2.FILES
HEADER = "src/codecs/ip/ipv6_home_address.h"
HELPER = HERE.parent / "plugins/home_address.h"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def prior_source(relative, clean):
    prior = pressure.prior_source(relative, clean)
    return pressure.patched(relative, prior) if relative in pressure.FILES else prior


def patched(relative, original):
    source = original.decode()
    replace = pressure.lifetime.options.type2.replace_once
    source = replace(source, '#include "ipv6_checksum_destination.h"',
                     '#include "ipv6_checksum_destination.h"\n#include "ipv6_home_address.h"')
    icmp = relative.endswith("cd_icmp6.cc")
    protocol = "ICMPV6" if icmp else "TCP" if relative.endswith("cd_tcp.cc") else "UDP"
    indent = "        " if icmp else "    "
    before = indent + "COPY4(ph6.hdr.sip, ip6h->get_src()->u6_addr32);"
    source = replace(source, before, before + "\n" + indent +
        "if (const auto* home = ax_home::source(\n" + indent +
        "        reinterpret_cast<const uint8_t*>(ip6h), raw.data,\n" + indent +
        "        static_cast<uint8_t>(codec.ip6_csum_proto)))\n" + indent +
        "    memcpy(ph6.hdr.sip, home, sizeof(ph6.hdr.sip));")
    if icmp:
        before = "        memcpy(ps6.hdr.sip, api.get_src()->get_ip6_ptr(), sizeof(ps6.hdr.sip));"
        pointer, indent = "api.get_ip6h()", "        "
        source = replace(source, "        (codec.is_cooked() || !valid_checksum_from_daq(raw)))",
            "        (codec.is_cooked() || snort.ip_api.get_ip6h()->next() != IpProtocol::ICMPV6 ||\n"
            "         !valid_checksum_from_daq(raw)))")
    else:
        before = "            memcpy(ps6.hdr.sip, ip6h->get_src()->u6_addr32, sizeof(ps6.hdr.sip));"
        pointer, indent = "ip6h", "            "
        source = replace(source, "        (codec.is_cooked() ||\n",
            "        (codec.is_cooked() ||\n"
            "         (snort.ip_api.is_ip6() && snort.ip_api.get_ip6h()->next() != IpProtocol::" + protocol + ") ||\n")
    source = replace(source, before, before + "\n" + indent +
        "if (const auto* home = ax_home::source(\n" + indent +
        "        reinterpret_cast<const uint8_t*>(" + pointer + "), raw_pkt,\n" + indent +
        "        static_cast<uint8_t>(IpProtocol::" + protocol + ")))\n" + indent +
        "    memcpy(ps6.hdr.sip, home, sizeof(ps6.hdr.sip));")
    return source.encode()


def apply(upstream, target):
    upstream, target = upstream.resolve(strict=True), target.resolve(strict=True)
    if upstream == target or upstream in target.parents or target in upstream.parents:
        raise ValueError("target must be a separate source copy")
    commit = subprocess.check_output(["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True).strip()
    lifetime = pressure.lifetime
    opts = lifetime.options
    if commit != opts.type2.COMMIT:
        raise ValueError("not the reviewed upstream commit")
    originals = {}
    for relative in dict.fromkeys((*opts.fragment.FILES, *opts.FILES, *lifetime.FILES, *pressure.FILES, *FILES)):
        clean = subprocess.check_output(["git", "-C", str(upstream), "show", "HEAD:" + relative])
        if (upstream / relative).read_bytes() != clean:
            raise ValueError("upstream changed: " + relative)
        prior = prior_source(relative, clean)
        if (target / relative).read_bytes() != prior:
            raise ValueError("unexpected preceding source: " + relative)
        if relative in FILES:
            originals[relative] = prior
    helpers = {pressure.HEADER: "fragment_pressure.h", lifetime.HEADER: "fragment_lifetime.h",
               opts.HEADER: "ipv4_fragment_options.h",
               "src/codecs/ip/ipv4_checksum_destination.h": "ipv4_checksum_destination.h",
               "src/codecs/ip/ipv6_checksum_destination.h": "ipv6_checksum_destination.h"}
    for relative, name in helpers.items():
        if (target / relative).read_bytes() != (HERE / name).read_bytes():
            raise ValueError("preceding helper changed: " + relative)
    if (target / HEADER).exists():
        raise ValueError("Home Address helper already exists")
    updates = {name: patched(name, data) for name, data in originals.items()}
    updates[HEADER] = HELPER.read_bytes()
    patch = "".join("".join(difflib.unified_diff(
        originals.get(name, b"").decode().splitlines(keepends=True), data.decode().splitlines(keepends=True),
        fromfile="a/" + name if name in originals else "/dev/null", tofile="b/" + name))
        for name, data in updates.items())
    for name in updates:
        if not (target / name).resolve().is_relative_to(target):
            raise ValueError("target path escapes source copy")
    local = [Path(__file__), HELPER, *[HERE / name for name in helpers.values()],
             *[HERE / name for name in ("apply_type2_repair.py", "apply_fragment_checksum_repair.py",
                "apply_ipv4_route_repair.py", "apply_fragment_options_repair.py", "apply_fragment_lifetime_repair.py",
                "apply_fragment_pressure_repair.py")]]
    report = {"upstream_commit": commit, "requires": "All preceding repairs through fragment pressure",
              "scope": "Separate local source copy only; rebuild the structural plugin and native engine, then replay.",
              "before_sha256": {name: digest(data) for name, data in originals.items()},
              "after_sha256": {name: digest(data) for name, data in updates.items()},
              "local_source_sha256": {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in local},
              "patch_sha256": digest(patch.encode())}
    for name, data in updates.items():
        (target / name).write_bytes(data)
    (target / "ax-home-address.patch").write_text(patch)
    (target / "ax-home-address-source-validation.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--target-source", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(apply(args.upstream, args.target_source), indent=2))


if __name__ == "__main__":
    main()
