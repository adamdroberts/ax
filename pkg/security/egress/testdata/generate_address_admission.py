"""Build public-address boundary cases from saved authoritative IANA CSVs."""

import argparse
import csv
import hashlib
import io
import ipaddress
import json
from pathlib import Path
import re


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipv4-csv", type=Path, required=True)
    parser.add_argument("--ipv6-csv", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("address_admission_cases.json"))
    args = parser.parse_args()
    sources, reserved = [], []
    for family, path in ((4, args.ipv4_csv), (6, args.ipv6_csv)):
        data = path.read_bytes()
        rows = list(csv.DictReader(io.StringIO(data.decode("utf-8"))))
        prefixes = []
        for row in rows:
            value = re.sub(r"\[[^]]*\]", "", row["Address Block"])
            for text in value.split(","):
                network = ipaddress.ip_network(text.strip())
                assert network.version == family
                prefixes.append(str(network))
                reserved.append(network)
        sources.append({"url": f"https://www.iana.org/assignments/iana-ipv{family}-special-registry/iana-ipv{family}-special-registry-1.csv",
                        "sha256": hashlib.sha256(data).hexdigest(), "rows": len(rows), "prefixes": prefixes})
    # The broker excludes all special-purpose assignments, even those marked
    # globally reachable. Multicast and the Azure platform address are separate
    # local restrictions; only 2000::/3 is eligible for IPv6 public destinations.
    extra = [ipaddress.ip_network("224.0.0.0/4"), ipaddress.ip_network("168.63.129.16/32")]
    global_v6 = ipaddress.ip_network("2000::/3")

    def public(value):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        if getattr(address, "scope_id", None) is not None:
            return False
        return (address.version == 4 or address in global_v6) and not any(address in net for net in reserved + extra)

    addresses = set()
    for net in reserved + extra + [global_v6]:
        first, last = int(net.network_address), int(net.broadcast_address)
        constructor = ipaddress.IPv4Address if net.version == 4 else ipaddress.IPv6Address
        for number in {first, first + 1, last - 1, last, first - 1, last + 1}:
            if 0 <= number < 1 << net.max_prefixlen:
                addresses.add(str(constructor(number)))
    addresses.update(["8.8.8.8", "93.184.216.34", "2606:4700:4700::1111", "2001:4860:4860::8888",
                      "", "not-an-address", "8.8.8.8%1"])
    addresses.update("2606:4700:4700::1111%" + zone for zone in ("0", "1", "en0", "25eth0"))
    address_cases = [{"name": f"address-{index:03d}", "address": value, "public": public(value)}
                     for index, value in enumerate(sorted(addresses))]

    dns_cases, seen = [], set()

    def add(name, ips):
        key = tuple(ips)
        assert key not in seen, name
        seen.add(key)
        dns_cases.append({"name": name, "addresses": ips,
                          "admitted": bool(ips) and len(ips) <= 64 and all(public(ip) for ip in ips)})

    def answers(family, count):
        return [str(ipaddress.IPv4Address(int(ipaddress.IPv4Address("93.184.216.1")) + index))
                if family == "v4" or family == "mixed" and index % 2 == 0
                else str(ipaddress.IPv6Address(int(ipaddress.IPv6Address("2001:4860::1000")) + index))
                for index in range(count)]

    add("empty", [])
    for family in ("v4", "v6", "mixed"):
        for count in (1, 2, 63, 64, 65, 128, 1024):
            if family == "mixed" and count == 1:
                continue  # Already covered by the one-address IPv4 case.
            add(f"{family}-{count}", answers(family, count))
    for family, address in (("v4", "8.8.8.8"), ("v6", "2606:4700:4700::1111")):
        for count in (64, 65):
            add(f"{family}-duplicates-{count}", [address] * count)
    for label, bad in (("private-v4", "10.0.0.1"), ("platform", "168.63.129.16"),
                       ("private-v6", "fd00::1"), ("scoped-v6", "2606:4700:4700::1111%en0")):
        for position in (0, 31, 63):
            ips = answers("mixed", 64)
            ips[position] = bad
            add(f"{label}-at-{position}", ips)
    output = {"version": 1, "sources": sources,
              "policy": {"deny_all_iana_special_purpose": True, "extra_exclusions": [str(n) for n in extra],
                         "eligible_ipv6": str(global_v6), "maximum_resolver_addresses": 64},
              "address_cases": address_cases, "dns_cases": dns_cases}
    args.output.write_text(json.dumps(output, indent=2) + "\n")
    print(f"{len(address_cases)} address cases and {len(dns_cases)} resolver cases")


if __name__ == "__main__":
    main()
