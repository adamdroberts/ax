#!/usr/bin/env python3
"""Generate a reviewed, exact-endpoint DNS-aware Snort perimeter configuration.

Consumes data only. Does not install files, run Snort or modify networking.
The output loads the existing protocol profile and the alternative perimeter,
optionally combined with the existing plaintext HTTP overlay.
"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
IMPORTED = HERE.parent / "pkg/security/snort/imports/agent-guard-snort3/native-only.rules"
FIELDS = {"schema_version", "agent_networks", "dns_proxy_addresses", "dns_port", "broker_addresses", "broker_ports"}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate configuration key: " + key)
        result[key] = value
    return result


def bounded_list(value, name, limit):
    if not isinstance(value, list) or not 1 <= len(value) <= limit:
        raise ValueError(f"{name} must contain 1..{limit} entries")
    return value


def addresses(value, name, limit):
    result = []
    for text in bounded_list(value, name, limit):
        if not isinstance(text, str):
            raise ValueError(name + " must contain literal IP strings")
        ip = ipaddress.ip_address(text)
        if (text != str(ip) or ip.is_unspecified or ip.is_loopback or ip.is_multicast
                or ip.is_link_local or getattr(ip, "scope_id", None)
                or getattr(ip, "ipv4_mapped", None) or str(ip) == "255.255.255.255"):
            raise ValueError(name + " must contain canonical, routable unicast literals")
        if ip in result:
            raise ValueError("duplicate " + name)
        result.append(ip)
    return sorted(result, key=lambda ip: (ip.version, int(ip)))


def port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError("ports must be integers 1..65535")
    return value


def validate(config):
    if not isinstance(config, dict) or config.keys() != FIELDS or type(config["schema_version"]) is not int or config["schema_version"] != 1:
        raise ValueError("configuration must have exactly the schema-version-1 fields")
    nets = []
    for value in bounded_list(config["agent_networks"], "agent_networks", 32):
        if not isinstance(value, str):
            raise ValueError("agent networks must be canonical CIDR strings")
        network = ipaddress.ip_network(value, strict=True)
        if (str(network) != value or network.prefixlen == 0 or network.is_multicast
                or network.is_loopback or network.is_link_local or getattr(network.network_address, "ipv4_mapped", None)):
            raise ValueError("invalid or ambiguous agent network")
        if any(network.overlaps(other) for other in nets if other.version == network.version):
            raise ValueError("overlapping or duplicate agent networks")
        nets.append(network)
    dns = addresses(config["dns_proxy_addresses"], "dns_proxy_addresses", 8)
    brokers = addresses(config["broker_addresses"], "broker_addresses", 8)
    if set(dns) & set(brokers):
        raise ValueError("DNS proxy and broker addresses must be separate")
    if any(ip in network for ip in dns + brokers for network in nets if ip.version == network.version):
        raise ValueError("trusted endpoints must be outside the agent networks")
    families = {network.version for network in nets}
    if {ip.version for ip in dns} != families or {ip.version for ip in brokers} != families:
        raise ValueError("each agent address family requires DNS proxy and broker endpoints")
    broker_ports = [port(value) for value in bounded_list(config["broker_ports"], "broker_ports", 8)]
    if len(set(broker_ports)) != len(broker_ports):
        raise ValueError("duplicate broker port")
    return {"schema_version": 1, "agent_networks": sorted(map(str, nets)),
            "dns_proxy_addresses": list(map(str, dns)), "dns_port": port(config["dns_port"]),
            "broker_addresses": list(map(str, brokers)), "broker_ports": sorted(broker_ports)}


def load(path):
    data = path.read_bytes()
    if len(data) > 16384:
        raise ValueError("configuration exceeds 16 KiB")
    return validate(json.loads(data, object_pairs_hook=unique_object))


def rules():
    own = (HERE / "dns-perimeter.rules").read_text()
    entries = [line for line in own.splitlines() if line and not line.startswith("#")]
    sids = [int(re.search(r"; sid:(\d+);", line)[1]) for line in entries]
    if sids != list(range(9202001, 9202017)) or len(set(entries)) != len(entries):
        raise ValueError("perimeter inventory changed: review actions and queue limits")
    # Retain the source's exact SYN-rate telemetry once, without copying it into
    # another product rule file or importing the incompatible original perimeter.
    syn = [line for line in IMPORTED.read_text().splitlines() if "; sid:9121001;" in line]
    if len(syn) != 1 or not syn[0].startswith("alert tcp $AGENT_NET "):
        raise ValueError("imported SYN-rate definition changed")
    return own + "\n" + syn[0] + "\n", entries + syn


def render(config, with_http=False, native_dir=HERE):
    config = validate(config)
    text, entries = rules()
    native_dir = native_dir.resolve()
    # JSON's ASCII quote escaping is compatible with Lua for these paths; use
    # literal UTF-8 instead of JSON's \u syntax, which Lua does not support.
    quote = lambda value: json.dumps(str(value), ensure_ascii=False)
    if any(ord(c) < 32 for c in str(native_dir)):
        raise ValueError("native profile directory contains control characters")
    base = "agent-guard-overlay.lua" if with_http else "protocol-ips.lua"
    if not (native_dir / base).is_file():
        raise ValueError("native profile directory is missing the selected base profile")
    selector = ("assert(os.getenv('AX_NATIVE_OVERLAY') == 'http', 'DNS perimeter HTTP mode requires AX_NATIVE_OVERLAY=http')"
                if with_http else "assert(not os.getenv('AX_NATIVE_OVERLAY'), 'DNS perimeter cannot load a second perimeter overlay')")
    array = lambda values: "[" + ",".join(map(str, values)) + "]"
    variables = {"AGENT_NET": array(config["agent_networks"]), "BROKER_NET": array(config["broker_addresses"]),
                 "AX_DNS_PROXIES": array(config["dns_proxy_addresses"]),
                 "AX_TRUSTED_ENDPOINTS": array(config["broker_addresses"] + config["dns_proxy_addresses"])}
    source_digest = hashlib.sha256((Path(__file__).read_bytes() + (HERE / "dns-perimeter.rules").read_bytes() + IMPORTED.read_bytes())).hexdigest()
    lines = ["-- Generated DNS-aware perimeter. Regenerate after editing its JSON input.",
             "-- This loads no pass rule and no original broker-only perimeter.",
             "-- Generator/rule source SHA-256: " + source_digest,
             "-- Canonical policy: " + json.dumps(config, sort_keys=True), selector,
             "include(" + quote(native_dir / base) + ")",
             "ips.variables = ips.variables or { nets = {}, ports = {} }"]
    lines += ["ips.variables.nets." + key + " = " + quote(value) for key, value in variables.items()]
    lines += ["ips.variables.ports.BROKER_PORTS = " + quote(array(config["broker_ports"])),
              "ips.variables.ports.AX_DNS_PORT = " + quote(config["dns_port"]),
              "ips.rules = ips.rules .. [=[\n" + text + "]=]",
              "ips.states = ips.states .. [=["]
    for line in entries:
        sid = re.search(r"; sid:(\d+);", line)[1]
        lines.append(line.split()[0] + " ( gid:1; sid:" + sid + "; enable:yes; )")
    lines.append("]=]\n")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--native-dir", type=Path, default=HERE)
    parser.add_argument("--with-http", action="store_true")
    args = parser.parse_args()
    try:
        rendered = render(load(args.config), args.with_http, args.native_dir)
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.error(str(error))
    # Avoid overwriting the reviewed inputs or an existing working policy.
    with args.output.open("x") as target:
        target.write(rendered)
    print(json.dumps({"output": str(args.output.resolve()), "sha256": hashlib.sha256(rendered.encode()).hexdigest(),
                      "perimeter_rules": 17, "http_overlay": args.with_http}))


if __name__ == "__main__":
    main()
