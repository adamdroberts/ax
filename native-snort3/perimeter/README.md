# DNS-aware native perimeter

This alternative permits agents to contact only the operator's DNS proxy and
HTTP broker. DNS uses TCP or UDP on one exact port; the HTTP broker uses TCP on
the configured ports. Other destinations, transports and service ports are
blocked. Both IPv4 and IPv6 use the same policy. The DNS proxy itself enforces
the [exact-name, scheduled-cache contract](../../docs/dns-proxy.md); these packet
rules constrain routing and do not decode encrypted application payloads.

Use this profile **instead of** the original `perimeter`/`both` overlay, which
denies UDP DNS. There are no `pass` rules. The generator reuses the original SYN
telemetry definition once and retains the existing protocol controls.

## Configuration

Copy [the example JSON](../dns-perimeter.example.json) and replace its illustrative
addresses with the addresses visible at this sensor. DNS proxy and broker IPs
must be distinct and outside the agent networks. Every protected address family
requires both endpoint roles. IPv4-only and IPv6-only configurations are valid;
dual-stack configurations require both. CIDRs must be canonical and nonoverlapping;
endpoints must be canonical numeric unicast addresses. Hostnames, wildcards,
mapped addresses, duplicate keys, unknown settings, missing endpoints and invalid
ports are rejected. Configuration is operator-controlled data, never agent input.

The configured destination port is the port visible at this boundary. Account
for Service/NAT translation separately from the proxy's local listening port.
Keep the proxy, its upstream resolver and the HTTP broker outside agent control.

Build the additional options using the SDK for the reviewed Snort engine and its
existing protocol plugin. This creates a **new** directory containing both
libraries. It downloads nothing and never overwrites an existing directory.

```sh
python3 native-snort3/perimeter/build.py \
  --snort-include /path/to/snort/include/snort \
  --daq-include /path/to/daq/include \
  --protocol-plugin /path/to/reviewed/ax_nd_options.so \
  --output-dir /path/to/new/dns-perimeter-plugins

python3 native-snort3/generate_dns_perimeter.py \
  --config /path/to/reviewed-dns-perimeter.json \
  --output /path/to/new/dns-perimeter.lua

# Configuration validation only; no live interface is opened.
snort --plugin-path /path/to/new/dns-perimeter-plugins \
  -c /path/to/new/dns-perimeter.lua -T
```

Use the [cumulative repaired Snort 3.12.2.0 engine](../patches/fragment-identity.md),
including preceding repairs. Stock version equality alone does not establish
equivalence with that engine. The generator embeds canonical settings and its
source digest in the output. Review and regenerate after source changes; it does
not overwrite an existing configuration. Keep the source tree at the generated
absolute path, or regenerate for the installed layout.

For a sensor that also sees the separate **plaintext** inspection hop, add
`--with-http` when generating, then set `AX_NATIVE_OVERLAY=http` and the existing
`AX_INSPECT_CLIENTS`, `AX_INSPECT_SERVERS`, `AX_INSPECT_PORTS` variables. The HTTP
scope must describe the plaintext hop, not the encrypted agent-to-broker socket.
DNS-only output requires `AX_NATIVE_OVERLAY` to be absent. Other selections fail.

## Local policy and limits

The new rules use SIDs `9202001–9202016`: fifteen blocking rules and one inbound
control-traffic advisory. SYN telemetry retains `9121001`. The resulting native
profile has **225** enabled signatures (179 blocking, 46 advisory), or **288**
with HTTP inspection (198 blocking, 90 advisory). No duplicate native GID:SID is
loaded. The original native profiles remain alternatives with unchanged counts.

IPv4 loose/strict source routes and all decoded IPv6 routing headers are denied
on agent egress, even if otherwise valid. An approved first hop must not become
a routing relay. `ax_ip6_route_present` checks Snort's decoded layer metadata;
omitting either required library fails configuration. Ordinary IPv6 Hop-by-Hop
and Destination Options controls remain accepted when the protocol profile permits
them. Source-routing rejection is a local authorization policy, not a claim that
all routing headers violate an RFC.

`ax_ip6_home_present` also rejects Home Address options in packets travelling to
or from the agent networks (SID `9202016`). Such an option can change the source
address presented to upper layers under
[RFC 6275 section 9.3.1](https://datatracker.ietf.org/doc/html/rfc6275#section-9.3.1).
The prior perimeter checked wire addresses but allowed this otherwise valid
feature. Its fixed-peer policy now excludes it, without relying on unverified
Mobile IPv6 binding caches. The option uses the existing bounded Home Address
parser; the general RFC framing/checksum validation remains unchanged. Opaque
option data and ordinary payloads resembling a Home Address option do not match.

Agents require an unavoidable inline boundary and anti-spoofing before source
CIDRs can identify them. These signatures do not authenticate endpoint identity,
own host firewall connection state, or authorize ICMP errors/Neighbor Discovery.
Outbound non-DNS/non-broker traffic includes such control traffic; trusted host
networking must supply required routing control. Inbound control traffic remains
advisory and needs trusted router/state policy at the host. A sandbox must not
modify these controls or reach a different relay on an approved service port.

Keeping both TCP and UDP DNS preserves the transport choice described by
[RFC 7766](https://www.rfc-editor.org/rfc/rfc7766.html). Preventing encrypted DNS
elsewhere requires closing arbitrary outbound HTTPS, since DoH can use ordinary
HTTP request paths under [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484.html).
The forced HTTP broker and its exact-origin/application authorization remain
required. This policy does not decrypt every encrypted stream or guarantee
prevention of unknown attacks or abuse of approved applications.

## Reproduce local validation

```sh
PYTHONDONTWRITEBYTECODE=1 python3 native-snort3/tests/test_dns_perimeter.py
PYTHONDONTWRITEBYTECODE=1 python3 native-snort3/tests/dns_perimeter_replay.py \
  --snort /path/to/repaired/snort \
  --plugin-path /path/to/new/dns-perimeter-plugins \
  --report /path/to/dns-perimeter-validation.json

PYTHONDONTWRITEBYTECODE=1 python3 native-snort3/tests/dns_perimeter_bypass_replay.py \
  --snort /path/to/repaired/snort \
  --plugin-path /path/to/new/dns-perimeter-plugins \
  --report /path/to/dns-perimeter-bypass-validation.json
```

The [build record](build-validation.json) identifies both libraries and SDK/source
hashes. The [packet record](../dns-perimeter-validation.json) reports **231/231**
passing cases, verifies exact enabled actions for both new profiles and rejects
five conflicting/incomplete configurations. Cases cover both IP families,
outside destinations, DNS/broker cross-ports, direct encrypted-DNS service ports,
inbound peers, TCP query splitting/reuse, ordinary IPv6 extensions, source routes,
fragments in both arrival orders and retained HTTP/TLS separation.

Each packet case uses an inline `dump:pcap` DAQ reading a local capture. Assertions
check native verdicts, expected rule events and actual forwarded bytes. A blocked
fragmented datagram may leave a previously forwarded orphan fragment; the complete
denied datagram must not be delivered. Tests use no live interfaces and establish
neither a deployed sandbox route nor exhaustive protocol conformance.

The [additional audit](../dns-perimeter-bypass-validation.json) passes **2,224
cases**: 2,032 opaque-protocol checks, 48 IP/GRE encapsulation checks, 108 Home
Address policy rejections and 36 controls. The Home Address cases compare the
current policy with a reconstruction that removes only SID `9202016`, using
the same engine and plugin. All 108 are forwarded by that comparison policy and
blocked by the new rule; 72 supply a source address different from the wire
source. Both directions, DNS and broker endpoints, TCP/UDP, long/aligned option
headers and both fragment arrival orders are covered. This demonstrates sensor
behavior, not successful impersonation against a live endpoint.

The [sanitizer audit](../dns-perimeter-bypass-asan-validation.json) repeats the
144 Home Address/control cases with an AddressSanitizer Snort engine and a new
perimeter library built with `--sanitize` (AddressSanitizer and
UndefinedBehaviorSanitizer). It verifies identical verdicts, bytes and events
against the release run. The reused general protocol library and prebuilt
dependencies are not instrumented by this new build; their earlier unit-parser
records are separate evidence. The raw protocol sweep uses empty/zero-filled
payloads, not full semantic implementations of every IP protocol.
