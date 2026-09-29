# Native Snort packet and stream protection

This is a profile for a separate **Snort 3.12.2.0** deployment. It inspects real packets
and reassembled streams. AX's Go/Python HTTP matcher does not load these files.
The native profile complements the proxy's request validation, destination
authorization and limits; it does not provide a guarantee against every attack,
unknown vulnerability, or malicious use of an otherwise authorized service.

The official source is pinned to
[`14aeb09f5a0856812dbe08ead3c21f99e8860aa0`](https://github.com/snort3/snort3/tree/14aeb09f5a0856812dbe08ead3c21f99e8860aa0),
tag `3.12.2.0`. No user-archive programs or deployment instructions are executed.

The latest locally verified cumulative engine is the
[TCP timestamp and SYN-data repair](patches/tcp-timestamps.md), including all
preceding repairs through fragment identity. Loading the rules alone does not
apply those source changes. Its [build record](tcp-timestamp-build-validation.json)
and [replay record](tcp-timestamp-validation.json) bind the current source and
binaries to 3,120 timestamp cases and 3,884 existing regression cases. These
local artifacts have not been installed or deployed.

## Files and effective policy

- `protocol-ips.lua` is the standalone packet profile.
- `protocol-builtins.rules` loads only the 192 selected builtin definitions.
  Global builtin generation remains disabled, so unselected events have no rule
  object and cannot occupy the event queue.
- `protocol.states` explicitly enables each selected builtin and sets its action.
- `builtin-inventory.json` records the exact native GID:SIDs, source symbols,
  descriptions, selected actions, exceptions, source URLs and source hashes.
- `protocol-validation.rules` supplies seven additional ND checks missing from the
  builtin events: invalid ICMPv6 Neighbor Solicitation/Advertisement/Redirect
  codes, invalid Hop Limits for all five Neighbor Discovery message types, and
  ordinary reassembled fragmentation, and link-local source requirements for
  Router Advertisement and Redirect, structured option validation, and stateless
  target/flag/source-option/destination relationships. The broader atomic-fragment
  policy is below. Four additional rules check mandatory Hop-by-Hop placement,
  AH header framing, the original IPv6 first fragment's header chain, and the
  base Next Header admission set with AH support.
  Three further plugin checks cover IPv4 options/padding, IPv6 Router Alert/Jumbo
  options, and visible ESP framing. A final rule rejects nonzero ICMPv6 Echo codes.
  A further original-wire Routing Type 2 check supplies known length, segment
  and stateless address requirements. TCP option validation adds original
  padding, length, SACK block geometry and SYN-only MSS/SACK-Permitted checks.
  A separate connection guard requires admitted peer permission before SACK,
  including fragmented handshakes and rejected-offer isolation.
  The eleven stateless guards and SACK connection guard require the native plugin in `plugins/`;
  omitting it is a configuration error, not a reduced-protection fallback.
- `agent-guard-overlay.lua` optionally loads the archive's 70 native signatures
  from their existing single canonical file, with their original IDs and actions.
- `generate_dns_perimeter.py` generates an alternative exact-endpoint perimeter
  for the DNS proxy and HTTP broker. See [DNS perimeter setup](perimeter/README.md).
  Its 16 new rules require the routing/Home Address options in `perimeter/`;
  the original SYN telemetry is reused once. Do not stack the original perimeter.
- `generate_inventory.py` checks official source against the installed runtime.
- `validate_profiles.py` verifies effective actions and scope selection, rather
  than merely accepting a successful parse. `profile-validation.json` is its
  local validation record, including hashes of the exact checked files, plugin
  source, build helper, tests, documentation and loaded library.

| Profile | Enabled signatures | Drop | Block | Alert |
| --- | ---: | ---: | ---: | ---: |
| Packet protocol profile | 210 | 166 | 0 | 44 |
| Protocol + perimeter overlay | 217 | 166 | 5 | 46 |
| Protocol + plaintext HTTP overlay | 273 | 166 | 19 | 88 |
| Protocol + both overlays | 280 | 166 | 24 | 90 |
| Protocol + DNS-aware perimeter | 227 | 166 | 15 | 46 |
| Protocol + DNS-aware perimeter + plaintext HTTP | 290 | 166 | 34 | 90 |

These current counts include TCP option SID 9201017 and SACK negotiation SID
9201018. The [timestamp validation record](tcp-timestamp-validation.json) repeats
the loaded-action checks with the latest engine; its repair uses existing
events 129:4 and 129:14 and adds no signature. The [SACK record](tcp-sack-validation.json),
[option record](tcp-options-validation.json) and older profile records retain
their original source and build snapshots.

The 192 builtin entries include every registered decoder event in GID 116,
all 11 `stream_ip` events in GID 123 and all 21 `stream_tcp` events in GID 129
in this release. `stream_udp` and `stream_icmp` are enabled for tracking, but do
not have their own anomaly GID inventory here; UDP/ICMP header anomalies are
decoder events. Unrelated builtin groups, including normal TCP lifecycle
notifications, are not loaded. `drop` affects an offending packet; the imported
`block` action can block its flow. Counts are signatures, not measured attacks
prevented. See the pinned [Snort action documentation](https://github.com/snort3/snort3/blob/14aeb09f5a0856812dbe08ead3c21f99e8860aa0/doc/user/active.txt).

The profile evaluates and drops invalid IP/TCP/UDP/ICMP checksums, limits protocol
layers and reassembly queues, tracks both directions, requires TCP handshakes
from startup, and enables inline TCP normalization and retransmission consistency.
These settings are verified against the actual runtime and the pinned
[network module](https://github.com/snort3/snort3/blob/14aeb09f5a0856812dbe08ead3c21f99e8860aa0/src/main/network_module.cc),
[stream module](https://github.com/snort3/snort3/blob/14aeb09f5a0856812dbe08ead3c21f99e8860aa0/src/stream/base/stream_module.cc)
and [normalizer](https://github.com/snort3/snort3/blob/14aeb09f5a0856812dbe08ead3c21f99e8860aa0/src/network_inspectors/normalize/norm_module.cc).

The event queue and processing limit are both 512, with all action groups
processed. This prevents a reproduced bypass where three advisory decoder
events exhausted Snort's default processing limit before a later drop rule's
action was applied. The native fast-pattern match limit is 100 per action
group; text matches are deduplicated within those separate groups. Validation
requires fewer than 512 enabled signatures and fewer than 100 GID 1 text rules
per action, and rejects any extra loaded rule, including disabled rules. The
profile loads selected builtin definitions explicitly: the pinned event lookup
returns before allocation for omitted rules. This prevents unrelated, disabled
builtins from consuming queue capacity. Repeated selected builtin events are
still not globally deduplicated, so signature counts do **not** prove a universal
event bound. The queue remains finite; overload testing must include
event exhaustion as well as flow and reassembly exhaustion. These behaviors
are established by the pinned
[match selection](https://github.com/snort3/snort3/blob/14aeb09f5a0856812dbe08ead3c21f99e8860aa0/src/detection/fp_detect.cc),
[event insertion](https://github.com/snort3/snort3/blob/14aeb09f5a0856812dbe08ead3c21f99e8860aa0/src/detection/detection_engine.cc)
and [event queue](https://github.com/snort3/snort3/blob/14aeb09f5a0856812dbe08ead3c21f99e8860aa0/src/events/sfeventq.cc).
Explicit builtin loading uses the same headerless rule syntax emitted by the
[module manager](https://github.com/snort3/snort3/blob/14aeb09f5a0856812dbe08ead3c21f99e8860aa0/src/managers/module_manager.cc)
and recognized by the [rule parser](https://github.com/snort3/snort3/blob/14aeb09f5a0856812dbe08ead3c21f99e8860aa0/src/parser/parse_rule.cc).

Some builtin messages describe legal features or compatibility heuristics.
Those stay advisory: ordinary IPv6 multicast/Neighbor Discovery, UDP larger than
4000 bytes, IPv4 options, TCP Fast Open, simultaneous open, some legacy/unknown
options and codes, and diagnostic ICMP messages. The inventory gives the reason
for every advisory exception. This follows the distinction between sender rules
and receiver behavior in [RFC 8200 section 4.1](https://www.rfc-editor.org/rfc/rfc8200#section-4.1),
[RFC 7323 section 2.3](https://www.rfc-editor.org/rfc/rfc7323#section-2.3),
[RFC 4861](https://www.rfc-editor.org/rfc/rfc4861) and
[RFC 9293 section 3.8.5](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.8.5).
ICMPv6 Packet Too Big messages advertising an MTU below 1280 are dropped, as
required by [RFC 8201 section 4](https://www.rfc-editor.org/rfc/rfc8201.html#section-4).

## Validate and replay

Use an installed, trusted Snort binary and libdaq. This work validated Snort
3.12.2.0 with DAQ 3.0.27 in an isolated local runtime. It did not install a service,
attach an interface, or change a firewall. Build dependencies are listed in the
pinned [official README](https://github.com/snort3/snort3/blob/14aeb09f5a0856812dbe08ead3c21f99e8860aa0/README.md).
Build the required ND plugin against that same Snort release using the
[plugin build instructions](plugins/README.md). No compiled plugin is checked in.

From the repository root, substituting your actual executable path:

```sh
SNORT=/path/to/snort
ND_PLUGIN=/path/to/reviewed/ax_nd_options.so
"$SNORT" --dump-version
"$SNORT" --plugin-path "$ND_PLUGIN" -c native-snort3/protocol-ips.lua -T
python3 native-snort3/validate_profiles.py --snort "$SNORT" --plugin-path "$ND_PLUGIN"
python3 native-snort3/tests/replay.py --snort "$SNORT" --plugin-path "$ND_PLUGIN" --report native-snort3/replay-validation.json
python3 native-snort3/tests/next_header_policy.py --snort "$SNORT" --plugin-path "$ND_PLUGIN" --report native-snort3/next-header-validation.json
python3 native-snort3/tests/checksum_replay.py --snort "$SNORT" --plugin-path "$ND_PLUGIN" --report native-snort3/checksum-validation.json
python3 native-snort3/tests/structure_replay.py --snort "$SNORT" --plugin-path "$ND_PLUGIN" --report native-snort3/structure-validation.json
"$SNORT" --plugin-path "$ND_PLUGIN" -c native-snort3/protocol-ips.lua -r /path/to/local.pcap -s 65535 -A alert_json
```

Use full snap length (`-s 65535`) for these fixtures; a shortened capture can
turn a valid large datagram into a truncation event. Both directions and full
handshakes are needed for TCP/HTTP tests. Packet generation and replay scripts
under `tests/` operate on local synthetic captures only. Their report is
separate from `profile-validation.json`, which proves only configuration and
effective actions. Review the replay report for exactly which cases were run;
neither report certifies every event or all protocol behavior. The checked-in
[replay record](replay-validation.json) passes **156 of 156 cases**: 46 valid
controls, 106 malformed cases, and four intentional policy rejections: RFC-valid
atomic UDP, traffic exceeding the eight-extension-header budget, an unadmitted
base Next Header, and a first fragment with an unsupported upper-layer header shape. It includes
the advisory-event starvation regression and thousands of well-formed unknown options,
all five ND message types, atomic and ordinary fragmentation, and structured ND
option/semantic cases. The [profile record](profile-validation.json) additionally
checks all four scope combinations and 18 invalid configurations. Run Python
validation without `-O` or `PYTHONOPTIMIZE`; optimized mode is explicitly rejected.
The separate [plugin build record](plugin-validation.json) records the macOS
arm64 build, 206 ND assertions, 535,904 IP framing assertions,
1,177,304 IPv4 option assertions, 2,168 IPv6 option assertions, 6,920 ESP assertions,
3,253 Type 2 routing assertions and six sets of 100,000 deterministic randomized inputs
with AddressSanitizer and UndefinedBehaviorSanitizer enabled. Those parser checks
and the offline replay have separate scopes; neither is live deployment evidence.

Ordinary read-file inline simulation skips checksum-drop enforcement; alert-only
replay cannot prove that protection. The separate [checksum record](checksum-validation.json)
passes **16 of 16 cases** using an inline `dump` DAQ over a read-file `pcap` DAQ.
It checks actual allow/block verdicts, decoder checksum counters and the emitted
capture: seven correct/corrupt checksum pairs cover the IPv4 header and TCP, UDP
and ICMP over IPv4 and IPv6. It also verifies that omitted IPv4 UDP checksums are
accepted while ordinary IPv6 UDP zero checksums are rejected. Every allowed
output packet must equal its input bytes; every blocked output must contain no
packets. This file-only setup never opens a network interface.

The [Next Header comparison](next-header-validation.json) uses the same file-only
inline setup for **256 comparisons / 512 native runs**. It reconstructs the
previous admission predicate with the current binary and plugin, then verifies
that AH is the only changed disposition and that all 243 other previously
rejected base-header values remain blocked. It uses one bounded payload shape
per value, not every possible packet for each protocol. The comparison and
checksum reports record executable, plugin, configuration and runner hashes.
Neither validates deployment routing, hardware checksum offload or live traffic.

The [IP structure comparison](structure-validation.json) checks the additional
IPv4/IPv6 option, visible ESP and ICMPv6 Echo guards with file-only inline DAQ
verdicts and emitted packet bytes, including Type 2 routing bounds and wire fields:
**151 of 151 cases pass across 302 native runs**, with 91 newly blocked malformed
cases and 60 unchanged controls. Type 2 adds 23 malformed cases and 17 controls.
A reconstructed policy with only these five
rules omitted demonstrates which malformed shapes were previously forwarded;
benign controls must pass unchanged under both policies. This includes original
first-fragment checks and legal IPv4 split AH/ESP headers. The ESP controls prove
only visible framing, not validity under an authenticated IPsec association.

To reproduce the builtin inventory, supply a clean official source checkout at
the pinned commit and the matching runtime:

```sh
python3 native-snort3/generate_inventory.py \
  --upstream /path/to/official/snort3 \
  --snort "$SNORT" --check
```

The generator rejects a different runtime version, changed source, duplicate
IDs, source/runtime inventory differences and unmatched policy exceptions.
Remove `--check` only when intentionally regenerating the reviewed artifacts.
For a Snort upgrade, review the source/event changes and policy assumptions,
update the release pin deliberately, then rerun configuration, state and packet
tests. Do not reuse a stale inventory as proof for another release.

## Optional imported rules

`AX_NATIVE_OVERLAY=perimeter` loads seven original-address perimeter/SYN-rate
signatures. It requires `AX_AGENT_NET`, `AX_BROKER_NET` and `AX_BROKER_PORTS`.
`AX_NATIVE_OVERLAY=http` loads 63 plaintext HTTP, response/file, original-header,
protocol mismatch and rate signatures. It requires `AX_INSPECT_CLIENTS`,
`AX_INSPECT_SERVERS` and `AX_INSPECT_PORTS`. `both` requires all six variables.
Net values use Snort address syntax; port values are explicit decimal ports,
separated by commas, with no ranges, wildcards or negation. These variables are
operator configuration, not agent-supplied request data.

Example **configuration validation only**, with illustrative private networks:

```sh
AX_NATIVE_OVERLAY=http \
AX_INSPECT_CLIENTS=10.40.0.0/24 AX_INSPECT_SERVERS=10.50.0.10 \
AX_INSPECT_PORTS=8080,8081 \
"$SNORT" --plugin-path "$ND_PLUGIN" -c native-snort3/agent-guard-overlay.lua -T
```

These are separate sensor positions: perimeter signatures need the original
agent/broker addresses; HTTP signatures need the actual plaintext inspection
hop. Use `both` only if that sensor genuinely observes both scopes. The overlay
does not decrypt TLS. In fact, original SID 9120003 intentionally blocks TLS on
the configured **plaintext** hop. Binding it to an encrypted broker interface
would implement the wrong policy. Responses and request limits also differ from
the AX matcher, and advisory source actions remain advisory.

Perimeter SID 9101003 blocks all non-TCP agent egress. Enabling that original
signature can therefore block DNS, DHCP, IPv6 Neighbor Discovery, and outgoing
ICMP/PMTU feedback. This is an explicit closed-agent-network policy, not a
generally valid IP firewall. Supply necessary network control through the
trusted network architecture or review that policy before deploying it. The
standalone protocol profile does not enable this perimeter restriction.
Use the [DNS-aware alternative](perimeter/README.md) when an agent must also
reach the restricted DNS proxy. Its exact-address/port rules and source-route
rejections replace the seven-rule broker-only perimeter; they are not exceptions
implemented with `pass` rules.

## Inline deployment boundaries

Actual prevention requires an inline-capable DAQ, correct bidirectional traffic
placement, and the traffic path being unable to bypass the sensor. Inspect
`snort --daq-list` for your build and use its documented inline mode (`-Q`) on a
dedicated test path before production. A passive capture can emit drop actions
without dropping anything on the network. Offline PCAP replay is also not live
prevention proof. Capture/offload placement must expose correct checksums, and
the packet snap length must not truncate valid traffic.

The defaults intentionally reject multiple IP encapsulation layers and all
atomic IPv6 fragments, cap IPv6
extension headers at eight and decoded layers at sixteen, and require handshake
visibility immediately. Those are deployment limits, not RFC universal limits.
Legitimate tunnels, existing connections at sensor startup, asymmetric paths,
and endpoint OS reassembly differences require an explicitly reviewed profile.
The default stream policies are Linux; match them to the protected endpoints.

Finite flow/fragment caches can prune state under load. The additional
[fragment pressure engine repair](patches/fragment-pressure.md) enforces live
fragment-node limits and blocks new fragment contexts temporarily after early
state loss. It is not applied by the rule plugin alone. Per-direction TCP queue
limits, disabled allowlist caching and this repair do not provide a global
fail-closed memory or connection admission system. Size and monitor the sensor,
test overload behavior with its actual DAQ, and enforce connection/resource
admission outside the signature engine. The optional HTTP inspector's finite
body depths are inspection limits, not guaranteed rejection of larger bodies;
the plaintext proxy must enforce body sizes itself.

Native protocol rules do not establish router authorization, source ownership,
application credentials, business permissions, DNS trust, TLS plaintext
visibility, or complete RFC compliance. In particular, ND minimum lengths and
some zero-length options are checked by the builtin ICMPv6 decoder. In the
pinned decoder, option validation stops at unknown option types; a trailing
one-byte option and a nonzero option length extending past the available bytes
do not generate a dedicated error. Consequently, 116:478 alone is not a
complete ND option validator. Required SID 9201006 adds a bounded structured
walk of the complete option area; SID 9201007 checks the stateless target,
flag, source-option and destination relationships supported by the plugin.
These checks still do not prove that a router is authorized or that a Redirect
came from the current first-hop router.
SID 9201003 rejects ND packets reassembled from ordinary fragments, following
[RFC 6980 section 5](https://www.rfc-editor.org/rfc/rfc6980.html#section-5).
Builtin 116:458 separately drops **every atomic IPv6 fragment** (offset zero and
M bit zero), independent of its payload length or upper-layer protocol. This
also rejects legitimate non-ND atomic traffic described by
[RFC 6946](https://www.rfc-editor.org/rfc/rfc6946.html). It is an explicit strict
deployment policy, not a claim that atomic fragments are universally malformed.
Source review and padded ND/atomic UDP replay confirmed that behavior. Do not
change 116:458 to alert while assuming SID 9201003 still covers atomic ND:
`flow:only_frag` identifies reassembled packets, and atomic fragments are not
marked that way. Supporting non-ND atomic traffic while blocking only atomic ND
needs a separately validated extension-header-aware guard or codec change.

SID 9201008 distinguishes the mandatory first position of Hop-by-Hop from legal
orders/repetitions of other extensions. It also examines original first Fragment
headers, because reassembly removes Fragment and can otherwise make a later
Hop-by-Hop header appear first. SID 9201010 requires the original first fragment
to contain its complete supported header chain, following
[RFC 7112](https://www.rfc-editor.org/rfc/rfc7112.html). Unknown upper-layer header
shapes and more than eight post-fragment extensions are rejected by local policy.
This does not authenticate fragment sources or replace reassembly/overlap checks.

SID 9201009 checks AH framing under
[RFC 4302](https://www.rfc-editor.org/rfc/rfc4302.html), including malformed AH
behind another extension. AH structural controls do not have an authenticated SA
or ICV. The pinned decoder separately flags AH directly following the IPv6 base
header as 116:281 despite supporting its decoder. That event is now advisory;
SID 9201011 retains the previous base Next Header rejection set except AH. It
does not bypass other inspection or pass the packet. This admission set remains
a conservative local policy, not a claim that every other IANA protocol is
RFC-invalid. The plugin build verifies hashes of the SDK headers containing the
inline predicate. IPsec authentication and replay protection remain endpoint
responsibilities.
SID 9201012 checks original IPv4 options and padding, including bytes hidden by
the decoder's shortened valid-option span. SID 9201013 checks IPv6 option chains
and Router Alert/Jumbo fields before reassembly removes original fragment context.
Unknown well-framed option types are preserved: whether their action bits require
discard depends on the receiving endpoint's recognition, which this sensor does
not establish. This pinned decoder/profile does not support complete IPv6
jumbograms; validating a Jumbo option's fields does not enable them.

SID 9201014 checks visible ESP header bounds and nonzero SPI independently of the
native `esp.decode_esp` setting. That setting defaults to false, causing the ESP
codec to return before its own short-header event. It remains disabled: the new
guard does not attempt heuristic decryption. IPv4 can legally split AH/ESP headers
across fragments, so incomplete original IPv4 headers defer until reassembly;
IPv6 retains the complete first-header-chain requirement. SID 9201015 enforces
Echo Request/Reply Code=0 under [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html).
SID 9201016 supplies the Type 2 Routing checks missing from the generic decoder:
exactly 24 bytes, Segments Left=1 on the original wire packet, and rejection of
statelessly identifiable non-routable/non-unicast home addresses. Reserved fields
are ignored; repeated Type 2 headers and other routing types are not blanket
rejected. The correct receive specification is
[RFC 6275 section 11.3.3](https://www.rfc-editor.org/rfc/rfc6275.html#section-11.3.3),
with wire format in section 6.4.1. A former advisory-event test used Type 2 with
zero segments, which is only the locally processed representation; it now uses
an unknown routing type with zero segments under RFC 8200's required-ignore rule.

There is a separate stock-engine defect: Type 2 TCP, UDP and ICMPv6 checksums
use the base destination instead of the final Home Address. The
[mobility checksum audit](mobility-checksum-validation.json) records the failing
standards behavior: correct final-address checksums block, while incorrectly
base-address-checksummed twins pass. The new structural rule does not fix that
decoder behavior, authenticate the home address, or implement every routing
subtype. Do not treat these checks as validated Mobile IPv6 support. The audit
uses synthetic offline captures; no deployment behavior has been established.
Run that stock-engine conformance audit separately; it records six
failures and exits nonzero, rather than counting reproduction as protection:

```sh
python3 native-snort3/tests/mobility_checksum_audit.py \
  --snort "$SNORT" --plugin-path "$ND_PLUGIN" \
  --snort-source /path/to/official/snort3 \
  --report native-snort3/mobility-checksum-validation.json
```

The [source repair](patches/README.md) corrects checksum verification and update
in all three codecs. It requires rebuilding the engine: loading the rule plugin
alone cannot apply it. A matched clean/repaired build comparison passes
[90 packet cases](type2-repair-validation.json), including six normalization
cases, and the four existing native suites also pass on the repaired engine.
This closes the tested Type 2 checksum defect locally. An additional
[fragment checksum repair](patches/fragment-checksums.md) requires software
verification of reassembled transport checksums and removes the UDP/ICMP
failure exception. Its matched comparison passes
[312 paired cases in 624 runs](fragment-checksum-comparison.json), closing 84
previously forwarded invalid cases while retaining all 156 valid controls.
The cumulative engine also passes the four existing native suites. It is a
separate local build; the earlier Type 2-only installation lacks this repair.
The subsequent [IPv4 source-route checksum repair](patches/ipv4-source-route.md)
corrects TCP/UDP final-destination selection and rejects malformed source-route
geometry before checksum omission or offload can bypass validation. It passes
[236 paired cases](ipv4-route-comparison.json), with 86 newly blocked invalid
cases and 74 restored valid cases. Its cumulative engine retains the existing
packet dispositions and all 90 Type 2 cases. The additional
[fragment option repair](patches/fragment-options.md) replaces length-only
comparison with bounded copied-option and final-destination consistency checks.
It preserves legal padding changes and mutable route records, prevents
reconstruction after a conflict, and reuses drop rule 123:1 for retries.
Its [320 paired cases](fragment-options-comparison.json) include 156 valid
controls, 92 retry cases and eight fresh-ID isolation controls. All seven prior
native suites pass on the cumulative engine. The subsequent
[fragment lifetime repair](patches/fragment-lifetime.md) measures reassembly age
from the first arrival, enforces IPv6's 60-second ceiling, removes stale
geometry on abandonment and retains rejection across the old short idle
timeout. Its [372 paired timing cases](fragment-lifetime-comparison.json) pass,
as do all eight preceding native suites. The subsequent
[fragment pressure repair](patches/fragment-pressure.md) enforces the previously
unused allocation budget and preserves rejection after flow-cache eviction
with a process-wide guard per IP family. It passes
[270 paired pressure cases](fragment-pressure-comparison.json), including
101 valid controls and 18 recovery cases, plus all nine preceding native
suites. New fragmented traffic can be denied during quarantine, including
legitimate traffic; existing contexts continue inspection. The subsequent
[Home Address repair](patches/home-address.md) validates the option's visible
format/order/uniqueness and corrects TCP, UDP and ICMPv6 source checksums and
updates. It passes [354 paired cases](home-address-comparison.json), all ten
preceding native suites and the new bounded-parser sanitizer tests. It expands
SID 9201013 to revision 2 without adding a duplicate signature. A separate
[IPv6 header-retention audit](ipv6-fragment-header-audit.json) demonstrates
18 bypasses of a temporary blocking policy in 72 wire cases / 144 native runs:
reconstruction uses the completing fragment's Hop Limit. The separate
[Home Address wire-prefix audit](ipv6-fragment-prefix-audit.json) has 18 of 48
disagreements with its stateless oracle; it does not establish endpoint-valid
Mobile IPv6 reassembly contexts. The subsequent
[IPv6 prefix repair](patches/ipv6-prefix.md) passes all 144 header-policy runs
and all 48 wire-oracle cases, closing the 18 demonstrated blocking bypasses.
It also passes 816 paired prefix/ECN/size cases, 72 large-fragment IPv4 cases,
and all eleven preceding suites. It preserves offset-zero headers, retains
congestion markings and bounds reconstruction before copying. Mobile IPv6
endpoint processing and binding state remain unverified. Unknown option
semantics, other routing semantics, final-route authorization, eager idle
cleanup, multi-worker/failover behavior and live deployment enforcement also
remain outside these results.

W3C browser policies belong at the HTTP/application boundary, not IP decoding.

## Source attribution

The builtin event descriptions and identifiers are generated from Cisco Snort,
copyright Cisco and its affiliates, distributed under
[GPL version 2](https://github.com/snort3/snort3/blob/14aeb09f5a0856812dbe08ead3c21f99e8860aa0/COPYING).
Source-file hashes and direct pinned links are recorded in the inventory.
The imported 70 signatures retain their original user-archive provenance in
`../pkg/security/snort/imports/agent-guard-snort3/`.
