# Native IP and neighbor-discovery rule options

This plugin is required by the AX native profile and adds ten stateless rule
options to **Snort 3.12.2.0**.
The implementation uses the supported `IpsApi`/`IpsOption` interface and the
installed development headers. The reviewed upstream source is commit
`14aeb09f5a0856812dbe08ead3c21f99e8860aa0`.

- `ax_nd_options` matches invalid option framing in ICMPv6 types 133–137:
  zero option length, a one-octet trailing header, or an option extending beyond
  the decoded ICMP message. Structurally valid unknown option types are skipped,
  and scanning continues. No per-packet allocation is required; every successful
  iteration advances by at least eight octets.
- `ax_nd_semantics` matches selected stateless receive violations: multicast
  NS/NA target addresses; the NA Solicited flag with a multicast IP destination;
  an unspecified RS/NS source with a Source Link-Layer Address option; an
  unspecified NS source without a solicited-node multicast destination; and a
  Redirect's multicast inner destination or target that is neither link-local
  nor equal to that inner destination. A malformed option chain belongs to
  `ax_nd_options`; load both rules together.
- `ax_ip6_hop_order` detects Hop-by-Hop headers outside the first extension
  position, including an original first Fragment header that points at Hop-by-Hop.
  This preserves evidence that reassembly would remove.
- `ax_ah_header` checks each decoded AH span against its declared size, the
  twelve fixed bytes and IPv6 eight-byte alignment. It does not verify an ICV,
  Security Association or replay window.
- `ax_ip6_first_fragment` checks the original first fragment for a complete
  supported header chain. It walks Destination/Routing/AH extensions with an
  eight-extension budget, and checks TCP (including its data offset), UDP,
  ICMPv6 common headers, ESP fixed headers and encapsulated IP headers. No Next
  Header terminates the chain. Unknown upper-layer shapes and nested Fragment
  headers are rejected as local policy; noninitial fragments are left to reassembly.
- `ax_ip6_base_next_header` retains the pinned decoder's base Next Header
  admission set and adds AH, which its codec supports but its validity list
  omits. This replaces only the broad blocking action for builtin 116:281;
  all other inspections and AH framing checks still run. Unsupported values are
  local admission decisions, not universal RFC-invalidity claims.
- `ax_ip4_options` walks the original IHL-bounded option and padding bytes,
  including bytes the native decoder stops exposing after End of Option List.
  It validates framing, route/timestamp minimum fields and pointers, single
  RR/TS/source-route instances, four-byte Router Alert options and zero padding.
  Well-formed unknown options, obsolete option contents, unknown Router Alert
  values and completed pointers past an option's end stay opaque.
- `ax_ip6_options` checks complete Hop-by-Hop/Destination option chains,
  including those after an original first Fragment header. Router Alert and
  Jumbo Payload receive type-specific length, placement and alignment checks;
  Jumbo additionally requires zero base payload length, a value above 65535 and
  no Fragment header. Repeated Jumbo lengths are rejected as local ambiguity
  policy. Home Address options require 16 data bytes, alignment at 8n+6, a
  Destination Options header after Routing and before Fragment/AH/ESP, and no
  duplicate within the selected IPv6 header. Multicast, unspecified, loopback
  and link-local home addresses are rejected. These checks reuse SID 9201013.
  Their shared helper also supports the separate
  [native checksum repair](../patches/home-address.md); rebuilding this plugin
  alone cannot change the engine's checksum selection. Binding-cache state,
  actual routability and ownership are not established by these stateless checks.
  Unknown option types and Router Alert values remain opaque; their
  endpoint-dependent processing cannot be inferred from this sensor.
- `ax_esp_header` checks visible ESP framing even when native ESP decoding is
  disabled: fixed SPI/sequence fields, nonzero SPI and space for mandatory
  trailer bytes in complete packets. IPv6 first fragments need the fixed header;
  incomplete IPv4 AH/ESP headers defer to reassembly. Encrypted contents, sequence
  windows, algorithm lengths and security associations are not inspected.
- `ax_ip6_type2_routing` checks original-wire Type 2 Routing headers: exactly
  24 bytes, Segments Left=1, and no multicast, unspecified, loopback or link-local
  home address. Reserved fields, repeated structurally valid Type 2 headers and
  other routing types retain their receive semantics. Zero segments represents
  a locally processed Type 2 header, so this guard must inspect original packets.
  Home-address ownership and actual routability require endpoint state.

These checks implement selected requirements in
[RFC 4861 sections 4.6, 6.1.1, 7.1.1, 7.1.2, 8.1 and 9](https://www.rfc-editor.org/rfc/rfc4861.html).
Home Address format and ordering follow
[RFC 6275 section 6.3](https://www.rfc-editor.org/rfc/rfc6275.html#section-6.3).
The [Home Address build and replay records](../patches/home-address.md) cover
the latest extension of this plugin; the original reports below predate it.
Unknown option contents and reserved fields are ignored. This plugin does not
authorize routers, verify sender ownership, maintain a neighbor cache, validate
every option's type-specific contents, or replace checksum, hop-limit, code,
fragmentation and minimum-header checks in the surrounding native profile.
The additional IP checks use [RFC 8200](https://www.rfc-editor.org/rfc/rfc8200.html),
[RFC 7112](https://www.rfc-editor.org/rfc/rfc7112.html) and
[RFC 4302](https://www.rfc-editor.org/rfc/rfc4302.html). A complete common upper-layer
header is not a guarantee that its message body or authentication is valid.
The option guards apply sender formats from [RFC 791](https://www.rfc-editor.org/rfc/rfc791.html),
[RFC 1122](https://www.rfc-editor.org/rfc/rfc1122.html),
[RFC 2113](https://www.rfc-editor.org/rfc/rfc2113.html),
[RFC 2711](https://www.rfc-editor.org/rfc/rfc2711.html) and
[RFC 2675](https://www.rfc-editor.org/rfc/rfc2675.html) as strict IPS policy;
some of those options are optional for endpoints to process. ESP framing follows
[RFC 4303](https://www.rfc-editor.org/rfc/rfc4303.html).
Type 2 checks follow [RFC 6275 sections 6.4.1 and 11.3.3](https://www.rfc-editor.org/rfc/rfc6275.html#section-11.3.3).
They do not correct native Mobile IPv6 transport-checksum calculation; see the
separate [known-defect audit](../mobility-checksum-validation.json).

The pinned decoder places ND payload data after the four common ICMP header
octets. The plugin uses that decoded span, excluding Ethernet padding; selected
ND packets with an inconsistent span match invalid. Other Snort versions need a
fresh API/layout audit and replay, even when their plugin API version matches.

## Build without installing

Use development headers from the same Snort installation and its DAQ dependency.
Choose a temporary output directory; the helper does not install or modify Snort.
No compiled binary is checked in. Compile on the deployment platform against
its pinned Snort/DAQ SDK, then run configuration validation and packet replay
there before enabling the profile. The local build/replay evidence below is for
macOS arm64; Linux support in the helper is not Linux runtime validation.

```sh
python3 native-snort3/plugins/build.py \
  --snort-prefix /path/to/snort \
  --daq-include /path/to/daq/include \
  --output-dir /tmp/ax-nd-plugin \
  --sanitize-tests
```

The helper checks the Snort executable version and the exact SDK header hashes
for its inline Next Header predicate, builds `ax_nd_options.so`, and
runs the pure validators. It records compiler commands, source/library hashes
and test output in `build-report.json` in the output directory. The macOS build
uses the same unresolved-symbol linking approach as upstream dynamic plugins;
Snort resolves the supported API symbols when loading it.

Load with `--plugin-path /tmp/ax-nd-plugin`. Configuration must contain all ten
keywords; omitting the library then fails configuration validation instead of
silently removing these checks. Example rules, with reserved project SIDs:

```text
drop icmp any any -> any any (msg:"AX invalid IPv6 ND options"; ax_nd_options; sid:9201006; rev:1;)
drop icmp any any -> any any (msg:"AX invalid IPv6 ND semantics"; ax_nd_semantics; sid:9201007; rev:1;)
drop ip any any -> any any (msg:"AX misplaced IPv6 Hop-by-Hop"; ax_ip6_hop_order; sid:9201008; rev:1;)
drop ip any any -> any any (msg:"AX invalid AH length"; ax_ah_header; sid:9201009; rev:1;)
drop ip any any -> any any (msg:"AX incomplete or unsupported first fragment"; ax_ip6_first_fragment; sid:9201010; rev:1;)
drop ip any any -> any any (msg:"AX unadmitted IPv6 base Next Header"; ax_ip6_base_next_header; sid:9201011; rev:1;)
drop ip any any -> any any (msg:"AX malformed IPv4 options"; ax_ip4_options; sid:9201012; rev:1;)
drop ip any any -> any any (msg:"AX malformed IPv6 options"; ax_ip6_options; sid:9201013; rev:2;)
drop ip any any -> any any (msg:"AX impossible visible ESP framing"; ax_esp_header; sid:9201014; rev:1;)
drop ip any any -> any any (msg:"AX malformed original-wire Type 2 routing"; ax_ip6_type2_routing; sid:9201016; rev:1;)
```

The plugin supplies matching conditions; the configured rule action and DAQ
mode determine enforcement. A library on disk alone provides no protection.

## Validation boundary

The standalone test exercises all five message layouts, recognized and unknown
option types, malformed chains, stateless address/flag checks, and 100,000
deterministic randomized inputs. Run it with AddressSanitizer and
UndefinedBehaviorSanitizer as shown above. These are bounded regression checks,
not proof that every possible input or deployment has been verified.
The separate IP test exhausts AH length-byte/span combinations, exercises
first-fragment extension and upper-layer bounds, and runs a further 100,000
randomized inputs. Native packet replay separately tests the adapter's span
selection, arrival order and exclusion of link-layer padding.
Four further parser suites cover IPv4 options, IPv6 extension options, visible
ESP framing and Type 2 routing, each with 100,000 deterministic randomized inputs under sanitizers.
Their exact assertion counts and source hashes are in the build report. The
separate [structure comparison](../structure-validation.json) checks real file-only
inline DAQ decisions and output packets, including benign controls and the policy
with the five additional structure guards omitted.

The combined profile's final [replay report](../replay-validation.json) records
the full packet suite and exact source/configuration/library hashes.
Malformed captures produced `would_drop` during offline readback. This is
simulated enforcement; live inline DAQ blocking and deployment routing were not
tested by the plugin build or replay.
