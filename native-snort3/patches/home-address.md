# Home Address option validation and checksum repair

The preceding cumulative Snort engine uses the IPv6 base source address for
transport checksums even when a Home Address option supplies the logical
source. Native file replay confirmed reversed behavior for TCP, UDP and ICMPv6:
correct Home Address checksums were rejected, while incorrect base-source
checksums passed. The preceding structural plugin also allowed malformed Home
Address options.

This repair adds bounded Home Address validation to existing **SID 9201013,
revision 2**, and corrects checksum verification and update in all three
transport codecs. Both the plugin and engine must be rebuilt. No duplicate
signature or additional SID is introduced.

The [354-case comparison](../home-address-comparison.json) passes, but a
separate [header-retention audit](../ipv6-fragment-header-audit.json) finds
18 local-policy bypasses in 72 wire cases / 144 native runs. That reassembly
defect is described below; this repair does not establish complete fragmented
Mobile IPv6 support.

## Standards and checks

[RFC 6275 section 6.3](https://www.rfc-editor.org/rfc/rfc6275.html#section-6.3)
defines Home Address type `0xc9`, 16 data bytes, alignment at `8n+6`, placement
in Destination Options after Routing and before Fragment/AH/ESP, and at most
one occurrence per IPv6 header. The guard enforces these visible relationships
across the selected header's extension chain, including original first
fragments. It rejects statelessly identifiable multicast, unspecified, loopback
and link-local home addresses.

[RFC 6275 section 11.3.1](https://www.rfc-editor.org/rfc/rfc6275.html#section-11.3.1)
requires upper-layer checksum calculation with the home source. The engine
selects it for TCP, UDP and ICMPv6, including checksum updates after rewriting.
Existing Type 2 destination selection remains in force when both endpoints
use mobility headers.

These checks cannot establish address ownership, actual routability or the
care-of/home binding relationship required by
[RFC 6275 section 9.3.1](https://www.rfc-editor.org/rfc/rfc6275.html#section-9.3.1).
The fixture addresses are synthetic; passing their checksum/structure checks
is not an authorization decision.

## Implementation

`plugins/home_address.h` is shared by the structural plugin and the codec
repair, which copies it as `src/codecs/ip/ipv6_home_address.h`. The helper
walks only length-checked known extensions, with the existing local maximum
of eight. TLVs advance within their exact containing header; full option-type
bytes are compared. Unknown option data, transport payload, another IP layer
and ESP are opaque. Noninitial fragment contents are not scanned for headers.

The checksum selector stops exactly at the current transport boundary. It
requires a complete compatible extension prefix and never selects an address
from a transport-payload lookalike. Real fragments cannot provide a complete
transport checksum; reassembled packets are checked through the existing
software-checksum repair. Selection does not rewrite the original IP source,
change flow identity, authenticate a binding or generate Mobile IPv6 replies.

The three codecs also require software checksum calculation when IPv6
extensions precede the transport. A hardware verdict about the base header
cannot substitute for these extension-specific address semantics. The file
replays have no hardware offload metadata; live offload behavior still needs
separate validation.

Generic malformed extension framing remains covered by the preceding
decoder and structured-option guards. New Home Address failures use the
existing IPv6-option rule. Unrelated unknown options keep their existing
receive semantics; the helper does not infer endpoint feature support from
their action bits.

## Evidence

The [paired engine/plugin comparison](../home-address-comparison.json)
records **354 cases / 708 native runs** with actual inline file DAQ verdicts,
checksum counters and exact forwarded bytes:

- The repaired combination passes all 354; the baseline passes 111 and fails 243.
- Rejection improves in 153 cases, including all 51 malformed-option cases.
- Correct forwarding is restored in 90 cases.
- Coverage includes 171 fragment cases, 27 retry cases and 12 normalization
  or rewriting cases across TCP, UDP and ICMPv6.

Fixtures include multiple extension layouts, Type 2 destination plus Home
Address source selection, the eight-extension boundary, a 2,048-byte option
header, ULA addresses, opaque lookalikes, forward/reversed/all selected
three-fragment arrival orders and checksum-corrupt retries. Fragment cases in
this passing suite have consistent per-fragment address semantics.

The 12 update cases use a temporary TCP reserved-bit normalization profile
and two temporary payload-rewrite rules. The expected replacement bytes and
their checksums are independently checked. These test rules are not added to
the product catalog, and the supplied profile preserves its existing
normalization settings. Malformed-option fixtures use a valid base-source
checksum so an unrelated checksum failure cannot conceal a missing guard.

The [plugin build record](../home-address-plugin-validation.json) binds the
preceding saved sources and new sources to their respective shared libraries
and the same pinned SDK headers. Its Home Address helper passes **306,943
assertions**, 100,000 generated semantic cases and 100,000 arbitrary bounded
spans under AddressSanitizer and UndefinedBehaviorSanitizer. All six preceding
pure-parser suites also pass. The helper bytes in the plugin and engine build
records must match.

All ten preceding native suites pass on the new engine and plugin:

| Suite | Cases |
| --- | ---: |
| [General replay](../home-address-repaired-engine/replay-validation.json), inline simulation | 156 |
| [Ordinary checksums](../home-address-repaired-engine/checksum-validation.json) | 16 |
| [IP structure](../home-address-repaired-engine/structure-validation.json), paired policies | 151 |
| [Next Header](../home-address-repaired-engine/next-header-validation.json), paired policies | 256 |
| [Fragment checksums](../home-address-repaired-engine/fragment-checksum-validation.json) | 312 |
| [Structure and Type 2](../home-address-repaired-engine/cumulative-validation.json) | 241 |
| [IPv4 source routes](../home-address-repaired-engine/ipv4-route-validation.json) | 236 |
| [Fragment options](../home-address-repaired-engine/fragment-options-validation.json) | 320 |
| [Fragment lifetimes](../home-address-repaired-engine/fragment-lifetime-validation.json) | 372 |
| [Fragment pressure](../home-address-repaired-engine/fragment-pressure-validation.json) | 270 |

## Reassembly failure and subsequent repair

[RFC 8200 section 4.5](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.5)
retains the offset-zero fragment's preceding headers after processing each
fragment's headers before queueing. Header differences are permitted; some
fields have additional aggregation rules, including ECN. Source review shows
that this pinned engine formats the reconstructed prefix from the
**completing** fragment.

The [address-independent audit](../ipv6-fragment-header-audit.json) keeps
source/destination identity and transport checksums unchanged. Temporary
rules examine Hop Limit only on defragmented packets. All 72 wire cases pass
checksum checks and forward unchanged under the observation policy. However,
18 cases reconstruct the continuation fragment's Hop Limit. A second policy
demonstrates 18 bypasses of a test-only rule blocking reconstructed Hop Limit
41. That threshold is an explicit test policy, not an RFC validity rule or a
product rule. Across both policies, 108 of 144 native runs meet expectations;
36 fail. Reversed arrival, unchanged Hop Limit and varying padding lengths
provide controls.

A separate [48-case wire-prefix audit](../ipv6-fragment-prefix-audit.json)
varies Home Address contents, presence and padding under Snort's current
wire-identity grouping. Its offset-zero-source checksum oracle disagrees in
18 cases: nine differing checksums forward and nine matching ones are blocked.
These are **not** assertions that those datagrams form one valid Mobile IPv6
endpoint context. RFC 6275 processing can change logical source identity
before queueing, and binding validation can reject a fragment. Those endpoint
semantics remain unverified. Both audits exit nonzero and are excluded from
the passing 354-case comparison.

A repair must preserve the appropriate offset-zero prefix with bounded
storage and cleanup, while respecting field aggregation and processing before
queueing. Blanket rejection of varying headers would not implement the
required receive behavior. Prefix retention alone also would not establish
correct Mobile IPv6 flow identity or binding validation. The subsequent
[IPv6 prefix repair](ipv6-prefix.md) now passes the 144 header-policy runs and
48 wire-oracle cases. It closes the demonstrated prefix-retention bypasses;
the endpoint-state limitations above remain open. The original failure reports
linked in this section are preserved as baseline evidence.

## Build and repeat

Start from a separate copy of pinned Snort commit
`14aeb09f5a0856812dbe08ead3c21f99e8860aa0`, containing all repairs through
[fragment pressure](fragment-pressure.md). Preserve its baseline source and
executable with `build_snapshot.py`. Save the preceding plugin sources and
build report before editing them. Apply:

```sh
python3 native-snort3/patches/apply_home_address_repair.py \
  --upstream /path/to/clean/pinned/snort3 \
  --target-source /path/to/separate/source-copy
```

Rebuild the engine in the same configured tree and rebuild the plugin with
`plugins/build.py --sanitize-tests`. Use `record_home_address_build.py` with
`--build-root`, `--previous-build-root`, `--upstream` and `--report` to recreate
the [engine record](../home-address-build-validation.json). Use
`record_home_address_plugin.py` with `--baseline-source`,
`--baseline-build-report`, `--repaired-build-report` and `--report` for the
plugin record. These are local build records, not hermetic attestations.

Run `tests/home_address_replay.py` against each engine/plugin combination,
using `--snort`, `--plugin-path` and separate `--report` files. Compare with
`tests/compare_home_addresses.py`, supplying `--baseline-report`,
`--repaired-report`, `--build-report`, `--plugin-report` and `--report`.
Run `tests/ipv6_fragment_header_audit.py` and
`tests/ipv6_fragment_prefix_audit.py` separately with the same three replay
arguments and distinct report paths; their current nonzero exits must not be
treated as passing gates.

Verified local artifacts:

- Engine: `/private/tmp/ax-snort-home-address-repair/repaired/snort`, SHA-256
  `78de00eeec69faba0f67a2692494c9070af4aeab5e674e454aa2b95fdd16a558`.
- Plugin: `/private/tmp/ax-home-address-plugin/ax_nd_options.so`, SHA-256
  `3dde09c3191beefd8ca35121762daa282631705cd7938d306f53732c1b83f6fb`.

No installation, live interface or deployment changed. Generated responses,
binding authentication, IPsec processing, other active routing types, hardware
offload and live endpoint behavior remain outside these tests. Full RFC/W3C
compliance and prevention of every unknown attack remain unproved.
