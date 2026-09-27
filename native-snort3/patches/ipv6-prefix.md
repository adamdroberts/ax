# IPv6 fragment prefix, ECN and size repair

The preceding engine rebuilt IPv6 headers from the fragment that completed
reassembly. An agent could therefore change the reconstructed Hop Limit by
changing a continuation fragment. A temporary rule that examined defragmented
traffic was bypassed in 18 tested cases. Large fragments also exposed signed
16-bit length handling, and reassembly did not preserve congestion information
across fragments.

This cumulative engine repair closes the 18 demonstrated policy bypasses,
preserves the offset-zero IPv6 prefix, aggregates ECN, and validates the final
size. It adds no rule or SID. The structural plugin is unchanged from the
[Home Address repair](home-address.md); the native engine must be rebuilt.

## Standards and implementation

[RFC 8200 section 4.5](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.5)
retains the offset-zero fragment's preceding headers. Other fragments can
carry different preceding headers and Fragment Next Header values. The engine
now saves the selected IPv6 base header and its preceding extensions once,
including their decoded layer descriptions. Reconstruction removes Fragment,
uses its offset-zero Next Header, and updates the resulting lengths. Tests
compare the complete reconstructed bytes, including Hop Limit, Traffic Class,
Flow Label and extension contents.

[RFC 3168 section 5.3](https://www.rfc-editor.org/rfc/rfc3168.html#section-5.3)
requires reassembly to preserve congestion indications. The repair retains CE
from any contributing fragment and rejects CE combined with Not-ECT. Identical
codepoints remain unchanged. For mixtures without CE, whose precise result
that section leaves unspecified, this implementation retains the offset-zero
codepoint; this is an implementation choice, not an additional RFC requirement.

The engine checks fragment extent before first/last-fragment arithmetic and
checks it again against the known offset-zero prefix. It rejects a selected
IPv6 payload above 65,535 bytes, then checks the complete reconstruction against
the actual packet buffer before copying. Signed overlap adjustments use
32-bit values so valid fragment lengths above 32,767 bytes remain positive.
That arithmetic is shared with IPv4 and has a separate large-fragment replay.

Native packet formatting also checks its captured source and destination
capacity before copying a prefix. It no longer assumes every IPv6 prefix fits
within an Ethernet MTU. Framing and semantic validation still use the existing
decoder and structural guards.

The saved prefix belongs to one tracker. Completion, rejection, expiration and
resource cleanup free it with the stored fragments. Bounds use captured bytes,
IP lengths, configured layer limits and the existing fragment-node budget.
There is no new process-wide byte budget; the supplied profile's eight-extension
limit permits at most seven pre-fragment extensions in this path. ECN or prefix
rejection retains a sticky drop until the existing tracker retention ends.
Native `ecn_drops` and `prefix_drops` counters distinguish these rejection paths.

## Evidence

The [comparison](../ipv6-prefix-comparison.json) binds **1,008 paired cases /
2,016 native runs** to matched source builds and the unchanged plugin:

| Suite | Baseline | Repaired |
| --- | ---: | ---: |
| [Prefix, ECN and size](../ipv6-prefix-validation.json) | 213 / 816 | 816 / 816 |
| [Header observation and blocking policies](../ipv6-prefix-repaired-engine/header-retention-validation.json) | 108 / 144 | 144 / 144 |
| [Home Address wire-prefix oracle](../ipv6-prefix-repaired-engine/home-wire-prefix-validation.json) | 30 / 48 | 48 / 48 |

The 816-case suite includes 156 ECN rejections, 66 size rejections, 57 retry
cases and 594 valid controls. It covers all selected two- and three-fragment
ECN combinations, reversed and permuted arrival, different extension lengths,
up to seven maximum-length extension headers, differing continuation Next
Header values, large original fragments, and IPv6 payload boundaries. Compared
with baseline, rejection improves in 176 cases and valid forwarding is restored
in 12. The reconstructed-byte expectation is corrected in 591 cases; these
categories overlap.

The 144-run header suite contains 72 wire cases under observation and blocking
policies. All 18 original blocking bypasses now fail to bypass. The threshold
used by the temporary blocking rule is a local test policy, not a rule declaring
a particular Hop Limit invalid. None of these observation rules enter the
product catalog.

The [72-case IPv4 regression](../ipv6-prefix-repaired-engine/wide-ipv4-validation.json)
also passes. It checks maximum-size datagrams across TCP, UDP and ICMPv4, large
original fragments, both arrival orders, checksum errors and retries.

All eleven preceding native suites pass on the final engine:

| Suite | Cases |
| --- | ---: |
| [General replay](../ipv6-prefix-repaired-engine/replay-validation.json), inline simulation | 156 |
| [Ordinary checksums](../ipv6-prefix-repaired-engine/checksum-validation.json) | 16 |
| [IP structure](../ipv6-prefix-repaired-engine/structure-validation.json), paired policies | 151 |
| [Next Header](../ipv6-prefix-repaired-engine/next-header-validation.json), paired policies | 256 |
| [Fragment checksums](../ipv6-prefix-repaired-engine/fragment-checksum-validation.json) | 312 |
| [Structure and Type 2](../ipv6-prefix-repaired-engine/cumulative-validation.json) | 241 |
| [IPv4 source routes](../ipv6-prefix-repaired-engine/ipv4-route-validation.json) | 236 |
| [IPv4 fragment options](../ipv6-prefix-repaired-engine/fragment-options-validation.json) | 320 |
| [Fragment lifetimes](../ipv6-prefix-repaired-engine/fragment-lifetime-validation.json) | 372 |
| [Fragment pressure](../ipv6-prefix-repaired-engine/fragment-pressure-validation.json) | 270 |
| [Home Address](../ipv6-prefix-repaired-engine/home-address-validation.json) | 354 |

The [pure-helper sanitizer record](../ipv6-prefix-parser-validation.json)
contains 2,916,560 assertions, including 100,000 arbitrary captured spans and
100,000 random size combinations, under AddressSanitizer and
UndefinedBehaviorSanitizer. These helper tests are separate from native replay.

The [native AddressSanitizer record](../ipv6-prefix-asan-validation.json) binds
a second engine build to the same complete source snapshot. All 1,530 cases
across the 816-case prefix suite, 72 large-fragment IPv4 cases, 270 pressure
cases and 372 lifetime cases pass without AddressSanitizer errors. Input bytes,
forwarded bytes and DAQ verdicts match the release build. These runs exercise
native allocation and cleanup; they do not prove leak freedom, concurrency
safety, or instrumentation of the prebuilt plugin and external libraries.

The complete reconstructed-byte test enables the native packet logger through
Lua and uses a temporary `flow:only_frag` log rule. CLI logging mode is not used
because it can disable inspection or replace the configured output list. The
pinned logger declares a 65,535-byte global snaplen but writes complete
manufactured frames above that value near the IPv6 payload maximum. The report
identifies 168 such records and checks their actual bytes and individual
captured/original lengths. This diagnostic logger metadata limitation does not
change the original-fragment DAQ verdict checks.

## Remaining limits

The 48 Home Address cases establish an offset-zero **wire-prefix** oracle only.
Headers preceding Fragment require endpoint processing before queueing. Mobile
IPv6 can change logical source identity, and ownership/binding authentication
requires endpoint state. Restoring wire headers alone does not establish those
semantics or prove that all heterogeneous Home Address fragments belong to one
authorized endpoint context.

The subsequent [IPv4 header repair](ipv4-prefix.md) adds first-header retention,
ECN aggregation and total-size checks for IPv4. Neither repair establishes other
endpoint option processing, IPsec authentication, hardware-offload equivalence, live
multi-worker or failover behavior, or deployment enforcement. Full RFC/W3C
compliance and protection against every unknown attack remain unproved.

## Build and repeat

Start from a separate source copy of Snort commit
`14aeb09f5a0856812dbe08ead3c21f99e8860aa0` with all repairs through
[Home Address](home-address.md). Preserve the baseline with `build_snapshot.py`,
then apply:

```sh
python3 native-snort3/patches/apply_ipv6_prefix_repair.py \
  --upstream /path/to/clean/pinned/snort3 \
  --target-source /path/to/separate/source-copy
```

Rebuild in the same configured tree and preserve the new snapshot. Use
`record_ipv6_prefix_build.py` with `--build-root`, `--previous-build-root`,
`--upstream`, `--report` and `--parser-report` to reproduce the build and helper
records. Run `ipv6_prefix_replay.py`, `ipv6_fragment_header_audit.py` and
`ipv6_fragment_prefix_audit.py` against both binaries, keeping separate reports.
Each replay takes `--snort`, `--plugin-path` and `--report`. Repeat the eleven
preceding suites and `wide_ipv4_fragment_replay.py` against the final binary.
`compare_ipv6_prefixes.py --report ...` verifies the paired records.

For the native sanitizer run, copy the final source into another build tree,
use the same configuration with `-DENABLE_ADDRESS_SANITIZER=ON`, and preserve
the result with `build_snapshot.py`. Run `ipv6_prefix_replay.py`,
`wide_ipv4_fragment_replay.py`, `fragment_pressure_replay.py` and
`fragment_lifetime_replay.py` with
`ASAN_OPTIONS=halt_on_error=1:abort_on_error=1`. Keep the sanitizer reports
separate. `record_ipv6_prefix_asan.py` binds the build, harness and replay
reports; its recorded configuration lists the exact local compiler settings.

The [local build record](../ipv6-prefix-build-validation.json) identifies the
final executable at `/private/tmp/ax-snort-ipv6-prefix-repair/repaired/snort`,
SHA-256 `300586623515a42150f20cb69469824f52a768304e1f2bf98e3837cf44d10429`.
The plugin remains `/private/tmp/ax-home-address-plugin/ax_nd_options.so`,
SHA-256 `3dde09c3191beefd8ca35121762daa282631705cd7938d306f53732c1b83f6fb`.
These are local build records, not hermetic attestations. Nothing was installed
or deployed and no live interface was opened.
