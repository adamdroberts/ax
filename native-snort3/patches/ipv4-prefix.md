# IPv4 fragment header, ECN and size repair

The preceding cumulative engine reconstructed IPv4 base headers from whichever
fragment completed reassembly. Changing a continuation's TTL therefore bypassed
a temporary rule that examined the reconstructed packet in 16 tested cases.
The engine also failed to combine congestion markings and could build datagrams
whose total size exceeded the IPv4 limit when offset-zero options were included.

This cumulative engine repair closes those reproduced bypasses. It preserves
the offset-zero base header, combines ECN observations and rejects impossible
reassembly sizes before fragment arithmetic and copying. It adds no product
rules or SIDs. The plugin and all preceding repairs are unchanged; loading
rules alone does not apply the engine repair.

## Standards and implementation

The header choice follows the reassembly procedure in
[RFC 791 section 3.2](https://www.rfc-editor.org/rfc/rfc791.html#section-3.2).
The tracker saves the first accepted offset-zero base header once, alongside
the existing saved options. Reconstruction restores it, clears fragmentation
fields as before, and updates total length and the IPv4 header checksum. Tests
compare the entire reconstructed frame, including TTL, DSCP, ECN, options,
lengths, header checksum and transport payload. Keeping the first accepted
offset-zero header on repeated fragments is the existing local first-option
policy extended to the base header; this does not assert a universal endpoint
overlap policy.

[RFC 3168 section 5.3](https://www.rfc-editor.org/rfc/rfc3168.html#section-5.3)
requires congestion information to survive reassembly or the datagram to be
dropped. The repair preserves CE from any contributing fragment and drops
CE/Not-ECT conflicts. Identical codepoints remain unchanged. For mixtures
without CE, where the section leaves the result unspecified, the engine uses
the offset-zero codepoint. Both IP versions use the same tested ECN-selection
helper.

Every fragment's extent is checked using wide arithmetic before insertion.
Before offset zero arrives, the check includes the minimum 20-byte IPv4 header.
Once it arrives, the known maximum extent must fit with its complete header,
including up to 40 option bytes, within the 65,535-byte total-length limit.
Reconstruction checks the actual destination-buffer capacity separately.
Captured header length, decoded payload span and fragment offset must agree.
An isolated high-offset fragment cannot wrap the legacy 16-bit geometry.

Failure retains the existing sticky tracker rejection, so retrying a fragment
or sending a later otherwise-valid fragment under the same ID does not resume
reassembly. The existing `prefix_drops` and `ecn_drops` counters now cover both
IP versions. The ECN drop reason is `ip_reassembly_ecn`. The additional state
is fixed-size, contains no new allocations, and resets with tracker cleanup.

## Evidence

The [matched comparison](../ipv4-prefix-comparison.json) covers **936 paired
cases / 1,872 native runs** using identical configurations, captures,
expectations and plugin bytes. The baseline passes 254 cases; the repaired
engine passes all 936. It closes all 16 header-policy bypass cases, strengthens
rejection in 219 cases and restores the reconstructed-byte expectation in
664 cases. These categories overlap.

The [replay](../ipv4-prefix-validation.json) includes 172 ECN rejection cases,
90 size rejection cases, 77 retries and 674 controls without a structural/ECN
rejection. Coverage includes TCP, checksummed and checksum-omitted IPv4 UDP,
ICMPv4, all selected two- and three-fragment ECN combinations, both or all
arrival orders, 20/24/60-byte headers, large original fragments and exact
total-length boundaries. Twenty-four cases exercise high-offset fragments
arriving without the first fragment and subsequent retries. Sixty-four use a
temporary TTL blocking policy with allowed controls. TTL 41 is a test value,
not an RFC violation; neither test rule enters the product catalog.

All 15 preceding native suites pass on this exact engine:

| Suite | Cases |
| --- | ---: |
| [General replay](../ipv4-prefix-repaired-engine/replay-validation.json), inline simulation | 156 |
| [Ordinary checksums](../ipv4-prefix-repaired-engine/checksum-validation.json) | 16 |
| [IP structure](../ipv4-prefix-repaired-engine/structure-validation.json), paired policies | 151 |
| [Next Header](../ipv4-prefix-repaired-engine/next-header-validation.json), paired policies | 256 |
| [Fragment checksums](../ipv4-prefix-repaired-engine/fragment-checksum-validation.json) | 312 |
| [Structure and Type 2](../ipv4-prefix-repaired-engine/cumulative-validation.json) | 241 |
| [IPv4 source routes](../ipv4-prefix-repaired-engine/ipv4-route-validation.json) | 236 |
| [IPv4 fragment options](../ipv4-prefix-repaired-engine/fragment-options-validation.json) | 320 |
| [Fragment lifetimes](../ipv4-prefix-repaired-engine/fragment-lifetime-validation.json) | 372 |
| [Fragment pressure](../ipv4-prefix-repaired-engine/fragment-pressure-validation.json) | 270 |
| [Home Address](../ipv4-prefix-repaired-engine/home-address-validation.json) | 354 |
| [IPv6 header policies](../ipv4-prefix-repaired-engine/header-retention-validation.json) | 144 |
| [Home Address wire-prefix oracle](../ipv4-prefix-repaired-engine/home-wire-prefix-validation.json) | 48 |
| [IPv6 prefix, ECN and size](../ipv4-prefix-repaired-engine/ipv6-prefix-validation.json) | 816 |
| [Large IPv4 fragments](../ipv4-prefix-repaired-engine/wide-ipv4-validation.json) | 72 |

The [pure-helper record](../ipv4-prefix-parser-validation.json) contains
2,636,406 assertions under AddressSanitizer and UndefinedBehaviorSanitizer,
including all IPv4 header lengths and fragment offsets, total-length
boundaries, truncated allocations, ECN arrival permutations, and 100,000
arbitrary spans plus 100,000 random capacity combinations. Native allocation
and cleanup are tested separately from these pure helpers.

The [native AddressSanitizer record](../ipv4-prefix-asan-validation.json)
binds an instrumented engine to the same complete source snapshot as the
release build. All 2,466 cases pass: 936 IPv4 prefix cases, 816 IPv6 prefix
cases, 72 large IPv4 fragment cases, 270 pressure cases and 372 lifetime cases.
Original and forwarded packet bytes, reconstructed bytes where observed,
verdicts and counters match the release runs. This does not establish leak
freedom, race freedom or instrumentation of the prebuilt plugin and external
libraries.

The reconstructed-frame logger retains the previously documented snaplen
metadata limitation: complete manufactured frames near the IPv4 maximum can
exceed its 65,535-byte global snaplen. The replay records 262 such log records
and checks actual bytes and each record's captured/original lengths. Every
original input fragment fits the DAQ capture limit; exact original-fragment
forwarding is checked separately. Preliminary oversized input fixtures were
corrected before producing the paired final evidence.

## Remaining limits

This repair covers observed fragment reconstruction behavior. Endpoint option
processing, source-route authorization, Mobile IPv6 bindings and logical
source grouping, IPsec authentication, complete IPv6 jumbograms, offload
equivalence, live multi-worker/failover behavior and deployment enforcement
remain outside this evidence. Outer encapsulation headers are still supplied
by the completing packet; the supplied profile limits IP nesting separately.
There is no new aggregate process-wide byte budget. Full RFC/W3C compliance
and prevention of every unknown attack remain unproved.

## Build and repeat

Start from a separate copy of pinned Snort commit
`14aeb09f5a0856812dbe08ead3c21f99e8860aa0` with all repairs through
[IPv6 prefix/ECN/size](ipv6-prefix.md). Preserve a baseline using
`build_snapshot.py`, then apply:

```sh
python3 native-snort3/patches/apply_ipv4_prefix_repair.py \
  --upstream /path/to/clean/pinned/snort3 \
  --target-source /path/to/separate/source-copy
```

Rebuild in the same configured tree and preserve the repaired snapshot.
`record_ipv4_prefix_build.py` takes `--build-root`, `--previous-build-root`,
`--upstream`, `--report` and `--parser-report` to verify the build and helper
records. The reviewable source delta is
[`snort-ipv4-prefix.patch`](snort-ipv4-prefix.patch).

Run `ipv4_prefix_replay.py` against both binaries with `--snort`,
`--plugin-path` and `--report`. Keep the baseline and repaired reports separate;
`compare_ipv4_prefixes.py --report ...` checks their bindings. Repeat the
15 suites above against the final executable. The build and replay records
include exact source and configuration hashes.

For native memory-safety checks, build another copy of the final source using
the same configuration plus `-DENABLE_ADDRESS_SANITIZER=ON`. Run
`ipv4_prefix_replay.py`, `ipv6_prefix_replay.py`,
`wide_ipv4_fragment_replay.py`, `fragment_pressure_replay.py` and
`fragment_lifetime_replay.py` with
`ASAN_OPTIONS=halt_on_error=1:abort_on_error=1`, preserving separate reports.
`record_ipv4_prefix_asan.py` takes `--build-root`, `--release-build-root`,
`--harness` and `--report` and verifies source, configuration and replay
bindings. The local sanitizer executable is
`/private/tmp/ax-snort-ipv4-prefix-asan/repaired/snort`, SHA-256
`6d0a1b3305415bd7a69e747489d75850f202613511c3d70e708f36a44a769d79`.

The [local build record](../ipv4-prefix-build-validation.json) identifies
`/private/tmp/ax-snort-ipv4-prefix-repair/repaired/snort`, SHA-256
`af84e9dfb21123422b9ed233c10a4dc2ccb1b810774733e5561dc096ac61f6d9`.
The unchanged plugin is `/private/tmp/ax-home-address-plugin/ax_nd_options.so`,
SHA-256 `3dde09c3191beefd8ca35121762daa282631705cd7938d306f53732c1b83f6fb`.
These are local build records, not hermetic attestations. Nothing was installed
or deployed and no live interface was opened.
