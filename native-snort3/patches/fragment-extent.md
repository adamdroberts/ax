# Fragment final-length and coverage repair

The preceding cumulative engine could accept disjoint fragments that declared
different final lengths. It used the largest observed length and could reconstruct
them as one datagram, despite their contradictory last-fragment flags. Six initial
TCP, UDP and ICMP probes across both IP versions were completely forwarded and
reconstructed with valid transport checksums. Existing overlap checks could not
reject these cases because their byte ranges did not overlap.

This repair makes the final length consistent across a tracked datagram and
requires exact, continuous byte coverage before reconstruction. On a length
conflict it drops the current fragment, frees saved buffers and retains rejection
state for subsequent fragments and retries. It adds no product rules or SIDs.
The plugin and rule profiles remain unchanged; deployment requires a rebuilt
native engine.

## Standards and strict policy

[RFC 791 sections 2.3 and 3.2](https://www.rfc-editor.org/rfc/rfc791.html#section-3.2)
define fragment positions and derive total data length from the last fragment.
[RFC 8200 section 4.5](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.5)
likewise defines the M flag and computes reconstructed length from the final
fragment's offset and length. These fields must describe a consistent datagram
before its bytes can be reconstructed.

The strict policy here abandons a tracked context when those declarations
conflict. The RFCs' field definitions do not establish one universal endpoint
reaction to every contradictory sequence; this rejection policy deliberately
avoids choosing among conflicting reconstructions. It applies to both IP
versions and all endpoint policies and overlap thresholds. Repeated final
declarations with the same endpoint are left to the separate overlap policy.

A fixed-size, trivial tracker field records the greatest endpoint of any
non-final fragment and the declared final endpoint, when known. A non-final
fragment must end strictly before a known final endpoint. A final declaration
must agree with a previous final declaration and extend beyond every previously
observed non-final fragment. The comparison works in either arrival order and
uses 32-bit arithmetic. Failed observations leave the saved geometry unchanged.
Existing header/size, option and overlap checks retain precedence.

The completion check now walks the ordered fragment list from byte zero to the
declared endpoint. Every node must have positive length and start exactly where
the preceding node ends; the final node must end at the declared boundary.
An aggregate byte count alone no longer establishes completion, since bytes
outside the declared datagram could otherwise compensate for a missing range.
Ordinary gaps remain pending until their missing bytes arrive or the existing
timeout expires.

Length rejection uses the existing oversized-fragment event and adds
`extent_drops` and `ip_reassembly_extent` diagnostics. Rejection is independent
of event-queue action selection. Buffer cleanup resets the geometry; rejection
flags survive until normal tracker retention or capacity-quarantine handling
permits a new context. There are no new dynamic allocations.

The new suite includes continuation Next Header variations for its fixture IDs.
The preceding prefix repair retains the offset-zero value, as RFC 8200 requires.
A broader identifier audit subsequently found that ICMP-specific conversions
in the shared flow-key helpers can split a datagram into separate trackers for
other IDs. That separate defect is addressed by the subsequent
[fragment identity repair](fragment-identity.md).

## Evidence

The [matched comparison](../fragment-extent-comparison.json) covers **840 paired
cases / 1,680 native runs**. All repaired cases pass, including **168 valid
controls**, **624 retry cases** and **12 fresh-ID controls**. Categories overlap.
Tests cover TCP, UDP and ICMP in both IP versions, all seven endpoint policies,
overlap thresholds zero/one/eight, both arrival directions, option/extension
padding, differing continuation Next Header values and 48 large-fragment cases.

The baseline passed 228 forwarding checks; the repaired engine passes 840,
correcting **612 forwarding failures**. It also removes extra reconstructions
in **624 cases**. Those categories overlap and are not counts of distinct
vulnerabilities. The 168 valid controls already passed before repair. Remaining
baseline failures include counters and cleanup behavior; they are not additional
forwarding bypasses. The [baseline](../fragment-extent-baseline-validation.json)
and [repaired](../fragment-extent-validation.json) reports preserve these details.

An independent oracle parses the serialized fragments and compares each length
declaration with earlier declarations. It checks completion using per-byte
occupancy rather than the native aggregate state. A completed identity is freed,
so later traffic is not incorrectly treated as part of a finished datagram.
Expected original-packet forwarding, actual inline file DAQ verdicts, checksum
errors, fragment nodes, reassemblies and rejection counters are compared.

All **17 preceding regression suites / 5,840 cases** pass on the final engine:

| Suite | Cases |
| --- | ---: |
| [Protocol replay](../fragment-extent-repaired-engine/replay-validation.json) | 156 |
| [Checksums](../fragment-extent-repaired-engine/checksum-validation.json) | 16 |
| [IP structures](../fragment-extent-repaired-engine/structure-validation.json) | 151 |
| [Next Header policy](../fragment-extent-repaired-engine/next-header-validation.json) | 256 |
| [Fragment checksums](../fragment-extent-repaired-engine/fragment-checksum-validation.json) | 312 |
| [Cumulative Type 2 and structure checks](../fragment-extent-repaired-engine/cumulative-validation.json) | 241 |
| [IPv4 source routes](../fragment-extent-repaired-engine/ipv4-route-validation.json) | 236 |
| [IPv4 fragment options](../fragment-extent-repaired-engine/fragment-options-validation.json) | 320 |
| [Fragment lifetimes](../fragment-extent-repaired-engine/fragment-lifetime-validation.json) | 372 |
| [Fragment pressure](../fragment-extent-repaired-engine/fragment-pressure-validation.json) | 270 |
| [Home Address](../fragment-extent-repaired-engine/home-address-validation.json) | 354 |
| [IPv6 header policies](../fragment-extent-repaired-engine/header-retention-validation.json) | 144 |
| [Home Address wire-prefix oracle](../fragment-extent-repaired-engine/home-wire-prefix-validation.json) | 48 |
| [IPv6 prefix, ECN and size](../fragment-extent-repaired-engine/ipv6-prefix-validation.json) | 816 |
| [Large IPv4 fragments](../fragment-extent-repaired-engine/wide-ipv4-validation.json) | 72 |
| [IPv4 header, ECN and size](../fragment-extent-repaired-engine/ipv4-prefix-validation.json) | 936 |
| [Fragment overlaps](../fragment-extent-repaired-engine/overlap-validation.json) | 1,140 |

The [pure-helper record](../fragment-extent-parser-validation.json) contains
**1,351,548 assertions** under AddressSanitizer and UndefinedBehaviorSanitizer.
It compares length observations against an independent pairwise history oracle,
exercises every wire offset at selected length boundaries, checks unchanged
state after rejection, and includes 100,000 random sequences plus 100,000
coverage lists. Contiguous lists, holes, overlaps, cycles, zero-length nodes
and maximum endpoint boundaries are covered.

The [native AddressSanitizer record](../fragment-extent-asan-validation.json)
contains **4,766 passing cases** across eight suites. The instrumented build
matches the complete release source snapshot, and packet verdicts, bytes and
counters agree with the release runs. These finite checks do not establish leak freedom, race
freedom or instrumentation of the prebuilt plugin and external dependencies.

## Remaining limits

Previously forwarded fragments cannot be recalled. Tracker retention, ID reuse,
flow capacity and quarantine remain bounded as documented in the preceding
repairs. An attacker able to inject a conflicting fragment can cause strict
rejection of a legitimate datagram; this change does not authenticate fragments.
Endpoint behavior, stateful routing and Mobile IPv6, IPsec authentication,
complete IPv6 jumbograms, live worker/failover behavior and deployed enforcement
remain outside this evidence. Full RFC/W3C compliance and prevention of every
unknown attack remain unproved.

## Build and repeat

Start with a separate source copy of pinned Snort commit
`14aeb09f5a0856812dbe08ead3c21f99e8860aa0` containing all repairs through
[fragment overlap rejection](fragment-overlap.md). Preserve a baseline with
`build_snapshot.py`, then apply:

```sh
python3 native-snort3/patches/apply_fragment_extent_repair.py \
  --upstream /path/to/clean/pinned/snort3 \
  --target-source /path/to/separate/source-copy
```

Rebuild in the same configured tree and preserve the repaired snapshot.
`record_fragment_extent_build.py` takes `--build-root`,
`--previous-build-root`, `--upstream`, `--report` and `--parser-report`.
It verifies the source/build bindings and runs the sanitizer helper checks.
The reviewable native delta is [`snort-fragment-extent.patch`](snort-fragment-extent.patch).

Run `native-snort3/tests/fragment_extent_replay.py` against both binaries with
`--snort`, `--plugin-path` and separate `--report` paths, then run
`compare_fragment_extents.py --report ...`. Repeat the 17 regression suites
against the final executable.

For native sanitizer checks, copy the final source and build with the same
configuration plus `-DENABLE_ADDRESS_SANITIZER=ON`. Repeat the eight suites
named in the sanitizer record with
`ASAN_OPTIONS=halt_on_error=1:abort_on_error=1`.
`record_fragment_extent_asan.py` verifies these records using `--build-root`,
`--release-build-root`, `--harness` and `--report`.

The [local build record](../fragment-extent-build-validation.json) identifies
`/private/tmp/ax-snort-fragment-extent-repair/repaired/snort`, SHA-256
`263796db94fa03709c7c3d71f21d9bfbd1ed51cf5b9ada260f3047621af956a3`.
The sanitizer executable is
`/private/tmp/ax-snort-fragment-extent-asan/repaired/snort`, SHA-256
`caa6cb3feeff71c7e2cad434cf9f312f4ded6e39f67478cb5e99d2a7eaa66ee4`.
The unchanged plugin is `/private/tmp/ax-home-address-plugin/ax_nd_options.so`,
SHA-256 `3dde09c3191beefd8ca35121762daa282631705cd7938d306f53732c1b83f6fb`.
These are local build records, not hermetic attestations. Nothing was installed
or deployed and no live interface was opened.
