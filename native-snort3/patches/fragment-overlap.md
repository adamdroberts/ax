# Fragment overlap rejection and buffer release

The preceding cumulative engine made IPv6 overlap rejection depend on a
configurable overlap threshold and endpoint policy. With permissive settings,
it forwarded overlapping fragments that must abandon IPv6 reassembly. The
supplied strict profile already blocked the tested overlaps, but retained
fragment buffers after rejection. That could exhaust its node allowance and
block an unrelated, valid fragmented datagram.

This repair rejects IPv6 overlaps regardless of those settings and immediately
releases the rejected datagram's buffers. IPv4 uses the same early rejection
when its configured threshold is one, as in the supplied profile. The tracker
retains rejection state so later fragments and retries cannot restart that
datagram during its existing retention period. No product rules or SIDs are
added, and the plugin is unchanged. Loading rules alone does not apply this
native engine change.

## Standards and implementation

[RFC 8200 section 4.5](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.5)
requires abandoning IPv6 reassembly when fragments overlap and discarding the
buffered pieces without an ICMP error. It allows an optional exception for
exact duplicates; this implementation deliberately does not use that exception.
Duplicate fragments therefore reject the tracked datagram even when their
bytes agree. [RFC 5722 section 4](https://www.rfc-editor.org/rfc/rfc5722.html#section-4)
also requires discarding subsequent constituent fragments.

The IPv4 threshold of one is a strict local policy, not a universal RFC ban on
IPv4 overlaps. IPv4 thresholds of zero or greater than one retain the existing
endpoint-policy behavior. IPv6 always uses the new rejection path, including
when `max_overlaps` is zero or eight. The parameter's help text now explains
that distinction.

Before updating first/last-fragment geometry, capturing a prefix, trimming
payload or allocating a payload node, the engine checks the incoming half-open
byte range against stored ranges. Touching adjacent ranges do not overlap.
The ordered scan is bounded by the existing fragment-node allowance, uses
32-bit arithmetic and allocates no new overlap state. Existing IPv4 option
validation takes precedence so its rejection reason remains stable on retries.

A conflict raises the existing overlap event, marks the tracker rejected and
frees its fragment list, saved options and prefix storage through the existing
cleanup path. The new `overlap_drops` counter and `ip_reassembly_overlap` reason
cover the conflicting fragment and subsequent tracked drops. Rejected retries
do not rescan the list or allocate replacement payload nodes. Existing lifetime,
capacity quarantine and tracker cleanup rules still apply.

## Evidence

The [matched comparison](../fragment-overlap-comparison.json) checks **1,140
paired cases / 2,280 native runs** with identical inputs, expectations,
configuration and plugin bytes. All 1,140 repaired cases pass.

| Observed difference | Cases |
| --- | ---: |
| IPv6 rejection restored under permissive overlap settings | 348 |
| Valid traffic restored after rejected-buffer cleanup | 24 |
| Strict-threshold forwarding checks already correct before repair | 732 |

The baseline passes 768 forwarding checks. Only 108 baseline cases pass every
check because the other checks also require prompt node release and the new
counter. Those counter/cleanup failures are not additional forwarding bypasses.
The [baseline record](../fragment-overlap-baseline-validation.json) and
[repaired record](../fragment-overlap-validation.json) preserve the distinction.

The suite covers TCP, UDP and ICMP for both IP families; all seven configured
endpoint policies; partial, contained, same-start, same-end and duplicate
overlaps; changed and identical payloads; selected arrival orders; and options
or extension padding. It includes 108 adjacent valid controls, 960 retry cases,
24 cleanup controls and 48 cases with large fragment extents. These categories
overlap. Changed payloads preserve the complete transport checksum so checksum
failure cannot conceal an overlap result.

An independent byte-occupancy oracle determines rejection and expected output.
It releases a successfully completed identity and does not label later pieces
as overlaps of a datagram already delivered. The checks compare exact original
and forwarded packet bytes, actual file-only inline DAQ verdicts, fragment-node
creation/deletion, reassembly counts and resource/overlap drops. The cleanup
controls use a two-node allowance and send fresh valid traffic immediately
after rejection, before retries could incidentally free the old buffers.

All **16 preceding suites, comprising 4,700 cases**, also pass on the final
release executable. Some suites contain paired runs or overlapping coverage;
this is a regression case count, not a count of unique vulnerabilities.

| Suite | Cases |
| --- | ---: |
| [Protocol replay](../fragment-overlap-repaired-engine/replay-validation.json) | 156 |
| [Checksums](../fragment-overlap-repaired-engine/checksum-validation.json) | 16 |
| [IP structures](../fragment-overlap-repaired-engine/structure-validation.json) | 151 |
| [Next Header policy](../fragment-overlap-repaired-engine/next-header-validation.json) | 256 |
| [Fragment checksums](../fragment-overlap-repaired-engine/fragment-checksum-validation.json) | 312 |
| [Cumulative Type 2 and structure checks](../fragment-overlap-repaired-engine/cumulative-validation.json) | 241 |
| [IPv4 source routes](../fragment-overlap-repaired-engine/ipv4-route-validation.json) | 236 |
| [IPv4 fragment options](../fragment-overlap-repaired-engine/fragment-options-validation.json) | 320 |
| [Fragment lifetimes](../fragment-overlap-repaired-engine/fragment-lifetime-validation.json) | 372 |
| [Fragment pressure](../fragment-overlap-repaired-engine/fragment-pressure-validation.json) | 270 |
| [Home Address](../fragment-overlap-repaired-engine/home-address-validation.json) | 354 |
| [IPv6 header policies](../fragment-overlap-repaired-engine/header-retention-validation.json) | 144 |
| [Home Address wire-prefix oracle](../fragment-overlap-repaired-engine/home-wire-prefix-validation.json) | 48 |
| [IPv6 prefix, ECN and size](../fragment-overlap-repaired-engine/ipv6-prefix-validation.json) | 816 |
| [Large IPv4 fragments](../fragment-overlap-repaired-engine/wide-ipv4-validation.json) | 72 |
| [IPv4 header, ECN and size](../fragment-overlap-repaired-engine/ipv4-prefix-validation.json) | 936 |

The [native AddressSanitizer record](../fragment-overlap-asan-validation.json)
binds an instrumented engine to the same complete source snapshot as the release
build. All **3,926 cases** pass across overlap, IPv4/IPv6 prefix, large-fragment,
option, pressure and lifetime suites. Observed packet bytes, verdicts and
counters match the release runs. This is finite native memory-safety testing;
it does not establish leak freedom, race freedom or instrumentation of the
prebuilt plugin and external libraries.

## Remaining limits

An inline inspector cannot recall fragments forwarded before the overlap was
observable. Rejection memory has bounded lifetime and capacity; its existing
expiry and quarantine controls remain part of the security boundary. Completed
datagrams, later ID reuse and endpoint reassembly lifetimes are distinct from
an active overlapping context. Dropping an entire exact-duplicate context can
also reject legitimate network duplication.

The preceding repairs' limits remain: stateful endpoint options and Mobile IPv6
bindings, ultimate-route authorization, IPsec authentication, complete IPv6
jumbograms, aggregate process memory, live worker/failover behavior and deployment
enforcement are not established here. This closes reproduced behaviors, not all
RFC/W3C requirements or every unknown attack.

## Build and repeat

Start from a separate copy of pinned Snort commit
`14aeb09f5a0856812dbe08ead3c21f99e8860aa0` with every repair through
[IPv4 header/ECN/size](ipv4-prefix.md). Preserve the baseline using
`build_snapshot.py`, then apply:

```sh
python3 native-snort3/patches/apply_fragment_overlap_repair.py \
  --upstream /path/to/clean/pinned/snort3 \
  --target-source /path/to/separate/source-copy
```

Rebuild in the same configured tree and preserve the repaired snapshot.
`record_fragment_overlap_build.py` takes `--build-root`,
`--previous-build-root`, `--upstream` and `--report` to verify exact source,
configuration and binary bindings. The reviewable delta is
[`snort-fragment-overlap.patch`](snort-fragment-overlap.patch).

Run `native-snort3/tests/fragment_overlap_replay.py` against both executables
with `--snort`, `--plugin-path` and `--report`, keeping baseline and repaired
reports separate. `compare_fragment_overlaps.py --report ...` checks their
bindings. Repeat the 16 regression suites above against the final executable.

For sanitizer checks, build another copy of the final source with the same
configuration plus `-DENABLE_ADDRESS_SANITIZER=ON`. Repeat the seven suites
named in the sanitizer record with
`ASAN_OPTIONS=halt_on_error=1:abort_on_error=1`.
`record_fragment_overlap_asan.py` takes `--build-root`, `--release-build-root`,
`--harness` and `--report` and verifies source, build and replay agreement.

The [local build record](../fragment-overlap-build-validation.json) identifies
`/private/tmp/ax-snort-fragment-overlap-repair/repaired/snort`, SHA-256
`8d5d77f559865164e82ce2d6b2e6208dc85c6cff42de9f08d979021c25be41fb`.
The sanitizer executable is
`/private/tmp/ax-snort-fragment-overlap-asan/repaired/snort`, SHA-256
`6c27f4f60e83a66aebc5fda51f04022c4a52004d4657c79c6d7649f5a57ff990`.
The unchanged plugin is `/private/tmp/ax-home-address-plugin/ax_nd_options.so`,
SHA-256 `3dde09c3191beefd8ca35121762daa282631705cd7938d306f53732c1b83f6fb`.
These are local build records, not hermetic attestations. Nothing was installed
or deployed and no live interface was opened.
