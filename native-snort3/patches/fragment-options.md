# IPv4 fragment option consistency repair

The preceding cumulative Snort engine compares IPv4 fragment option lengths,
but does not consistently compare their presence, type, order or value. Its
zero-length sentinel misses absent options, and offset-zero options are not
compared with continuation options. It also rejects NOP padding on continuation
fragments and continues reconstructing datagrams after option errors.

The [source patch](snort-fragment-options.patch) adds bounded per-datagram
consistency checking to the native reassembler. It reuses the existing **123:1
drop rule**; no additional signature or duplicate SID is introduced. Loading
rules or the plugin alone cannot apply this change: rebuild the engine after
the Type 2, fragment checksum and IPv4 source-route checksum repairs.

## Standards and strict policy

[RFC 791 sections 3.1–3.2](https://www.rfc-editor.org/rfc/rfc791.html#section-3.1)
define selective copying of options during fragmentation. NOP and EOL may be
introduced or removed, and header padding is zero. The repair permits those
differences and permits non-copied options on the offset-zero fragment only.
[RFC 2113 section 2.1](https://www.rfc-editor.org/rfc/rfc2113.html#section-2.1)
requires Router Alert in every fragment. Its value is included in the comparison.
[RFC 1122 section 3.2.1.8](https://www.rfc-editor.org/rfc/rfc1122.html#section-3.2.1.8)
requires source-route processing before reassembly, so mutable recorded route
bytes must not be blindly compared.

The additional **local strict policy** requires each tracked fragment to agree
on the ordered copied-option types, lengths and multiplicity, Router Alert
values, and the ultimate destination selected by the preceding source-route
repair. These cross-fragment comparisons and sticky rejection are safeguards
against ambiguous reconstruction, not a claim that every endpoint is required
by an RFC to perform this exact comparison. A source-routing deployment can
have additional routing and datagram-identity requirements.

Unknown option data remains opaque. Source-route pointers and recorded path
bytes may differ while preserving geometry and the final destination. The
repair neither authorizes a route nor authenticates mutable or unknown options.

## Implementation

The parser reads at most the original 40-byte IPv4 option span. An explicit
`seen` flag distinguishes an empty option list from uninitialized state. Its
comparison state is 47 bytes, plus a flag recording whether the offset-zero
header has been saved. It uses fixed-size storage and no option-state heap
allocation. The original offset-zero option bytes are retained separately by
Snort for reconstruction, including their padding.

Options are checked before changing an existing tracker's fragment geometry
or inserting the arriving payload. An invalid first arrival also creates a
rejected tracker without storing its payload. A conflict marks that tracker
unusable for reconstruction. Every subsequent fragment re-queues event 123:1,
so the configured drop action applies to retries as well. In passive or
alert-only configurations, this does not provide inline packet blocking.

## Evidence

The [paired comparison](../fragment-options-comparison.json) checks **320
cases / 640 native engine runs**, using actual file-only inline DAQ verdicts
and exact forwarded packet bytes. It includes 156 valid controls, 92 retry
cases and eight controls checking that a different IPv4 ID remains usable
after a rejection. The preceding engine's failures are preserved in the
[baseline audit](../fragment-options-baseline-validation.json); its nonzero
exit is expected and is not counted as successful protection.

All 320 cases pass on the repaired engine. Of these, 86 conflicting-fragment
cases were previously entirely forwarded and now block; 54 valid cases that
were previously rejected are restored. The conflicted datagrams are not
reconstructed. The fresh-ID controls do reconstruct successfully.

The captures cover both arrival orders for two fragments, all six orders for
selected three-fragment cases, TCP, UDP with checksums, permitted IPv4 UDP
checksum omission, missing/added/reordered/duplicated options, changed Router
Alert values, changed final destinations, maximum option spans and mutable
opaque/route-record controls. A separate wire oracle checks original header
lengths and checksums, transport reconstruction and the first conflict.

The [parser record](../fragment-options-parser-validation.json) passes
**1,393,926 assertions**, including 100,000 deterministic random spans, with
AddressSanitizer and UndefinedBehaviorSanitizer enabled.

The cumulative engine also retains all existing native regression results:

| Suite | Cases |
| --- | ---: |
| [General replay](../fragment-options-repaired-engine/replay-validation.json), inline simulation | 156 |
| [Ordinary checksums](../fragment-options-repaired-engine/checksum-validation.json), actual file inline | 16 |
| [IP structure](../fragment-options-repaired-engine/structure-validation.json), paired policies | 151 |
| [Next Header](../fragment-options-repaired-engine/next-header-validation.json), paired policies | 256 |
| [Fragment checksums](../fragment-options-repaired-engine/fragment-checksum-validation.json) | 312 |
| [Structure and all prior Type 2 cases](../fragment-options-repaired-engine/cumulative-validation.json) | 241 |
| [IPv4 source routes](../fragment-options-repaired-engine/ipv4-route-validation.json) | 236 |

## Build and repeat

Use a separate source copy containing all three preceding repairs to pinned
Snort commit `14aeb09f5a0856812dbe08ead3c21f99e8860aa0`. Preserve a baseline
snapshot with [`build_snapshot.py`](build_snapshot.py), then apply:

```sh
python3 native-snort3/patches/apply_fragment_options_repair.py \
  --upstream /path/to/clean/pinned/snort3 \
  --target-source /path/to/separate/source-copy
```

Build and preserve a repaired snapshot using the same configured tree and
`build_snapshot.py`. The [build record](../fragment-options-build-validation.json)
checks full source snapshots, identical build configuration and the exact
two-reassembler-file plus helper change. It also verifies that the baseline
matches the preceding IPv4 route repair. This is local build evidence, not a
hermetic reproducible-build attestation.

The verified executable is
`/private/tmp/ax-snort-fragment-options-repair/repaired/snort`, SHA-256
`684f08201996eadf1966ba01322188ea09d0a46208150784167c40face7117e9`.
The matching baseline lives beside it in `baseline/snort`. No system
installation, service, network interface or deployment was changed.

Run `tests/fragment_options_replay.py` once per executable with `--snort`,
`--plugin-path` and distinct `--report` paths. The baseline exits 1. Recreate
build and parser evidence with `patches/record_fragment_options_build.py`,
supplying `--build-root`, `--previous-build-root`, `--upstream`, `--report`
and `--parser-report`. Finally, `tests/compare_fragment_options.py` accepts
`--baseline-report`, `--repaired-report`, `--build-report` and `--report`.
Run validation without Python optimization.

## Remaining limits

Earlier forwarded fragments cannot be recalled. Rejection lasts for the
current tracker; expiration, eviction, identifier reuse, overlap behavior and
queue exhaustion need separate lifecycle and endpoint tests. The fresh-ID
controls prove only their bounded isolation cases. A passive sensor cannot
provide the tested inline blocking, and deployment must place the repaired
engine on the actual traffic path.

The subsequent [fragment lifetime repair](fragment-lifetime.md) closes the
tested sliding-deadline, stale-expiration and short-idle-retention gaps. Its
timed tests do not cover every eviction, endpoint or deployment behavior.

Unknown option semantics, ultimate-route authorization, IPsec authentication,
other routing types, Home Address source options and complete jumbograms remain
separate work. This repair does not prove endpoint equivalence, universal RFC
or W3C compliance, or protection against all unknown attacks.
