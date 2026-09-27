# IPv4 source-route checksum repair

Snort 3.12.2.0 uses the IPv4 base destination to verify and update TCP/UDP
checksums, even when an active Loose or Strict Source and Record Route option
names a different final destination. The
[baseline audit](../ipv4-route-baseline-validation.json) reproduces both
directions of the error: correctly checksummed traffic is rejected, while
incorrect intermediate-destination checksums are accepted.

The checksum destination must be the ultimate destination for source-routed
TCP, as stated in [RFC 9293 section 3.9.2.1](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.9.2.1).
[RFC 791 section 3.1](https://www.rfc-editor.org/rfc/rfc791.html#section-3.1)
defines four-octet route entries and the route pointer's progression: the last
remaining entry is the final destination; once the pointer exceeds the option
length, the base destination applies. UDP uses the destination supplied by IP
for its pseudo-header, with option handling and invalid-checksum rejection
covered by [RFC 1122 sections 4.1.3.2–4.1.3.4](https://www.rfc-editor.org/rfc/rfc1122.html#section-4.1.3.2).

## Implementation

[`snort-ipv4-route-checksum.patch`](snort-ipv4-route-checksum.patch) applies after
the [Type 2](README.md) and [fragment checksum](fragment-checksums.md) repairs.
It changes TCP/UDP checksum verification and checksum update, and adds a bounded
IPv4 destination selector. A **rebuilt engine** is required. Rule IDs, rule
actions, the plugin ABI and flow addresses remain unchanged.

The selector walks only the original IHL option span, at most 40 bytes. It
handles LSRR and SSRR, active and completed pointers, NOPs and opaque options.
It never interprets payload or intervening AH bytes as options. Address bytes
are copied without requiring word alignment. Empty routes and pointers beyond
the option length remain valid and use the base destination.

Malformed or ambiguous source-route framing is rejected before either transport
checksum policy or IPv4 UDP checksum omission can bypass it. Partial address
slots, misaligned active pointers and duplicate source routes cannot silently
fall back to a different checksum destination. Active-slot alignment is strict
sender-format enforcement. Completed pointers are not required to remain
aligned. Errors raise the existing native IPv4-option event **116:4**, whose
action is already `drop`; checksum-error counters remain reserved for checksum
failures. Other transport protocols continue to use their existing structural
rules; this decoder addition is specific to TCP and UDP.

For IPv4 packets with options, TCP/UDP perform software checksum verification
instead of trusting generic DAQ checksum metadata that does not describe
source-route support. Valid IPv4 UDP zero checksums retain their existing
omission allowance. Live hardware metadata has not been exercised.

## Evidence

The [matched comparison](../ipv4-route-comparison.json) passes **236/236 paired
cases in 472 native engine runs**:

- 86 invalid cases that were previously forwarded are now blocked.
- 74 valid cases that were previously rejected are now accepted.
- All 126 valid cases are accepted with the expected bytes.
- 64 cases cover fragment arrival orders, including legal split TCP headers.
- 12 cases exercise TCP reserved-bit normalization or fixture-only payload
  rewriting, verifying TCP and UDP checksum updates after actual edits.
- 12 cases check malformed route geometry, including omitted UDP checksums.

Other cases cover LSRR/SSRR, intermediate and completed pointers, maximum IHL,
unaligned option locations, unknown option contents, AH and ordinary controls.
An independent wire oracle reconstructs the serialized datagram, advances the
route pointer slot by slot, and checks checksums with modular summation. It
also validates expected forwarded bytes after normalization.

The [repaired audit](../ipv4-route-validation.json) checks actual file-only
inline `dump:pcap` DAQ verdicts, exact emitted packets and checksum counters.
The baseline audit retains its 160 conformance failures and exits nonzero;
reproducing a failure is not counted as protection. No interface is opened.

The [pure parser report](../ipv4-route-parser-validation.json) records
**157,183 assertions**, including every pointer byte across both route types
and route lengths, plus 100,000 deterministic random spans, under AddressSanitizer
and UndefinedBehaviorSanitizer.

The cumulative engine retains the existing regression results:

| Suite | Result |
| --- | --- |
| [General replay](../ipv4-route-repaired-engine/replay-validation.json) | 156/156; inline simulation |
| [Ordinary checksums](../ipv4-route-repaired-engine/checksum-validation.json) | 16/16; actual file inline |
| [IP structure](../ipv4-route-repaired-engine/structure-validation.json) | 151/151; 302 actual file-inline runs |
| [Next Header](../ipv4-route-repaired-engine/next-header-validation.json) | 256/256; 512 actual file-inline runs |
| [Fragment checksums](../ipv4-route-repaired-engine/fragment-checksum-validation.json) | 312/312; actual file inline |
| [Structure and Type 2 follow-up](../ipv4-route-repaired-engine/cumulative-validation.json) | 241/241; 151 structure plus all 90 prior Type 2 cases |

The structure comparison now counts 88 cases blocked specifically by adding
its five rules, rather than the earlier engine's 91. The three other cases are
also blocked by the new native source-route validation. The original rule
matches still pass unchanged. The follow-up explicitly verifies both native
event 116:4 and rule 9201012, with no false checksum-error count, for those three
malformed routes.

## Build and repeat

Start with a separate copy of pinned official Snort commit
`14aeb09f5a0856812dbe08ead3c21f99e8860aa0` containing both preceding repairs.
Capture a baseline build using [`build_snapshot.py`](build_snapshot.py) before
applying this repair:

```sh
python3 native-snort3/patches/apply_ipv4_route_repair.py \
  --upstream /path/to/clean/pinned/snort3 \
  --target-source /path/to/separate/source-copy

python3 native-snort3/patches/build_snapshot.py \
  --source /path/to/separate/source-copy \
  --build /path/to/configured-build \
  --configure-manifest /path/to/configure-manifest.json \
  --output-dir /path/to/new-repaired-output
```

The applicator verifies the exact preceding codec/helper bytes before writing.
The [build record](../ipv4-route-build-validation.json) binds the two executables
to identical configuration, full source snapshots and the exact two-codec plus
helper delta. It also captures the configuration command and environment.
These are local build records, not hermetic reproducible-build attestations.

The verified cumulative executable is
`/private/tmp/ax-snort-ipv4-route-repair/repaired/snort`, SHA-256
`e031000e1e3e438aea1de0b638f943046f145a336360fc8aaa9488567e62c88f`.
The baseline is `/private/tmp/ax-snort-ipv4-route-repair/baseline/snort`;
it contains the Type 2 and fragment repairs but lacks this repair.
No system installation or deployment was performed. The older temporary
build/install directories do not acquire this repair automatically.

To repeat the paired audits, run the following once per binary, using distinct
output reports. The baseline audit is expected to exit 1:

```sh
python3 native-snort3/tests/ipv4_route_replay.py \
  --snort /private/tmp/ax-snort-ipv4-route-repair/repaired/snort \
  --plugin-path /private/tmp/ax-nd-plugin \
  --report native-snort3/ipv4-route-validation.json

python3 native-snort3/tests/compare_ipv4_routes.py \
  --baseline-report native-snort3/ipv4-route-baseline-validation.json \
  --repaired-report native-snort3/ipv4-route-validation.json \
  --build-report native-snort3/ipv4-route-build-validation.json \
  --report native-snort3/ipv4-route-comparison.json
```

For another machine/build, regenerate matched build evidence and replay the
captures with that binary and plugin. The supplied reports deliberately bind
the recorded executable, source, configuration, fixture and plugin hashes.

## Remaining scope

This selects checksum addresses; it does not authorize a source route, enforce
policy against its ultimate destination, authenticate route ownership or alter
flow identity. Generated responses and return-route state are not implemented
by this repair. AH fixtures validate visible framing, not IPsec authentication.

The fragment captures use matching copied options and bounded nonoverlapping
payloads. They do not prove consistent options across fragments, every overlap,
timeout or cache-pressure case, endpoint behavior, offload metadata or live
traffic placement. Home Address source options, other IPv6 routing types,
complete jumbograms and backend admission fencing remain separate work.
These checksums provide error detection, not authentication or protection
against all unknown attacks. Full RFC/W3C compliance remains unproved.
