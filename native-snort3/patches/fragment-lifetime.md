# Fixed fragment lifetime and timeout rejection

The preceding cumulative Snort engine restarts its fragment timer on every
arrival. A slow trickle can therefore keep reconstruction alive indefinitely.
For example, a four-fragment IPv6 datagram arriving at 0, 25, 50 and 75 seconds
was forwarded and reconstructed under the supplied 30-second profile.

A separate defect occurs at expiration: Snort frees stored payload fragments
but retains their byte counts and completion flags. A final fragment arriving
at the timeout can then trigger reconstruction using stale geometry. The
[baseline audit](../fragment-lifetime-baseline-validation.json) preserves these
failures; it passes only 48 of the 372 requested behaviors and exits nonzero.

The [native source repair](snort-fragment-lifetime.patch) measures lifetime from
the first arriving fragment, clears abandoned geometry, and rejects subsequent
fragments of that tracked datagram. It also retains the tracking entry beyond
the old short idle timeout. A rebuilt cumulative engine is required. No rule
IDs or signature counts change.

## Standards and local policy

[RFC 8200 section 4.5](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.5)
requires abandoning incomplete IPv6 reassembly within 60 seconds of the first
arriving fragment. Arrival of an offset-zero fragment later in the sequence
does not restart that deadline. The repair caps IPv6 reassembly at 60 seconds
even when the configured timeout is larger.

[RFC 1122 section 3.3.2](https://www.rfc-editor.org/rfc/rfc1122.html#section-3.3.2)
requires a reassembly timeout and recommends a fixed value between 60 and 120
seconds for IPv4. The existing profile's 30 seconds is a stricter **local IPS
budget**, not an RFC requirement. IPv4 uses the configured budget; IPv6 uses
the smaller of that budget and 60 seconds.

Blocking late fragments and retaining rejection state are additional local
IPS policy. The ordinary session and cache idle timeouts have a floor of
`max(configured timeout, 120 seconds)` for IPv4 and
`max(configured timeout, 60 seconds)` for IPv6, plus one second to cover the
cache's whole-second arithmetic. Longer pre-existing retention settings are
preserved. The floor is applied from configuration, so repeated setup cannot
increment it. Ordinary activity updates this idle retention, while it never
extends the separate reconstruction deadline.

These intervals do not prove equivalence with every endpoint timer or network
path. They do not authenticate fragment identifiers. They also do not enforce
every sender-side ID uniqueness rule described in
[RFC 6864](https://www.rfc-editor.org/rfc/rfc6864.html#section-4.3).

## Implementation

The patch changes two internal reassembly/session source files and adds a
small arithmetic helper. The helper preserves microsecond precision, avoids
signed overflow, caps IPv6 lifetimes and handles maximum timeout values.
Malformed or reversed DAQ timestamps cause rejection as a local fail-closed
policy; agent-controlled packet bytes do not supply these timestamps.

On expiration, Snort frees fragment payload and offset-zero option storage,
clears the fragment list tail, list count, byte count, calculated size and
option length, and retains an expired marker. The completing fragment and
subsequent retries receive native DAQ drop actions; they are never inserted
or reconstructed. The existing `stream_ip.frag_timeouts` counter counts the
abandonment once, and `stream_ip.drops` counts rejected arrivals. The native
drop reason is `ip_reassembly_timeout`. This is engine enforcement, not a new
alert signature. Passive operation cannot supply inline blocking.

The early return for an already rejected fragment tracker also prevents
checksum-rejected datagrams from being repeatedly reconstructed. Existing
checksum counter and retry tests remain satisfied.

## Evidence

The [matched comparison](../fragment-lifetime-comparison.json) passes **372
paired cases / 744 native engine runs** with actual file-only inline DAQ
verdicts and exact forwarded bytes:

- 204 late-fragment cases that were previously entirely forwarded now block.
- Forwarding enforcement improves in 240 cases, including retained retries.
- 324 expired reconstructions are prevented.
- All 48 timely controls retain their expected disposition and bytes.
- 36 retry cases and 24 recovery cases pass.

The captures cover IPv4/IPv6 TCP, UDP and ICMP; configured budgets of 1, 30, 60
and 120 seconds; one microsecond before, exactly at and after deadlines; slow
trickles; reversed arrival order and all six selected three-fragment orders.
The capture clock starts at a fractional second. Recovery cases test both
a fresh fragment ID during quarantine and a complete datagram after idle
retention expires. Checksums are valid before fragmentation, so timed drops
cannot be explained by intentionally corrupt transport data.

An independent wire oracle reconstructs original serialized payloads and
checks checksums and timestamps. The baseline and repaired runs use identical
captures and configurations. The baseline failures are retained as failures,
not counted as protection. No packets are transmitted on a network.

The [arithmetic record](../fragment-lifetime-parser-validation.json) passes
**100,844 assertions**, including 100,000 randomized timestamp combinations,
with AddressSanitizer and UndefinedBehaviorSanitizer. Its independent oracle
uses 128-bit microsecond arithmetic, while production compares bounded seconds
and fractions.

All eight preceding native suites pass on the cumulative executable:

| Suite | Cases |
| --- | ---: |
| [General replay](../fragment-lifetime-repaired-engine/replay-validation.json), inline simulation | 156 |
| [Ordinary checksums](../fragment-lifetime-repaired-engine/checksum-validation.json) | 16 |
| [IP structure](../fragment-lifetime-repaired-engine/structure-validation.json), paired policies | 151 |
| [Next Header](../fragment-lifetime-repaired-engine/next-header-validation.json), paired policies | 256 |
| [Fragment checksums](../fragment-lifetime-repaired-engine/fragment-checksum-validation.json) | 312 |
| [Structure and Type 2](../fragment-lifetime-repaired-engine/cumulative-validation.json) | 241 |
| [IPv4 source routes](../fragment-lifetime-repaired-engine/ipv4-route-validation.json) | 236 |
| [Fragment options](../fragment-lifetime-repaired-engine/fragment-options-validation.json) | 320 |

## Build and repeat

Start from a separate copy of pinned Snort commit
`14aeb09f5a0856812dbe08ead3c21f99e8860aa0` with all four preceding repairs,
ending with [fragment options](fragment-options.md). Preserve a baseline build
with `build_snapshot.py`, then run:

```sh
python3 native-snort3/patches/apply_fragment_lifetime_repair.py \
  --upstream /path/to/clean/pinned/snort3 \
  --target-source /path/to/separate/source-copy
```

Build a repaired snapshot in the same configured tree. Recreate the
[build record](../fragment-lifetime-build-validation.json) and arithmetic record
with `record_fragment_lifetime_build.py`, supplying `--build-root`,
`--previous-build-root`, `--upstream`, `--report` and `--parser-report`.
The recorder verifies full source snapshots, identical build configuration,
the exact source delta and the preceding baseline. This is local build evidence,
not a hermetic reproducible-build attestation.

Run `tests/fragment_lifetime_replay.py` once per executable with `--snort`,
`--plugin-path` and separate `--report` files. The baseline exits 1. Compare
with `tests/compare_fragment_lifetimes.py`, passing `--baseline-report`,
`--repaired-report`, `--build-report` and `--report`. Run without Python
optimization.

The verified executable is
`/private/tmp/ax-snort-fragment-lifetime-repair/repaired/snort`, SHA-256
`4b27f283229bc7c2f5743e8a390ca281aa92850e631e69ef1c11c67a63c99fa3`.
The baseline is beside it in `baseline/snort`. No installation, service,
firewall, interface or deployment was changed.

## Remaining limits

This verifies packet-processing decisions driven by synthetic capture time.
It does not prove live timer scheduling or eager removal of idle payload at
the deadline: payload cleanup occurs when eligible packet processing or
ordinary cache cleanup reaches the tracker. Cache pressure can evict state;
the new idle floors do not override capacity pruning. The subsequent
[fragment pressure repair](fragment-pressure.md) adds allocation admission and
a process-wide guard for premature state loss, verified separately. This
lifetime patch alone does not contain that protection. Failover, asymmetric
paths, timestamp behavior and endpoint-specific longer retention remain
separate requirements.

Previously forwarded fragments cannot be recalled. Retention is a bounded
local policy, not a proof that late traffic cannot combine with downstream
state in every deployment. Overlap behavior, opaque option semantics, other
routing types, Home Address options, complete jumbograms and admission fencing
remain separate work. Universal RFC/W3C compliance and protection against all
unknown attacks remain unproved.
