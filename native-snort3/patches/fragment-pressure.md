# Fragment allocation limits and rejection after cache eviction

The preceding cumulative engine displays `stream_ip.max_frags` but never
checks it before allocating fragment nodes. A nine-fragment datagram therefore
allocates nine nodes and reconstructs even with a configured limit of two.

A separate bypass occurs when the flow cache evicts a rejected datagram. In
the reproduced case, Snort first drops a completing fragment because the UDP
checksum is wrong. After enough unrelated fragment IDs fill the cache, the
same rejected fragment passes. This occurs both at a 16-flow test limit and
the supplied **4,096-flow** limit. Longer idle retention alone does not prevent
capacity eviction. These are observed engine behaviors, not claims of an
endpoint exploit or a newly assigned vulnerability.

The [source repair](snort-fragment-pressure.patch) enforces allocation limits
and retains a bounded rejection guard outside the evictable flow cache. It
requires a rebuilt cumulative engine. It adds no rule IDs or duplicate
signatures, and loading the rule plugin alone does not apply it.

## Allocation policy

Before each of the three fragment-node allocation paths, the engine checks
the live node count against the relevant `max_frags` limit. This covers first
admission, ordinary insertion and duplication when overlap handling splits an
existing node. The counter belongs to each packet-analysis thread and is
shared across its IP families and engine instances. It is independent of
statistics counters, which can be reset. Different policies can set different
limits; each allocation checks the total against its caller's limit.

If admission cannot allocate, the current fragment is dropped and a minimal
rejected tracker is retained. If insertion fails, stored payload is freed,
the current fragment is dropped and subsequent retries remain rejected. A
completed or abandoned datagram releases its live nodes for other datagrams.
This is a node limit, not a total process-memory budget: payload size, flow
objects, other inspectors and the number of packet threads still matter.

## Lost-state policy and recovery

Cleanup of an unfinished or rejected tracker before its retention deadline
publishes a process-wide quarantine deadline for that IP family. Publication
uses atomic maximum updates; a shorter or older loss cannot shorten the
existing deadline. The guard is separate from flow-cache entries, so more
cache eviction cannot erase it.

While that deadline is active, new or missing fragment contexts receive a
native DAQ drop before payload allocation. Existing admitted contexts continue
inspection. Unfragmented packets and the other IP family are not rejected by
this guard. This deliberately sacrifices availability for **new fragmented
traffic of the affected family**, including legitimate traffic, after state
loss. It does not identify an attacker or an affected tenant.

The deadline uses the lost tracker's own last-seen fragment time plus the
preceding repair's retention floor: `max(configured timeout, 120) + 1` seconds
for IPv4 and `max(configured timeout, 60) + 1` for IPv6. The supplied profile
therefore uses 121 and 61 seconds. Tracking its own last-seen time matters:
the ordinary flow lookup updates its timestamp before expired-session cleanup,
which would otherwise mistake a new arrival for recent activity in the old
datagram. Completed datagrams and natural cleanup after retention do not
publish quarantine.

Trackers created only to reject admission have forwarded no fragments; pruning
them does not publish a new deadline. Flooding these rejected contexts cannot
by itself extend the quarantine indefinitely. Fresh fragment IDs are admitted
again after the deadline. A still-present rejected tracker retains its own
rejection until its normal lifetime ends.

These limits are **local IPS admission policy**. They are not RFC claims that
all traffic denied under pressure is malformed. The separate reassembly
lifetime requirements remain documented against
[RFC 8200 section 4.5](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.5)
and [RFC 1122 section 3.3.2](https://www.rfc-editor.org/rfc/rfc1122.html#section-3.3.2)
in the [lifetime repair](fragment-lifetime.md). W3C application policies do not
specify IP fragment allocation behavior.

The added `stream_ip` telemetry is:

| Counter | Meaning |
| --- | --- |
| `max_fragment_nodes` | Peak concurrently allocated nodes on the packet thread |
| `resource_drops` | Fragments rejected after allocation admission/insertion failure |
| `state_lost_drops` | Fragments rejected in contexts denied by lost-state quarantine |
| `premature_state_losses` | Trackers discarded before retention elapsed |

Existing `drops` includes native resource and lost-state drops. Their DAQ drop
reasons are `ip_reassembly_resources` and `ip_reassembly_state_lost`. Final
process cleanup can increment the state-loss counter; it does not prove that
traffic encountered quarantine during that run. The replay tests verify
actual forwarded bytes as well as counters.

## Evidence

The [matched comparison](../fragment-pressure-comparison.json) passes **270
paired cases / 540 native runs**, using actual file-only inline DAQ verdicts:

- All 270 repaired cases pass; the baseline passes 101 and fails 169.
- 169 cases have stronger forwarding enforcement. Of these, 161 were entirely
  forwarded by the baseline, and 165 avoid reconstruction admitted previously.
- Eight eviction cases restore rejection of the previously dropped fragment,
  including both IP families at the default flow-cache limit.
- All 101 valid controls, 82 retry cases and 18 recovery cases pass.

Fixtures cover IPv4/IPv6 TCP, UDP and ICMP; limits of 1, 2, 3, 8 and 9 nodes;
forward and reversed arrival; competition between datagrams and IP families;
release after completion and rejection; and the duplicate-node allocation
path. The latter uses a separate IPv4 last-wins test profile with its overlap
limit disabled to isolate allocation behavior. The supplied Linux policy and
its strict overlap settings are unchanged.

Cache tests submit thousands of different IDs, retry the rejected tail, check
that an existing context and other-family/unfragmented traffic survive, then
flood quarantine-only contexts and verify recovery. Natural retention expiry
and ID reuse also pass. Independent checks validate serialized IP lengths,
fragment offsets, payload slices, transport checksums and every capture
timestamp, including captures containing more than 1,000 frames. The paired
reports bind identical fixtures, configurations and plugin hashes to their
respective binaries. The [baseline failures](../fragment-pressure-baseline-validation.json)
remain recorded as failures.

The [helper record](../fragment-pressure-parser-validation.json) passes
**100,017 assertions per run**, including 100,000 randomized deadline inputs
and 200,000 atomic updates from eight concurrent publishers. One run uses
AddressSanitizer and UndefinedBehaviorSanitizer; another uses ThreadSanitizer.
These are tests of arithmetic and atomic publication, not a multithreaded
native traffic test.

All nine preceding native suites pass on this cumulative executable:

| Suite | Cases |
| --- | ---: |
| [General replay](../fragment-pressure-repaired-engine/replay-validation.json), inline simulation | 156 |
| [Ordinary checksums](../fragment-pressure-repaired-engine/checksum-validation.json) | 16 |
| [IP structure](../fragment-pressure-repaired-engine/structure-validation.json), paired policies | 151 |
| [Next Header](../fragment-pressure-repaired-engine/next-header-validation.json), paired policies | 256 |
| [Fragment checksums](../fragment-pressure-repaired-engine/fragment-checksum-validation.json) | 312 |
| [Structure and Type 2](../fragment-pressure-repaired-engine/cumulative-validation.json) | 241 |
| [IPv4 source routes](../fragment-pressure-repaired-engine/ipv4-route-validation.json) | 236 |
| [Fragment options](../fragment-pressure-repaired-engine/fragment-options-validation.json) | 320 |
| [Fragment lifetimes](../fragment-pressure-repaired-engine/fragment-lifetime-validation.json) | 372 |

## Build and repeat

Start with a separate copy of pinned Snort commit
`14aeb09f5a0856812dbe08ead3c21f99e8860aa0`, containing all preceding repairs
through [fragment lifetime](fragment-lifetime.md). Preserve a baseline snapshot
with `build_snapshot.py`, then apply:

```sh
python3 native-snort3/patches/apply_fragment_pressure_repair.py \
  --upstream /path/to/clean/pinned/snort3 \
  --target-source /path/to/separate/source-copy
```

Build the repaired snapshot in the same configured tree. Run
`record_fragment_pressure_build.py` with `--build-root`,
`--previous-build-root`, `--upstream`, `--report` and `--parser-report`.
The [build record](../fragment-pressure-build-validation.json) verifies the
complete source snapshots, unchanged configuration, exact repair delta and
the preceding lifetime baseline. It is local evidence, not a hermetic
reproducible-build attestation.

Run `tests/fragment_pressure_replay.py` for each executable with `--snort`,
`--plugin-path` and separate `--report` files. The baseline exits 1; the
repaired run exits 0. Run `tests/compare_fragment_pressure.py` with
`--baseline-report`, `--repaired-report`, `--build-report` and `--report`.
Python assertions must be enabled.

The verified executable is
`/private/tmp/ax-snort-fragment-pressure-repair/repaired/snort`, SHA-256
`dbee409fd285e4158f23632fc4e7687c8f1ea0f253fa262778e6b41cb318185a`.
The matched baseline is beside it in `baseline/snort`. No installation,
interface, service or deployment changed.

## Remaining limits

The native replays run one packet thread. The atomic helper tests do not prove
DAQ flow distribution, simultaneous verdict ordering, worker migration,
multi-process coordination, restart or failover behavior. The guard is local
to one process; an independent sensor does not receive its deadline.

These tests do not simulate actual allocator failure, total memory exhaustion,
CPU starvation or packet loss before inspection. Node accounting does not
bound every inspector's memory or establish fail-closed live overload behavior.
Previously forwarded fragments cannot be recalled, and endpoint retention or
path delay may exceed the local guard window. Source authentication, other
protocol state loss, endpoint-dependent semantics and the documented external
admission race remain separate requirements. This evidence cannot establish
universal RFC/W3C compliance or prevention of every unknown attack.
