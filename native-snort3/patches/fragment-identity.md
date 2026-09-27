# Fragment identity repair

The shared flow-key helpers treated fragment IDs as ICMP message types. For
certain IDs this changed an address or part of the ID before choosing a fragment
tracker. IPv6 continuation headers could therefore split one datagram across
different trackers, allowing every fragment through without inspecting the
reassembled content. Conversely, distinct datagrams could collide and cause
legitimate traffic to be rejected.

This cumulative repair preserves the full fragment ID and both wire addresses
when constructing the fragment key. It closes reproduced checksum and content
policy bypasses without adding product rules, SIDs or plugin code. The two
changed calls belong specifically to the fragment-key overload; ordinary ICMP
session normalization continues to use the existing path. Loading rules alone
does not apply this engine repair.

## Standards and defect

[RFC 791 section 2.3](https://www.rfc-editor.org/rfc/rfc791.html#section-2.3)
groups IPv4 fragments by source, destination, protocol and identification.
[RFC 8200 section 4.5](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.5)
groups IPv6 fragments by source, destination and identification. IPv6 continuation
Next Header values may differ; the offset-zero fragment supplies the value used
for reconstruction.

Snort stores the ID across two fields also used for transport ports. Its fragment
key then called helpers that normally combine ICMP requests and replies, and
normalize router discovery addresses for ordinary sessions. For fragmented
traffic these fields contain ID bits, not an ICMP type. The normalization could
erase an IPv6 ID's upper 16 bits or alter an address when the lower bits happened
to match a recognized ICMP type. It could also affect IPv4 ICMP fragments.

For example, an offset-zero IPv6 UDP fragment with ID 65,537 and a continuation
whose Next Header is 58 reached different tracker keys. The preceding engine
forwarded both pieces of a deliberately corrupted UDP datagram and recorded no
reassembly or checksum error. The same split bypassed a temporary blocking rule
on valid reconstructed content. The initial tests with ID 1,234 did not expose
this dependency; the broader identifier matrix did.

The repair calls the existing address/ID-copy helpers with a neutral protocol
selector solely for fragment-key initialization. It still retains IPv4's actual
protocol in the resulting key, while IPv6 retains its existing protocol-independent
key field. VLAN, MPLS, tenant, address-space and DAQ grouping fields are unchanged.
No new allocation, counter, persistent state or runtime setting is introduced.

## Evidence

The [matched comparison](../fragment-identity-comparison.json) uses **694 paired
cases / 1,388 native runs** with identical captures, expectations, configuration
and plugin bytes. The baseline passes 426 cases; the repaired engine passes all
694. The [baseline](../fragment-identity-baseline-validation.json) and
[repaired](../fragment-identity-validation.json) records include exact input and
forwarded packet hashes, actual file-only inline verdicts, checksum errors,
reassembly counts, fragment-node counts and expected/observed policy events.

| Result | Cases |
| --- | ---: |
| Incorrect original-packet forwarding corrected | 188 |
| Temporary blocking-policy bypasses closed | 60 |
| Checksum rejection restored | 80 |
| Valid forwarding restored | 28 |
| Reassembly inspection restored | 268 |

These are overlapping case categories, not counts of separate vulnerabilities.
The forwarding changes also include malformed interleaved contexts whose
fragments were previously rejected or forwarded in the wrong positions.

The suite contains 338 valid observation controls, 96 temporary policy cases and
118 cases with independent datagrams interleaved. It covers TCP, UDP and ICMPv6
with differing continuation Next Header values, both arrival orders, IDs near
ICMP type values, zero and maximum IDs, IDs with nonzero upper bits, and extension
padding. Separate controls cover IPv4 ICMP address preservation, IPv6 ICMP ID and
address isolation, and IPv4 protocol separation. Valid payloads have independently
checked transport checksums; corrupted controls differ by one payload byte.

The temporary rule is restricted to reconstructed fragments and its event is
required in every policy case. It is created only in the test configuration and
does not increase the product rule count. The test oracle derives the expected
identity from serialized wire fields, preserving all IPv6 ID bits and keeping
IPv4 protocol in the identity. Preliminary fixture framing was corrected before
the paired final reports were produced.

The cumulative engine passed all 6,680 cases across the 18 preceding suites in
`fragment-identity-repaired-engine/`: protocol replay, checksums, IP structures,
Next Header policy, fragment checksums, cumulative Type 2 checks, IPv4 source
routes, fragment options, lifetimes, pressure, Home Address, IPv6 header policies,
Home Address wire-prefix handling, IPv6 prefix/ECN/size, large IPv4 fragments,
IPv4 header/ECN/size, overlaps and final-length/coverage checks.

The separate native sanitizer record is
[fragment-identity-asan-validation.json](../fragment-identity-asan-validation.json).
All 5,460 sanitizer replay cases passed. The record verifies the complete source snapshot, sanitizer compiler flags on the flow-key,
flow-control and fragment-processing units, and equality of release/sanitizer
packet verdicts, bytes and counters. These are finite replay checks, not proof
of universal memory safety or instrumentation of prebuilt external libraries.

## Remaining limits

This repair preserves the ordinary wire-level fragment identity. It does not
establish logical-source grouping after Mobile IPv6 processing, Home Address
ownership, routing authorization, IPsec authentication or other stateful endpoint
behavior. The preceding lifetime, resource, overlap and final-length protections
remain necessary. Live multithreaded operation, offload equivalence, failover and
actual deployment are not established by file-only replays. Full RFC/W3C
compliance and prevention of every unknown attack remain unproved.

## Build and repeat

Start with a separate copy of pinned Snort commit
`14aeb09f5a0856812dbe08ead3c21f99e8860aa0`, including all repairs through
[fragment final length and coverage](fragment-extent.md). Preserve the baseline
using `build_snapshot.py`, then apply:

```sh
python3 native-snort3/patches/apply_fragment_identity_repair.py \
  --upstream /path/to/clean/pinned/snort3 \
  --target-source /path/to/separate/source-copy
```

Rebuild in the same configured tree and preserve a separate repaired snapshot.
`record_fragment_identity_build.py` verifies it with `--build-root`,
`--previous-build-root`, `--upstream` and `--report`.
The reviewable delta is [`snort-fragment-identity.patch`](snort-fragment-identity.patch).

Run `native-snort3/tests/fragment_identity_replay.py` against both binaries with
`--snort`, `--plugin-path` and separate `--report` paths, then run
`compare_fragment_identities.py --report ...`. Repeat all 18 preceding suites
against the final executable.

For native sanitizer checks, copy the final source and use the same configuration
plus `-DENABLE_ADDRESS_SANITIZER=ON`. Repeat the nine suites named in the sanitizer
record with `ASAN_OPTIONS=halt_on_error=1:abort_on_error=1`.
`record_fragment_identity_asan.py` verifies the evidence with `--build-root`,
`--release-build-root`, `--harness` and `--report`.

The [local build record](../fragment-identity-build-validation.json) identifies
`/private/tmp/ax-snort-fragment-identity-repair/repaired/snort`, SHA-256
`00e78ad173adaf78ef40a14b8d3e4d0094373286bd00be298cc02148e279bf3c`.
The sanitizer executable is
`/private/tmp/ax-snort-fragment-identity-asan/repaired/snort`, SHA-256
`6189bf0a3b4b5ea327513a32a61c4e2a1a65dffb9c1ae9c5f37159e2d4e4c54b`.
The unchanged plugin is `/private/tmp/ax-home-address-plugin/ax_nd_options.so`,
SHA-256 `3dde09c3191beefd8ca35121762daa282631705cd7938d306f53732c1b83f6fb`.
These are local build records, not hermetic attestations. Nothing was installed
or deployed and no live interface was opened.
