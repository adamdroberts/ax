# Fragment reassembly checksum repair

The pinned Snort 3.12.2.0 UDP, ICMPv4 and ICMPv6 decoders tolerate checksum
failures when decoding a reassembled IP datagram. This lets malformed fragmented
traffic bypass the configured checksum rejection. TCP already rejects those
failures, but all four transport codecs can trust checksum metadata from the
DAQ message belonging to a parent fragment. That metadata cannot attest the
checksum of the reconstructed datagram.

[`snort-fragment-checksums.patch`](snort-fragment-checksums.patch) removes the
reassembled-packet exception and requires software checksum verification for
reassembled TCP, UDP and ICMP. It applies **after the [Type 2 routing checksum
repair](README.md)**. No rule IDs, rule actions, plugin interfaces or endpoint
addresses change. A rebuilt Snort engine is required; loading rules alone does
not apply either repair.

The IPv4 UDP checksum-omission allowance remains intact, as specified in
[RFC 1122 section 4.1.3.4](https://www.rfc-editor.org/rfc/rfc1122.html#section-4.1.3.4).
Ordinary IPv6 UDP zero checksums remain rejected under
[RFC 8200 section 8.1](https://www.rfc-editor.org/rfc/rfc8200.html#section-8.1);
this profile does not enable tunnel exceptions. ICMPv6 checksums cover the
complete message and pseudo-header under
[RFC 4443 section 2.3](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.3).

## Local validation

The [matched comparison](../fragment-checksum-comparison.json) records **312
paired cases in 624 engine runs**. The cumulative repaired engine passes all
312 cases. Compared with an otherwise identical Type 2-only build:

- 84 invalid cases that were fully forwarded are now blocked.
- 12 IPv6 UDP zero-checksum cases were already blocked by a native event; the
  repair also makes their checksum-failure counters accurate.
- All 156 valid controls remain accepted byte for byte.
- 144 cases exercise repeated completing fragments or repeated datagrams.
  Invalid retries remain blocked, and each performed reassembly records a
  checksum failure. The engine can recheck a rejected datagram on later retries;
  the tests do not assume a single reassembly or a permanent rejection cache.

The suite covers IPv4/IPv6 TCP, UDP and ICMP, omitted versus invalid checksums,
two- and three-fragment permutations, legal IPv4 TCP header splits, IPv6 Type 2
routing and Destination Options, and odd transport lengths. An independent
oracle reconstructs the first complete datagram from the serialized frames and
checks its checksum using a different calculation from the packet generator.

Tests use a file-only inline `dump:pcap` DAQ, never a live interface. They check
one actual DAQ verdict per input frame, reassembly/checksum counters, and exact
forwarded capture bytes. A rejected datagram's completing fragment and its
tested retries are blocked. Earlier incomplete fragments have already passed
and cannot be recalled. The
[baseline audit](../fragment-checksum-baseline-validation.json) preserves the
failures and exits nonzero; it is not reported as passing protection. The
[repaired audit](../fragment-checksum-validation.json) contains the passing
results.

The cumulative engine also passes the existing
[156-case replay](../fragment-repaired-engine/replay-validation.json),
[16 checksum cases](../fragment-repaired-engine/checksum-validation.json),
[151 structural comparisons](../fragment-repaired-engine/structure-validation.json),
and [256 Next Header comparisons](../fragment-repaired-engine/next-header-validation.json).
The general replay uses inline simulation; the other three use actual file-only
inline verdicts. The prior Type 2 comparison remains separate evidence for its
90 packet cases, including checksum updates during normalization.

## Build and repeat

Use a separate copy of official commit
`14aeb09f5a0856812dbe08ead3c21f99e8860aa0`. Apply the Type 2 repair first,
configure the source with Snort's supported CMake build, and retain a baseline
build before applying this additional repair:

```sh
python3 native-snort3/patches/build_snapshot.py \
  --source /path/to/type2-source-copy \
  --build /path/to/configured-build \
  --configure-manifest /path/to/configure-manifest.json \
  --output-dir /path/to/new-baseline-output

python3 native-snort3/patches/apply_fragment_checksum_repair.py \
  --upstream /path/to/clean/pinned/snort3 \
  --target-source /path/to/type2-source-copy

python3 native-snort3/patches/build_snapshot.py \
  --source /path/to/type2-source-copy \
  --build /path/to/configured-build \
  --configure-manifest /path/to/configure-manifest.json \
  --output-dir /path/to/new-repaired-output
```

The applicator verifies the pinned commit and exact prior codec/helper bytes.
It emits the source-change report and reviewable patch into the source copy.
The builder requires new output directories and an existing successful
configuration manifest; see `configuration` in the
[local build record](../fragment-build-validation.json) for the captured command
and environment. It captures full source hashes before and after each build,
build settings, logs, the builder hash and final binary hash. Optional macOS
`--relocations` accepts a JSON map of exact old library names to existing local
library paths. No system installation occurs.

The captured local baseline and cumulative binaries are respectively:

- `/private/tmp/ax-snort-fragment-repair/baseline/snort`
- `/private/tmp/ax-snort-fragment-repair/repaired/snort`

Their configuration files are byte-identical. The semantic source delta is
exactly the four transport codecs. The cumulative binary SHA-256 is
`cdbbe878d41db1b922482d4f1c75ea373ceac1a3fe43840fe2d0052deac439df`.
These temporary artifacts are not deployed services or portable repository
dependencies. The earlier `/private/tmp/ax-snort-repaired/install/bin/snort`
contains only the Type 2 repair and does not include this fragment repair.

To repeat each audit, select the corresponding executable and a distinct report
path. The baseline command is expected to exit 1:

```sh
python3 native-snort3/tests/fragment_checksum_replay.py \
  --snort /private/tmp/ax-snort-fragment-repair/baseline/snort \
  --plugin-path /private/tmp/ax-nd-plugin \
  --report native-snort3/fragment-checksum-baseline-validation.json

python3 native-snort3/tests/fragment_checksum_replay.py \
  --snort /private/tmp/ax-snort-fragment-repair/repaired/snort \
  --plugin-path /private/tmp/ax-nd-plugin \
  --report native-snort3/fragment-checksum-validation.json

python3 native-snort3/tests/compare_fragment_checksums.py \
  --baseline-report native-snort3/fragment-checksum-baseline-validation.json \
  --repaired-report native-snort3/fragment-checksum-validation.json \
  --build-report native-snort3/fragment-build-validation.json \
  --report native-snort3/fragment-checksum-comparison.json
```

For another build, supply new matched build evidence; the saved binary hashes
intentionally reject different executables. Reports bind the runner, shared
fixture sources, configuration, plugin and binary, and verify those inputs did
not change during replay.

## Remaining scope

The captures use closely spaced timestamps and bounded, nonoverlapping fragments.
They do not establish behavior under cache exhaustion, timeout differences,
overlap policies, asymmetric paths or hardware checksum offload. Source review
supports the cooked-packet offload change; live DAQ metadata was not exercised.
No deployment routing or live prevention was tested.

IPv4 source-route checksums are corrected by the subsequent
[IPv4 repair](ipv4-source-route.md), which requires another cumulative build.
Home Address source options, other active routing semantics, return-route state,
complete IPv6 jumbograms and endpoint-dependent option/IPsec processing remain
outside this repair. Checksums are not authentication. These results do not
establish complete RFC/W3C compliance or protection against every unknown attack.
