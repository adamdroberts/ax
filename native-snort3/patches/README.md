# Type 2 routing checksum repair

The pinned stock Snort 3.12.2.0 engine uses the IPv6 base destination when
checking TCP, UDP and ICMPv6 checksums. For an active Mobile IPv6 Type 2 routing
header, the checksum instead covers the final Home Address. This requirement
comes from [RFC 8200 section 8.1](https://www.rfc-editor.org/rfc/rfc8200.html#section-8.1)
and [RFC 6275](https://www.rfc-editor.org/rfc/rfc6275.html#section-6.4.1).
The [stock-engine audit](../mobility-checksum-validation.json) preserves six
actual failing inline file replays. It is not a passing security test.

`apply_type2_repair.py` applies a source repair to a **separate copy** of the
pinned upstream commit. It refuses a different commit or already-modified
codec inputs. It changes checksum verification and checksum update in the
three transport codecs and adds `ipv6_checksum_destination.h`. It records the
original and changed hashes and emits a reviewable unified patch. It does not
install Snort or change any interface or live policy.

```sh
python3 native-snort3/patches/apply_type2_repair.py \
  --upstream /path/to/clean/pinned/snort3 \
  --target-source /path/to/separate/source-copy
```

Build the separate source copy with Snort's supported build system and its
development dependencies. The local verification uses OpenSSL 3; this pinned
source does not compile unchanged against OpenSSL 4's const-qualified APIs.
Keep a baseline executable built with the same source, compiler, configuration
and dependencies before applying the repair. A replacement shared TCP codec
is unsuitable for the tested macOS runtime: it depends on unexported engine
symbols, and a failed load can silently leave the old static codec active.

The helper walks at most eight known extension headers between the selected
IPv6 header and the exact transport boundary. It never searches payload bytes
for headers, crosses another IP layer or decrypts ESP. An active, correctly
sized Type 2 supplies the final address; ignored zero-segment routes do not
replace it. Real fragments do not supply a complete transport checksum.
Malformed original-wire Type 2 fields remain the responsibility of rule
9201016. Address selection does not change the packet, flow identity, endpoint
ownership or IPsec state.

The [parser report](../type2-parser-validation.json) records 111,027 assertions
with AddressSanitizer and UndefinedBehaviorSanitizer, including 100,000
deterministic random spans. The native comparison runner is
[`type2_repair_replay.py`](../tests/type2_repair_replay.py); it requires both
executables, source repair evidence and a matching build manifest. It checks
actual inline DAQ verdicts, transport checksum counters and exact forwarded
packet bytes. Its extra normalization fixtures enable TCP reserved-bit and
IPv6-option normalization only in a temporary test profile. The production
profile continues to preserve legal options.

The [matched build record](../type2-build-validation.json) binds both executable
hashes to identical build settings and the exact source delta. The
[native comparison](../type2-repair-validation.json) passes **90/90 cases in
180 engine runs**: 78 routed cases, 12 ordinary controls, and six normalization
cases included in the routed count. Correct final-address checksums pass;
incorrect base-address checksums block. All forwarded repaired packets match
the expected bytes, including the three codecs' checksum-update paths.

The repaired engine also passes the existing
[156-case replay](../repaired-engine/replay-validation.json),
[16 checksum cases](../repaired-engine/checksum-validation.json),
[151 structural comparisons](../repaired-engine/structure-validation.json), and
[256 Next Header comparisons](../repaired-engine/next-header-validation.json).
The general replay uses inline simulation; the other three and the 90-case
repair comparison use actual file-only inline DAQ verdicts. None uses a live
network interface. The stock-engine failure reports are preserved separately.

To repeat the comparison using the captured local build artifacts:

```sh
python3 native-snort3/tests/type2_repair_replay.py \
  --baseline /private/tmp/ax-snort-repaired/baseline/snort \
  --repaired /private/tmp/ax-snort-repaired/repaired/snort \
  --plugin-path /private/tmp/ax-nd-plugin \
  --repair-source /private/tmp/ax-snort-repaired/source \
  --build-manifest native-snort3/type2-build-validation.json \
  --report native-snort3/type2-repair-validation.json
```

Those temporary binaries are local validation artifacts, not repository
dependencies or deployed services. For another machine, rebuild and capture
new matching build evidence; the recorded binary hashes intentionally reject
a different build. The source repair is available both through the applicator
and as [`snort-type2-checksum.patch`](snort-type2-checksum.patch).

Remaining limitations are explicit:

- The stock engine remains defective; loading the AX rule plugin does not
  apply this engine source repair.
- Unknown active routing types, RPL and segment-routing address semantics are
  not implemented by this Type 2 helper. It retains existing engine behavior
  where it cannot select a final address.
- Home Address destination options require a corresponding **source** address
  checksum correction, supplied by the later [Home Address repair](home-address.md).
  The later [IPv6 prefix repair](ipv6-prefix.md) retains the offset-zero wire
  headers and validates reconstruction. Endpoint binding and logical-source
  grouping remain separate requirements; the Type 2 patch alone does not apply
  either later repair.
- Type 2 repair alone leaves the reassembled-datagram checksum gap. The
  additional [fragment checksum repair](fragment-checksums.md) closes the tested
  UDP/ICMP gap and prevents all four transport codecs from trusting a parent
  fragment's checksum-offload metadata. Its cumulative build passes 312 cases.
- IPv4 source-routing checksums use a separate subsequent
  [repair](ipv4-source-route.md), verified with 236 paired cases. This Type 2
  patch alone does not apply that correction or implement return-route state.
- Generated-response encoders are unchanged. They may omit routing headers;
  copying the original Home Address into their checksum alone would mismatch
  the packet they actually emit.
- These local tests cannot prove live deployment enforcement, full Mobile
  IPv6 compliance, or prevention of unknown attacks.
