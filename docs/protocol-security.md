# Protocol and egress security contract

The Go and Python MCP proxies apply a restrictive HTTP/1.1 broker policy before
the Snort-style signature catalog. These controls address whole classes of
bypasses without needing an exploit signature. They do not guarantee protection
against every unknown vulnerability or every unauthorized agent action.

## Required destination configuration

Network egress is denied by default, in both rule profiles and with custom rules.
An administrator must supply each allowed origin when starting the proxy:

```sh
ax-mcp-proxy --profile strict \
  --allow-origin https://api.company.example \
  --allow-origin https://uploads.company.example:8443

python3 cmd/ax-mcp-proxy/ax_mcp_proxy.py --profile strict \
  --allow-origin https://api.company.example
```

An origin is exactly a scheme, hostname and effective port. A default port is
equivalent to its explicit spelling. DNS names are case insensitive. Paths,
queries, fragments, credentials, trailing slashes and wildcards are not allowed
in configuration entries. An allowed hostname does not authorize its subdomains,
another scheme or another port. There is no agent-controlled allowlist override
or budget-reset tool. Automatically registered proxies without these arguments
remain available for diagnostics and statistics but cannot send HTTP requests.

The origin check runs before DNS or a socket connection. At connection time the
proxy resolves once, rejects the entire answer set if any address is disallowed,
and dials only a vetted numeric address. Host headers and TLS certificate checks
retain the original hostname. Private, loopback, link-local, mapped IPv6,
multicast, reserved and special-purpose addresses are excluded, including cloud
metadata/platform endpoints and IPv6 transition ranges. No environment proxy,
cookie jar, redirect following, HTTP connection reuse, upgrade, tunnel or HTTP/2
negotiation is available through the production transport. DNS answers are
rechecked on every connection. A positive offline diagnostic does not establish
that DNS, TLS or a later network request will succeed.

The built-in address exclusions are conservative and must be maintained with
the [IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)
and [IPv6 special-purpose registries](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml).
An allowed origin does not override the public-address requirement.

## Gaps addressed

| Bypass class | Enforced protection |
| --- | --- |
| DNS rebinding, mixed public/private answers and alternative IP spellings | Exact origin authorization, canonical address syntax, whole-answer validation and numeric socket pinning |
| Proxy environment variables or redirect destinations changing the route | Dedicated direct transport, no environment proxy or automatic redirects |
| Request smuggling, framing and connection manipulation | Reject caller framing/hop headers; reconstruct one HTTP request using the standard client; no connection reuse |
| Routing and method-override headers | Reject `Forwarded`, `X-Forwarded*`, original/rewrite URL/host and method-override fields |
| Forged browser or agent approval context | Reject `Sec-*`, `Origin`, `Referer`, `X-Real-IP`, `X-Agent-ID` and `X-Approval-Token` |
| Duplicate JSON keys and Unicode replacement | Validate original bytes/escapes before ordinary decoding; reject duplicate decoded keys, invalid UTF-8, lone surrogates and noncharacters |
| Hidden body formats or compressed data | UTF-8 text, JSON and form bodies only; identity encoding; reject unsupported media types and charsets |
| Parser disagreements about URLs | Reject malformed escapes, fragments, userinfo, controls, backslashes, ambiguous numeric hosts and noncanonical IP/port forms |
| Deeper encoding than the inspection pipeline understands | Reject if further unseen decoded views remain after the three-round normalization budget |
| Repeated large inputs and allocation amplification | Per-message and process-lifetime limits; reuse folded buffers instead of copying every buffer for every case-insensitive rule |
| Malformed or unacknowledged MCP calls | Validate JSON-RPC 2.0 envelopes, typed IDs, object arguments, duplicate fields and known request properties; tool-call notifications cannot dispatch |
| Malicious response framing | Validate raw status/header lines and streaming body framing before client normalization; reject conflicting/duplicate framing, obsolete folding, bare LF, malformed chunk extensions/terminators, truncation, upgrades, trailers and encoded responses |
| Ambiguous response metadata | Check interim and final blocks before normalization; reject duplicate singleton fields, malformed Connection options, protected metadata nominated as hop-by-hop, and ambiguous Content-Type parameters |
| Invalid packet and reassembly behavior | Separate native Snort profile enables release-pinned decoder, IP reassembly and TCP stream checks, required structural Neighbor Discovery validation, Hop-by-Hop placement, AH framing, and original first-fragment header completeness checks; requires an independent packet sensor |
| Malformed IP option formats and skipped ESP decoding | Check original IPv4 options/padding, IPv6 Router Alert/Jumbo options and visible ESP bounds/nonzero SPI independently of optional native decryption; reject nonzero IPv6 Echo codes |
| Fragmented traffic bypassing checksum rejection | Additional native engine repair verifies complete reassembled TCP/UDP/ICMP checksums in software and removes the UDP/ICMP failure exception; requires the cumulative rebuilt engine |
| IPv4 source routes selecting the wrong checksum destination | Subsequent native TCP/UDP repair uses the final remaining route entry, retains completed-route behavior, and rejects malformed route geometry independently of checksum omission; requires the latest cumulative engine |
| Conflicting IPv4 options across fragments and retries | Additional native reassembly repair compares copied-option identity, Router Alert values and ultimate destinations; permits legal padding and mutable route records; keeps rejection for the current tracker using existing rule 123:1 |
| Slow fragments extending deadlines or reusing stale state after expiry | Subsequent native lifetime repair measures age from first arrival, caps IPv6 at 60 seconds, clears abandoned geometry, and applies native drops with longer ordinary idle retention; live scheduling remains separate |
| Fragment allocation pressure and retry after tracking-cache eviction | Additional native pressure repair checks all node allocation paths and blocks new fragmented datagrams of the affected IP family after premature state loss; existing contexts continue inspection and timed recovery is tested |
| Home Address option parser/checksum disagreement | Shared bounded helper checks visible Home Address structure and chooses the logical source for TCP/UDP/ICMPv6 checksum verification/update; the subsequent engine repair retains offset-zero wire prefixes, while actual ownership, binding state and logical-source flow grouping remain external |
| IPv6 fragment-header substitution and size/ECN disagreement | Engine repair preserves the offset-zero IPv6 prefix, retains CE congestion markings, rejects CE/Not-ECT conflicts, validates final sizes before copying and uses wide signed fragment arithmetic; original-fragment verdicts and reconstructed bytes are tested |
| IPv4 fragment-header substitution and size/ECN disagreement | Subsequent engine repair restores the offset-zero base header alongside saved options, combines ECN, and checks the total datagram size before insertion and reconstruction, including high-offset fragments received before offset zero |
| IPv6 overlap acceptance under permissive settings and rejected-buffer exhaustion | Subsequent engine repair rejects IPv6 overlaps independently of the configured threshold and immediately frees abandoned buffers; IPv4 uses the same cleanup under the supplied strict threshold, while tracked retries remain rejected |
| Advisory events suppressing prevention | Load only selected native builtin rules; event processing covers all action groups with matched bounded queue/log capacity; packet replay verifies a blocking rule still acts after multiple decoder advisories |
| Missing or silently broadened task gateway policy | Explicit deny-all by default, full binding fanout on gateway changes, rejection of unsupported port restrictions, and emergency containment attempts on admission failure; concurrent obsolete policy updates still require backend fencing |
| Stale updates erasing a pending deletion | Preserve persisted Terminating status, reject ordinary saves to terminating records, and atomically merge Redis status/delete changes into the current task with bounded retries |

No rules or SIDs were duplicated to implement these controls. They remain active
independently of signature selection. The raw `SnortEngine`/Go `Engine` APIs
remain detection interfaces for raw suspicious material; they do not authorize
network access. The MCP dispatch and diagnostic paths share the stricter request
gate. Rule fixtures intentionally include material that dispatch now rejects.

## Standards and intentional restrictions

The implementation enforces a documented subset; it is not a certification of
complete RFC or W3C conformance.

| Basis | Applied contract and stricter local policy |
| --- | --- |
| [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986.html), URI syntax | Absolute ASCII HTTP(S) URIs, valid percent triplets and authority grammar. The broker additionally requires UTF-8 decoded components, canonical IP/port spellings, and excludes fragments/userinfo/backslashes. Internationalized DNS must use ASCII labels. |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html), HTTP semantics | Header token and Connection-list syntax, proxy-owned routing/framing, separate repeated response values, explicit singleton-field checks, Content-Type parameter grammar and bounded complete bodies. The broker only supports uppercase GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS; GET/HEAD bodies, browser-context headers and non-ASCII/HTAB field values are denied by policy. These are stricter choices, not universal RFC prohibitions. |
| [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html), HTTP/1.1 messaging | Pre-parser streaming gates check CRLF, status/header syntax, framing conflicts, duplicate Content-Length, obsolete folding, declared lengths, chunk-size/extension grammar, data terminators and final empty trailer block. Valid hop-by-hop chunk extensions are removed after validation. HTTP/1.1 only, no pooling, compression, upgrade or trailers. Maintained runtime clients still serialize and decode the validated stream. |
| [RFC 4861](https://www.rfc-editor.org/rfc/rfc4861.html), IPv6 Neighbor Discovery | Native minimum lengths and Router Solicitation/Advertisement codes, supplemented by remaining ND codes, hop limit 255, link-local RA/Redirect sources, complete option-chain framing, and stateless target/flag/source-option/destination relationships. Unknown well-formed options remain allowed. Router ownership and other stateful requirements still need independent enforcement. |
| [RFC 6980](https://www.rfc-editor.org/rfc/rfc6980.html), fragmented Neighbor Discovery | Native rule rejects reassembled ND. A deliberately broader decoder policy rejects all atomic IPv6 fragments, including otherwise valid non-ND traffic; see the native profile's compatibility limits. |
| [RFC 8200](https://www.rfc-editor.org/rfc/rfc8200.html) and [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html), IPv6 and TCP | Release-pinned native decoder/reassembly/stream events and bounded state. This is a selected anomaly policy with explicit advisory exceptions for legal traffic, not a complete standards implementation. |
| [RFC 8200 section 4.5](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.5) and [RFC 5722 section 4](https://www.rfc-editor.org/rfc/rfc5722.html#section-4), IPv6 fragment overlaps | Additional [engine repair](../native-snort3/patches/fragment-overlap.md) abandons tracked reassembly and frees its buffers on overlap regardless of endpoint policy or overlap threshold. Exact duplicates reject the entire context; the optional duplicate-only exception is not used. IPv4 rejection at threshold one is local policy. Already-forwarded fragments cannot be recalled, and rejection retention remains bounded. |
| [RFC 7112](https://www.rfc-editor.org/rfc/rfc7112.html), IPv6 first fragments | Validate the original first fragment's complete supported extension/upper-layer header chain before reassembly can conceal a split header or misplaced Hop-by-Hop header. Unsupported upper-layer shapes and more than eight post-fragment extensions are denied by local policy. |
| [RFC 4302](https://www.rfc-editor.org/rfc/rfc4302.html), IP Authentication Header | Admit AH directly after IPv6 or behind supported extensions; validate declared AH lengths, twelve-byte fixed fields and IPv6 eight-byte alignment. A dedicated rule preserves the pinned decoder's other base Next Header admission decisions. This is structural inspection; IPsec authentication, Security Associations and replay protection remain endpoint responsibilities. |
| [RFC 791](https://www.rfc-editor.org/rfc/rfc791.html), [RFC 1122](https://www.rfc-editor.org/rfc/rfc1122.html) and [RFC 2113](https://www.rfc-editor.org/rfc/rfc2113.html), IPv4 options | Original option framing, zero padding, route/timestamp minimum fields and pointers, prohibited duplicate route/timestamp options and Router Alert length. Enforcing sender formats is strict IPS policy where endpoint processing is optional; unknown well-framed options stay opaque. |
| [RFC 2711](https://www.rfc-editor.org/rfc/rfc2711.html) and [RFC 2675](https://www.rfc-editor.org/rfc/rfc2675.html), IPv6 options | Router Alert and Jumbo length/placement/alignment, Router Alert uniqueness, and Jumbo base-length/value/fragment relationships. Duplicate Jumbo declarations are denied by local policy. Complete jumbograms are not supported by this pinned native profile. |
| [RFC 4303](https://www.rfc-editor.org/rfc/rfc4303.html), ESP | Visible fixed-header bounds, nonzero SPI and minimum complete-packet trailer space. Legal incomplete IPv4 first fragments defer to reassembly. No decryption, ICV, replay-window or SA authentication is performed. |
| [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html), ICMPv6 Echo | Request/Reply Code=0 in addition to native lengths and checksum enforcement. This does not implement all endpoint ICMP behavior. |
| [RFC 6275 sections 6.4.1 and 11.3.3](https://www.rfc-editor.org/rfc/rfc6275.html#section-11.3.3), Type 2 Routing | Original-wire length/segment fields and stateless home-address exclusions, including original first-fragment headers. Reserved bits are ignored. Home-address ownership, actual routing and care-of/home scope relationships require external state. Stock-engine final-address checksums are defective; a separately built and tested [engine repair](../native-snort3/patches/README.md) covers Type 2 verification and update. This does not establish full Mobile IPv6 support. |
| [RFC 791](https://www.rfc-editor.org/rfc/rfc791.html#section-3.1) and [RFC 9293 section 3.9.2.1](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.9.2.1), IPv4 source-route destinations | Additional [engine repair](../native-snort3/patches/ipv4-source-route.md) selects the final destination for TCP/UDP checksum verification and update. It validates route-entry/pointer geometry, preserves completed routes and opaque option data, and checks options in software. Ultimate-destination authorization, return routing and ownership are separate requirements. |
| [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259.html) and [RFC 7493](https://www.rfc-editor.org/rfc/rfc7493.html), JSON/I-JSON | UTF-8 and unique decoded object names, valid Unicode scalar values without noncharacters, finite numbers, and no replacement of malformed escapes. Integral numeric values outside ±(2^53−1) must be strings. Depth/work ceilings and object-only MCP arguments are local policy. |
| [W3C Fetch Metadata](https://www.w3.org/TR/fetch-metadata/) | Browser context fields are not agent identity or approval. Agents cannot assert `Sec-Fetch-*` or other `Sec-*` metadata through this broker. It does not implement a browser, browser CORS processing or the W3C platform as a whole. |

For requests, missing content types on nonempty bodies are inferred as JSON for an initial
`{`/`[`, otherwise UTF-8 plain text. Explicit JSON and `application/*+json` bodies
must parse strictly. Only an optional UTF-8 charset parameter is supported.
Content-Type parameters reject whitespace around `=` before normalization.
Spaces around the semicolon and quoted-pair spellings that decode to UTF-8 are
accepted. Extra parameters and empty parameter slots are denied by request policy.
Binary, multipart, XML, alternate charset and application compression need an
explicit inspector design before they can be enabled; changing a signature to
`alert` cannot enable them. Base64 or business-specific encodings carried inside
allowed text still require application-aware authorization and inspection.

Response Content-Type values support ordinary token and quoted parameters, with
case-insensitive unique parameter names and at most 128 semicolon slots. An
explicit charset must be UTF-8. Parameter names containing `*` are rejected to
avoid alternate continuation/encoding interpretations; this is a local restriction.
Other syntactically valid media types and parameters remain extensible, while the
body must still be valid UTF-8. Connection lists tolerate empty members within a
128-member budget across repeated fields and reject nominations of the explicitly
protected routing, framing, authentication and representation fields. These checks
cover a documented field set, not every present or future HTTP extension.

## Limits and response handling

| Resource | Limit |
| --- | --- |
| Request URL / body | 16 KiB / 1 MiB |
| Supplied headers | 128 fields, 64 KiB total, 8 KiB per field |
| JSON | 64 nested containers, 100,000 tokens |
| MCP message | 8 MiB |
| Process lifetime | 10,000 incoming RPC lines and 64 MiB of RPC input; 1,000 request/diagnostic inspection attempts and 64 MiB inspected input; 64 MiB response body input |
| One response | 64 KiB headers, 128 header fields, 8 KiB per field; 10 MiB UTF-8 body |
| Chunked response framing | 8 KiB per size/extension line, 4,096 data chunks, 64 KiB cumulative extensions and 192 KiB cumulative framing |
| Response metadata | 128 Connection members per header block; 128 Content-Type parameter slots |
| Request deadline | Default 30 seconds, caller range 1–120; connection/header sublimits can terminate earlier |

Limits reject rather than silently inspect or return a truncated prefix.
Body readers may consume one additional byte to detect overflow; these are
logical application limits rather than a cap on kernel/client buffer read-ahead.
Go's lifetime response counter measures content read by the application, including
partial content returned before an error. Python's production reader additionally
counts consumed body framing, including partial reads before a timeout. Neither is
a raw network-byte quota covering TLS overhead, headers or unread buffered bytes.
Per-response wire/framing limits and the request-count budget separately bound
those costs.
Invalid RPC lines consume the RPC budget. Diagnostics consume inspection capacity.
Response capacity exhaustion prevents further dispatch. Limits are per process;
an administrator can restart the process, so they do not replace account-wide
quotas or a supervisor's resource limits. Python requires POSIX main-thread
timers for inspection and total transport deadlines and caps outstanding resolver
threads; it fails closed when those facilities are unavailable.

Responses include `header_values` with every value as a separate array entry;
use this representation when repeatable fields matter. The compatibility
`headers` object keeps `Set-Cookie` as an array; other repeated fields are joined
by Go and retain their last value in Python. Retrieved text remains untrusted content. It is not
automatically scanned for semantic prompt injection or declared safe to execute.

HEAD and 304 responses have no content even when their representation metadata
contains a large Content-Length or Transfer-Encoding. A 204 cannot carry framing
fields, and a 205 must have empty content under any supported framing. EOF-delimited
responses are bounded but cannot distinguish an intentional close from network
truncation; use explicit length/chunk framing when completeness is required.

## Remaining security boundary

An allowed origin can still expose a destructive or overly privileged API.
Endpoint, method, resource, spending and user-approval authorization belong in an
independent application policy, with task-scoped credentials. A valid JSON
request is not proof of authorization. Unknown header conventions, opaque secret
values and multi-request business logic cannot be fully recognized by this
signature catalog. Plain HTTP also provides no server authentication; configure
HTTPS origins for sensitive operations.

The agent must not be able to edit the proxy, its startup arguments or catalog,
or bypass it using a shell, browser, other tools or direct sockets. Enforce that
with an external OS/container/network boundary. This source change does not
install such a boundary or change running deployments. The Go `WithHTTPClient`
and Python explicit `opener` constructor are trusted embedding/testing hooks;
their callers assume responsibility for transport enforcement. They are not MCP
arguments or CLI bypass switches. With an explicit origin list, offline origin
checks also apply to those hooks.

The controller now also [fails closed during task network admission](networking.md):
missing/empty gateway allowlists persist a deny-all policy, admission failures
prevent resume and trigger emergency deny/suspension attempts, and unsupported
port restrictions are rejected instead of discarded. Persisted deletion markers
survive stale status writes. A reproduced cross-process race still permits an
obsolete allow policy to replace a newer denial, and an already in-flight resume
cannot be cancelled by a local status update. The required external changes are
specified in [admission fencing](admission-fencing.md). This does not establish live
dataplane enforcement or atomic revocation.

## Regression evidence

`pkg/security/httpguard/testdata/request_cases.json` shares 121 request-boundary
cases between Go and Python. Dedicated tests exercise malformed MCP envelopes,
DNS rebinding and mixed DNS answers, exact origins, TLS hostname/certificate
verification, raw response headers, budgets and no-dispatch outcomes.
`pkg/security/egress/testdata/response_metadata_cases.json` adds 114 shared response
metadata cases, with additional raw final/interim-header regressions. The
2,580 signature fixtures continue to isolate the imported rules, and the import
reproducibility check prevents duplicate predicates or IDs. These are local
regression results, not a measured real-world detection rate, external penetration
testing or proof against all future attacks. Separate native configuration and
offline replay evidence is in [native-snort3](../native-snort3/README.md), with exact
version, configuration hashes, expected/observed rule IDs, benign fixtures and
deliberate policy restrictions. Offline `would_drop` verdicts do not establish live blocking
and omit checksum-drop enforcement. The separate
[checksum tests](../native-snort3/checksum-validation.json) verify 16 cases using
actual file-only inline DAQ verdicts and forwarded-output captures. The
[Next Header comparison](../native-snort3/next-header-validation.json) checks all
256 base-header values before and after the AH correction, retaining the other
243 policy rejections. These checks still do not validate a deployed traffic path.
The [IP structure comparison](../native-snort3/structure-validation.json) adds
151 paired option/ESP/Echo/Type 2 routing cases, with 91 newly blocked malformed
cases and 60 unchanged controls. Each side checks actual file-only
inline verdicts and emitted packet bytes; source hashes, exact counts and the
five-rule delta are recorded. Pure parsers additionally pass sanitizer checks.
The [mobility checksum audit](../native-snort3/mobility-checksum-validation.json)
separately records a native engine conformance failure: its Type 2 transport
checksums use the base destination rather than the final Home Address. The
[engine source repair](../native-snort3/patches/README.md) passes 90 paired packet
cases, including checksum rewrites in TCP, UDP and ICMPv6; it requires a rebuilt
engine and cannot be enabled by loading rules alone. The repaired engine also
passes the existing native regression suites. The additional
[fragment checksum repair](../native-snort3/patches/fragment-checksums.md) closes
the tested reassembled UDP/ICMP checksum gap and requires software verification
for all four transport codecs. Its cumulative engine passes 312 paired cases
in 624 runs, with 84 previously forwarded invalid cases now blocked and 156
valid controls preserved; all four existing native suites also pass. Tested
fragment retries remain blocked. A subsequent
[IPv4 source-route repair](../native-snort3/patches/ipv4-source-route.md) passes
236 paired cases, blocking 86 previously forwarded invalid cases and restoring
74 valid cases. It includes TCP/UDP checksum updates, malformed route geometry,
source-routed fragments and completed routes. Existing packet dispositions and
all 90 Type 2 cases also pass on the cumulative engine. The subsequent
[fragment option repair](../native-snort3/patches/fragment-options.md) adds bounded
cross-fragment comparisons and rejects retries after a conflict. Its 320 paired
cases pass, including 156 valid controls, 92 retry cases and eight fresh-ID
isolation controls; all seven preceding native suites also pass. This combines
RFC copy-bit/padding checks with an explicitly documented local policy against
ambiguous reconstruction. The subsequent
[fragment lifetime repair](../native-snort3/patches/fragment-lifetime.md) passes
372 paired timing cases and all eight preceding native suites. It fixes the
sliding deadline, stale expiration geometry and short ordinary retention, with
explicit local policy for timed drops and quarantine. The subsequent
[fragment pressure repair](../native-snort3/patches/fragment-pressure.md) passes
270 paired cases and all nine preceding native suites. It enforces fragment-node
limits and retains a process-wide guard per IP family when capacity eviction
loses recent state. Tested recovery avoids extending the guard just because
rejected contexts are pruned. The guard intentionally also denies legitimate
new fragmented traffic during quarantine; it is a local admission policy.
The subsequent [Home Address repair](../native-snort3/patches/home-address.md)
passes 354 paired cases and all ten preceding native suites. It adds visible
option checks to existing SID 9201013 revision 2 and corrects transport source
checksums and checksum updates. A separate
[header-retention audit](../native-snort3/ipv6-fragment-header-audit.json)
demonstrates 18 bypasses of a temporary Hop Limit blocking policy across
72 wire cases / 144 native runs. IPv6 reconstruction takes the completing
fragment's header. The subsequent
[IPv6 prefix repair](../native-snort3/patches/ipv6-prefix.md) closes those 18
bypasses and passes all 144 header-policy runs, 816 prefix/ECN/size cases,
72 large-fragment IPv4 regressions and the eleven preceding native suites.
The subsequent [IPv4 header repair](../native-snort3/patches/ipv4-prefix.md)
closes 16 further header-policy bypass cases and passes 936 paired
header/ECN/size cases plus all 15 preceding native suites. It adds no product
rule or SID; applying the cumulative native engine changes is required.
The subsequent [fragment overlap repair](../native-snort3/patches/fragment-overlap.md)
passes 1,140 paired cases, all 16 preceding suites and 3,926 native
AddressSanitizer cases. It restores IPv6 rejection in 348 cases using permissive
overlap settings and restores valid traffic in 24 buffer-cleanup controls.
The supplied strict threshold already blocked the tested overlaps; its
improvement is immediate release of rejected fragment buffers. No rule or SID
is added.
The additional 48-case Home
Address wire-prefix audit also passes after the repair, without establishing
endpoint-valid Mobile IPv6 contexts. Processing before
reassembly, logical source grouping, home-address bindings and actual
ownership, unknown option semantics, other active routing types and ultimate-route
authorization also remain open, along with eager idle cleanup,
multi-worker/failover behavior and live timer/endpoint behavior.
Complete IPv6 jumbograms and endpoint-dependent option/IPsec processing also
remain outside validated behavior. These engine builds are local artifacts,
not deployed protection.
