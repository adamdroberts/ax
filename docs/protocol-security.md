# Protocol and egress security contract

The [restricted DNS proxy](dns-proxy.md) adds exact-name resolution without
client-triggered upstream requests, plus DNS-over-HTTP escape signatures. Its
network boundary and deployment requirements are separate from protocol parsing.

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

Production HTTPS clients verify the original hostname against certificate DNS
subject alternative names (SANs), or a literal address against IP SANs. Legacy
Common Name fallback is disabled; certificate trust, validity and server-purpose
verification remain enabled. Whole-label leftmost wildcards match one DNS label.
Python conservatively requires OpenSSL 1.1.1l or newer and native support for
disabling Common Name checks, refusing startup if either is unavailable. This
avoids older releases where the flag could be ineffective, including runtimes
that might have a Python-level workaround. The explicit trusted embedding opener
is outside this production transport contract. System roots, TLS 1.2 minimum and
HTTP/1.1 ALPN remain in use.

The built-in address exclusions are conservative and must be maintained with
the [IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)
and [IPv6 special-purpose registries](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml).
An allowed origin does not override the public-address requirement.
Both runtimes exclude scoped IPv6 values and reject resolver results with more
than 64 address entries, including duplicates, before creating any destination
socket. They validate the entire admitted answer set before trying its first
address. The count is a local work limit, not an RFC limit on DNS records; it
does not cap allocation inside the system resolver before that resolver returns.

The 2026-09-27 [address admission audit](address-admission-validation.json) checked
full-prefix coverage of all 51 prefixes in the saved IANA registry snapshots,
including assignments marked globally reachable. Shared regression data covers
254 address boundaries and invalid/scoped values, plus 37 resolver answer sets.
The snapshots and generator live in `pkg/security/egress/testdata`; they do not
update automatically or prove reachability, ownership or deployed routing.

## Gaps addressed

| Bypass class | Enforced protection |
| --- | --- |
| DNS rebinding, mixed public/private answers and alternative IP spellings | Exact origin authorization, canonical address syntax, whole-answer validation and numeric socket pinning |
| Proxy environment variables or redirect destinations changing the route | Dedicated direct transport, no environment proxy or automatic redirects |
| Legacy certificate names admitting the wrong identity form | SAN-only DNS/IP identity verification before HTTP delivery; no Common Name fallback; refuse unsupported Python TLS runtimes |
| Request smuggling, framing and connection manipulation | Reject caller framing/hop headers; reconstruct one HTTP request using the standard client; no connection reuse |
| Routing and method-override headers | Reject `Forwarded`, `X-Forwarded*`, original/rewrite URL/host and method-override fields |
| Forged browser or agent approval context | Reject `Sec-*`, `Origin`, `Referer`, `X-Real-IP`, `X-Agent-ID` and `X-Approval-Token` |
| Duplicate JSON keys and Unicode replacement | Validate original bytes/escapes before ordinary decoding; reject duplicate decoded keys, invalid UTF-8, lone surrogates and noncharacters |
| Ambiguous JSON returned to the agent | Validate complete application/json and structured +json response bodies, including complete 206 ranges; preserve accepted bytes and charge rejected bodies to the response budget |
| Malformed XML or entity declarations returned as structured content | Validate complete declared XML before delivery, including complete single/multipart ranges; reject DTDs, unknown entities, ambiguous namespaces and excessive structure |
| Hidden body formats or compressed data | UTF-8 text, JSON and form bodies only; identity encoding; reject unsupported media types and charsets |
| Parser disagreements about URLs | Reject malformed escapes, fragments, userinfo, controls, backslashes, ambiguous numeric hosts and noncanonical IP/port forms |
| Deeper encoding than the inspection pipeline understands | Reject if further unseen decoded views remain after the three-round normalization budget |
| Repeated large inputs and allocation amplification | Per-message and process-lifetime limits; reuse folded buffers instead of copying every buffer for every case-insensitive rule |
| Malformed or unacknowledged MCP calls | Validate JSON-RPC 2.0 envelopes, typed IDs, object arguments, duplicate fields and known request properties; tool-call notifications cannot dispatch |
| Malicious response framing | Validate raw status/header lines and streaming body framing before client normalization; reject conflicting/duplicate framing, obsolete folding, bare LF, malformed chunk extensions/terminators, truncation, upgrades, trailers and encoded responses |
| Ambiguous response metadata | Check interim and final blocks before normalization; reject duplicate singleton fields, malformed Connection options, protected metadata nominated as hop-by-hop, and ambiguous Content-Type parameters |
| Malformed or inconsistent declared content digests | Validate Content-Digest syntax and supported hash lengths; verify all declared SHA-256/SHA-512 values before request inspection/dispatch or response delivery; buffer digest-bearing direct Go requests before DNS |
| Representation digests checked against the wrong bytes or left unverified | Repr-Digest uses complete selected bytes; reconstruct consistent multipart ranges within one bounded response, and deny declared integrity when required bytes are unavailable |
| Malformed integrity preferences or preferences used to weaken verification | Parse both Want-* dictionaries with integer weights 0..10; preserve them as hints and keep all actual digest checks independent |
| Ambiguous download filename metadata | Validate HTTP Content-Disposition before MIME-style recovery; reject duplicate fields/parameters, invalid extended encodings and selected unsafe filename forms; filenames remain advisory |
| Malformed URI labels or redirect references interpreted differently by downstream consumers | Validate request Content-Location and interim/final response Location and Content-Location before inspection or delivery; preserve admitted references without resolving or authorizing them |
| Malformed or amplifying HTTP byte ranges | Validate before dispatch and diagnostics; limit list size and numeric values; reject repeated, overlapping or reversed ranges and duplicate fields |
| Inconsistent partial uploads or responses | Validate Content-Range offsets, totals and octet lengths; require one fulfilled range on partial PUT; validate multipart boundaries and reject conflicting bytes at overlapping positions before MCP returns content |
| Malformed conditional requests and response validators | Parse entity tags without quoted-string repairs; bound tag lists; require strong If-Range tags with GET Range; validate HTTP-date grammar and calendar fields before dispatch or response delivery |
| Responses contradicting request conditions | Require conditional GET/HEAD for 304; check explicit returned validators against request conditions in precedence order; reject mismatched If-Range on 206 and Last-Modified later than Date |
| Invalid packet and reassembly behavior | Separate native Snort profile enables release-pinned decoder, IP reassembly and TCP stream checks, required structural Neighbor Discovery validation, Hop-by-Hop placement, AH framing, and original first-fragment header completeness checks; requires an independent packet sensor |
| Timestamp checks disabled by a zero clock or opening SYN data, or falsely enabled after negotiation | Additional native engine repair preserves handshake policy and sequence tracking, ignores unnegotiated timestamp options, and rejects missing or older negotiated timestamps through existing events; requires the cumulative rebuilt engine |
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
| Conflicting final-fragment lengths and incomplete reconstruction | Subsequent engine repair requires consistent final-length declarations in both IP versions and continuous byte coverage before reconstruction; conflicts free saved buffers and reject subsequent tracked fragments |
| ICMP normalization splitting or merging fragment identities | Subsequent engine repair preserves full fragment IDs and both wire addresses, preventing continuation Next Header changes from evading reassembly and keeping independent datagrams isolated |
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
| [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html) and [RFC 8941](https://www.rfc-editor.org/rfc/rfc8941.html), integrity fields and preferences | Validate the four request/response fields with shared keys and parameter grammar. Content-Digest covers actual content; Repr-Digest covers complete representation bytes. Verify declared SHA-256/SHA-512 values. Want-* values are integer hints from 0 to 10. Duplicate-algorithm rejection, strong-algorithm requirements for actual digests and rejection of unverifiable representations are stricter local policy. |
| [W3C XML 1.0 Fifth Edition](https://www.w3.org/TR/xml/), [Namespaces in XML 1.0 Third Edition](https://www.w3.org/TR/xml-names/) and [RFC 7303](https://www.rfc-editor.org/rfc/rfc7303.html) | Bounded UTF-8, DTD-free XML response admission. Single-root syntax, characters, Fifth Edition names, references, declarations, namespace scope and expanded attribute uniqueness. DTD/encoding exclusions and work limits are broker policy; this is not DTD/schema validation or a general XML processor. |
| [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525.html), TLS service identity | Original DNS/IP reference identity matched against its corresponding SAN type; no Common Name fallback; bounded wildcard matching. Python's minimum OpenSSL version is a conservative runtime policy. Certificate-chain validation remains the TLS library's responsibility. |
| [RFC 6266](https://datatracker.ietf.org/doc/html/rfc6266), [RFC 8187](https://www.rfc-editor.org/rfc/rfc8187.html) and [RFC 5646](https://www.rfc-editor.org/rfc/rfc5646.html), HTTP Content-Disposition | Unique fields and case-insensitive parameters, token/quoted syntax, extended percent encoding with UTF-8 and legacy Latin-1, and well-formed language tags. Rejection rather than recovery, bounded parameters and filename exclusions are validator policy. MIME body-part fields remain a separate contract. |
| [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986.html), URI syntax | Absolute ASCII HTTP(S) URIs, valid percent triplets and authority grammar. The broker additionally requires UTF-8 decoded components, canonical IP/port spellings, and excludes fragments/userinfo/backslashes. Internationalized DNS must use ASCII labels. |
| [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986.html) and [RFC 9110 sections 4, 8.7 and 10.2.2](https://www.rfc-editor.org/rfc/rfc9110.html), URI-reference metadata | Location permits a URI-reference including a fragment; Content-Location permits absolute or partial references without fragments. Check component alphabets, escapes, scheme and authority syntax, IPv6/IPvFuture literals and numeric port syntax. HTTP(S), including inherited network-path references, requires a nonempty host and forbids userinfo. Metadata admission does not grant destination permission. |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html), HTTP semantics | Header token and Connection-list syntax, proxy-owned routing/framing, separate repeated response values, explicit singleton-field checks, Content-Type parameter grammar and bounded complete bodies. The broker only supports uppercase GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS; GET/HEAD bodies, browser-context headers and non-ASCII/HTAB field values are denied by policy. These are stricter choices, not universal RFC prohibitions. |
| [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html), HTTP/1.1 messaging | Pre-parser streaming gates check CRLF, status/header syntax, framing conflicts, duplicate Content-Length, obsolete folding, declared lengths, chunk-size/extension grammar, data terminators and final empty trailer block. Valid hop-by-hop chunk extensions are removed after validation. HTTP/1.1 only, no pooling, compression, upgrade or trailers. Maintained runtime clients still serialize and decode the validated stream. |
| [RFC 4861](https://www.rfc-editor.org/rfc/rfc4861.html), IPv6 Neighbor Discovery | Native minimum lengths and Router Solicitation/Advertisement codes, supplemented by remaining ND codes, hop limit 255, link-local RA/Redirect sources, complete option-chain framing, and stateless target/flag/source-option/destination relationships. Unknown well-formed options remain allowed. Router ownership and other stateful requirements still need independent enforcement. |
| [RFC 6980](https://www.rfc-editor.org/rfc/rfc6980.html), fragmented Neighbor Discovery | Native rule rejects reassembled ND. A deliberately broader decoder policy rejects all atomic IPv6 fragments, including otherwise valid non-ND traffic; see the native profile's compatibility limits. |
| [RFC 8200](https://www.rfc-editor.org/rfc/rfc8200.html) and [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html), IPv6 and TCP | Release-pinned native decoder/reassembly/stream events and bounded state. This is a selected anomaly policy with explicit advisory exceptions for legal traffic, not a complete standards implementation. |
| [RFC 9293 sections 3.1 and 3.2](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.1) and [RFC 2018 sections 2 and 3](https://datatracker.ietf.org/doc/html/rfc2018#section-2), TCP options | Native SID 9201017 checks original option lengths, zero padding, complete SACK blocks and SYN-only MSS/SACK-Permitted. Unknown framed options remain opaque. [844 packet cases and 100,000 randomized parser inputs](../native-snort3/tcp-options-validation.json) validate the change; negotiated permission, sequence windows and extension authentication remain outside this stateless check. |
| [RFC 2018 section 4](https://datatracker.ietf.org/doc/html/rfc2018#section-4), SACK permission | Native SID 9201018 requires the peer's admitted SYN offer and an established connection before SACK. State commits after packet admission, including completed fragment flows; rejected offers and reused connections cannot carry permission across those boundaries. Conflicting retransmissions narrow permission as strict local policy. [344 conversations and 100,000 randomized histories](../native-snort3/tcp-sack-validation.json) validate these paths; SACK sequence truth and authentication remain separate requirements. |
| [RFC 7323 sections 3.2, 5.2 and 5.3](https://www.rfc-editor.org/rfc/rfc7323.html#section-3.2), TCP timestamps | The cumulative [engine repair](../native-snort3/patches/tcp-timestamps.md) ignores unnegotiated options and applies missing/older timestamp checks after agreement, including zero and wrapping clocks and SYN data. Resets retain their exception and rejected data can recover. [3,120 conversations](../native-snort3/tcp-timestamp-validation.json) pass in regular and instrumented builds. Removing OS tolerances and denying the ambiguous half-range difference are strict local policy; long-idle aging, timestamp authentication and final-admission transactional tracking are not proved. |
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

When a request or response supplies `Content-Digest`, its RFC 8941 dictionary must contain
at least one `sha-256` or `sha-512` byte sequence of the correct length. Every
declared supported digest must match. Unknown and deprecated algorithm entries
are parsed but never used as integrity evidence; they can accompany a supported
algorithm. Missing `Content-Digest` does not create a digest requirement. Empty
fields, unsupported-only dictionaries, duplicate algorithm keys and malformed
parameters are denied by local policy. Ordinary parameter values are ignored
after syntax validation; duplicate opaque parameter keys remain acceptable.
Absent base64 padding is synthesized and nonzero unused pad bits are tolerated
as RFC 8941 specifies. Date and display-string parameters are outside the
RFC 8941 types referenced by RFC 9530. Existing visible-ASCII header restrictions
and byte budgets still apply; this is not a general Structured Fields library.

For responses, hash input is the unchanged HTTP content after transfer decoding: a single 206
fragment, the complete multipart envelope, or empty content for HEAD, 1xx, 204,
205 and 304. MIME part fields do not select HTTP message digest behavior.
Representation reconstruction and `Repr-Digest` use the separate checks below. The Go
transport hashes incrementally and rejects at EOF with a persistent read error;
streaming embedders must discard bytes if the final read fails. MCP buffers the
bounded content and verifies it before exposing any result. Its complete-body
check also covers trusted custom transports; Python checks before MCP delivery.
Consumed rejected bytes remain charged. Repeated Content-Digest values survive
tool-result formatting, including differently cased field names, and Connection
cannot nominate the field for hop-by-hop removal. These unsigned hashes cannot
establish sender identity, application authorization or safe content: a malicious
sender can compute a matching hash, and an optional digest can be omitted.

Requests use the exact UTF-8 body bytes supplied to the tool, before any
signature inspection, DNS lookup or dispatch. JSON reserialization, form
decoding, Unicode normalization and line-ending conversion are never part of
the hash input. A partial PUT hashes its content fragment. Empty request content
uses the empty-content hash. The diagnostic tool applies the same checks.
Correct digests do not bypass signatures, origins or other admission policies.

The direct Go transport uses the same parser and independently binds every
digest-bearing body to a verified snapshot before DNS. It reads the actual
`Body`, never the caller's `GetBody` replay, and sends exactly the verified bytes
with their measured content length. It reads at most 1 MiB plus one overflow
byte, rejects declared/actual length mismatches and read failures, and closes
the original stream once. Zero length with a nonnil body retains Go's
unknown-length meaning; other positive declarations must match. Cancellation
closes the original stream to interrupt a pending read, relying on the
`net/http.Request.Body` contract that Close unblocks concurrent Read. A
custom reader that violates that contract cannot be forcibly terminated.
Direct requests with neither digest field retain their existing transport behavior; direct
transport use does not itself apply the broker's signature engine.

`Repr-Digest` uses the same dictionary grammar, supported algorithms and budgets,
but covers the entire selected representation. Ordinary request bodies,
including PATCH documents, provide those bytes. A partial PUT with Repr-Digest
is admitted only when its Content-Range establishes complete coverage from zero.
The Content-Digest and Repr-Digest fields remain independent: each must match
its respective bytes, and the same algorithm may appear once in each field.

Ordinary response representations are checked over their enclosed bytes.
A single 206 must establish complete coverage; a multipart 206 must provide a
known total and continuous, consistent coverage in that one response. The
digest covers reconstructed bytes in position order, including each byte once;
it does not cover MIME boundaries, metadata, duplication or part order.
Gaps, unknown totals and totals above the body budget are rejected when
Repr-Digest is present, without allocating memory from an advertised offset or
total. Declared JSON/XML checks continue to apply to reconstructed content.

HEAD and 304 do not transmit the selected representation. Only an explicit
Content-Length of zero allows verification against empty representation data.
Otherwise, a present Repr-Digest is rejected as unverifiable. Responses with
status 204 or 205 and Repr-Digest are also rejected: their empty message content
does not establish the bytes of a referenced or post-write resource. Interim
responses have no selected representation data here and use the empty hash.
These restrictions are local admission choices; valid HTTP exchanges can carry
digests of representation data this proxy does not possess. The proxy does not
fetch resources, combine different responses, or assume an absent body proves
an empty resource.

Raw Go streaming verification and both MCP implementations enforce these
checks. Invalid streamed content produces a persistent error at EOF; streaming
callers must discard previously read bytes on failure. MCP validates before
delivery. Repeated Repr-Digest values remain available in tool output, Connection
cannot remove the field, and MIME part fields do not become HTTP digest fields.
Legacy Digest fields and message signatures remain outside the implemented
integrity contract. Trailer sections remain prohibited by the protocol profile.

`Want-Content-Digest` and `Want-Repr-Digest` accept RFC 8941 dictionaries whose
values are integers from 0 through 10. An empty dictionary is valid. Leading
zeros and negative zero retain their integer meaning; decimals, booleans,
strings, byte sequences and inner lists cannot stand in for integers.
The fields use the same key and opaque-parameter grammar as the integrity
fields, with the same member/parameter and header byte limits. Unknown and
deprecated algorithm names may appear as preferences. Each field is independent;
duplicate algorithm keys within one field are denied as local policy.
Repeated field lines are combined semantically, so an empty line alongside
another value is rejected as an empty dictionary member.

Preferences remain hints. The proxy does not require a digest because a hint
was sent, select a requested algorithm, require the peer to honor a preference,
or suppress verification when the preference is zero. An actual digest still
needs a supported strong algorithm and matching bytes. Both broker paths and
the direct Go transport validate request preferences before dispatch. Raw,
interim, bodyless and complete-body response paths validate them before delivery.
Repeated output values are preserved, Connection cannot nominate either field,
and HTTP preference semantics are not applied to MIME part fields.

HTTP `Content-Disposition` accepts token/quoted parameters, including spaces
around `=` as allowed by its grammar, and preserves distinct `filename` and
`filename*` fallback parameters. Extended values require a charset and valid
percent escapes; supported charsets are UTF-8 and legacy ISO-8859-1. Their optional
language tags receive RFC 5646 well-formedness checks, including grandfathered
tags and duplicate variant/extension rejection, without registry membership or
extension-specific interpretation. Unknown disposition types and ordinary
extension parameters remain available. At most 128 parameters are admitted.

Filename policy additionally rejects empty names, path separators, reserved
filename punctuation, leading/trailing whitespace, trailing dots, control/format
characters, Unicode noncharacters, quoted-pair ambiguity and residual percent
triplets. Both fallback names are checked independently. HTTP parameter
continuations are rejected instead of allowing MIME recovery to combine them.
These are conservative admission restrictions, not universal RFC syntax bans or
a guarantee that a filename is safe for a particular filesystem or shell.
Accepted names remain advisory and do not authorize a file write. RFC 6266
explicitly excludes fields inside MIME payloads; byte-range part metadata keeps
its existing separate policy. This change does not interpret or sanitize those
part filenames.

Conditional request fields follow [RFC 9110 section 13.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1).
`If-Match` and `If-None-Match` accept a sole wildcard or a bounded entity-tag list.
Commas inside a tag are data, and backslashes are preserved literally instead of
being unescaped. The weakness marker is case-sensitive. Duplicate physical
conditional/Date fields, empty tag lists and more than 128 list slots (including
empty slots) are rejected by local policy. Weak tags are valid in ordinary tag
lists; `If-Range` requires a strong tag or a valid date and an accompanying GET
Range request. Both MCP dispatch and diagnostics apply these checks; the Go
transport also enforces them before DNS or dialing.

Outgoing `Date`, `If-Modified-Since`, `If-Unmodified-Since` and date-valued
`If-Range` use IMF-fixdate. Incoming `Date` and `Last-Modified` accept IMF-fixdate,
RFC 850 and asctime forms, as required by
[RFC 9110 section 5.6.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.7).
Incoming ETag fields require exactly one entity tag. Validation applies to raw
informational/final response blocks, the parsed response and known metadata
fields in multipart parts. Original values are retained. Calendar checks include
weekday agreement, month lengths, Gregorian leap years and the year floor of
1900 specified by [RFC 5322 section 3.3](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.3).
RFC 850's two-digit year is resolved in the 100-year window ending 50 calendar
years after the receiver's UTC clock. Leap-second syntax at 23:59:60 is preserved;
the broker does not verify historical or future leap-second announcements.
Clock accuracy, validator strength/provenance, cross-response consistency and
whether an origin actually honors a precondition remain separate requirements.
In particular, accepting a date-valued If-Range does not prove the client has no
entity tag or that the date is a strong validator. No cache or resource-state
authorization is implemented by these checks.

With request context, response validation also rejects unsolicited 304 responses,
304 on other methods, and explicit GET/HEAD 200/206/304 validator contradictions.
It respects [conditional precedence](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.2.2):
If-Match suppresses If-Unmodified-Since, and If-None-Match suppresses
If-Modified-Since, even when a returned validator is absent. If-Range requires
exact strong-tag or date agreement on 206 when the corresponding metadata is
present. Date comparisons preserve leap seconds. Last-Modified later than Date
is rejected whenever both fields are supplied in a header block.

Missing validators remain unknown. Mutation responses can carry post-write
validators; redirects and errors do not assert that preconditions succeeded.
An older modification date alone does not reject 200/206 for If-Modified-Since,
whose evaluation is a SHOULD. Matching If-Match/If-Unmodified-Since against
returned metadata is a stricter local policy for upstream caches/intermediaries,
which the RFC permits to ignore these origin preconditions. Helpers without
request context cannot perform correlation; production dispatch supplies it.

Request `Content-Location` and interim/final response `Location` and
`Content-Location` receive URI component validation before inspection, DNS or
response delivery. A parsed-response backstop also applies before complete-body
early returns. Duplicate fields, case-variant map keys and empty internal value
arrays are rejected. An empty field value is distinct: the URI grammar permits
an empty relative reference. Existing field budgets still apply, including the
field name and framing bytes; 8,000-octet reference values are supported.

`Location` can contain a fragment; `Content-Location` cannot, even when the
fragment is empty. Percent triplets remain encoded and are never normalized,
decoded or resolved by this validator. Numeric port spelling and registered-name
syntax are checked as URI metadata, without asserting that a port can be dialed,
a name is a DNS hostname, or an address is public. Generic non-HTTP schemes,
including opaque identifiers and file labels, remain advisory metadata; their
individual scheme specifications are not all validated. HTTP(S) authorities
must have a host and cannot contain userinfo. Network-path references inherit
that HTTP(S) context. Scoped IP literals are outside the admitted profile.

No accepted label causes a fetch, redirect, source rewrite or expansion of the
origin allowlist. Every later request still passes the separate, stricter target
URL and address checks. MIME part fields retain their separate contract,
including RFC 2557 comments/encoding rules for Content-Location; these URI
metadata checks do not add MIME URI interpretation or resolution. Location on
an HTTP request has no standard response-field semantics applied by this check.

## Limits and response handling

| Resource | Limit |
| --- | --- |
| Resolved destination addresses | 1–64 entries, including duplicates; every entry must be public and unscoped before any destination socket is created |
| Request URL / body | 16 KiB / 1 MiB |
| Supplied headers | 128 fields, 64 KiB total, 8 KiB per field |
| HTTP Range | One field on GET; bytes only; 16 list slots including empty slots; values from 0 through 2^63-1 |
| HTTP Content-Range | Bytes only, values through 2^63-1; partial PUT length must equal its UTF-8 body bytes; single 206 length must match received content |
| Conditional HTTP fields | One value per field; at most 128 entity-tag list slots; existing ASCII and 8 KiB field limits; HTTP dates use bounded fixed-format parsing |
| Multipart byte ranges | At most 16 parts; boundary 1–70 MIME characters; 128 fields and 64 KiB of headers across all parts; 8 KiB per part header line; existing 10 MiB response limit |
| JSON | 64 nested containers, 100,000 tokens |
| MCP message | 8 MiB |
| Process lifetime | 10,000 incoming RPC lines and 64 MiB of RPC input; 1,000 request/diagnostic inspection attempts and 64 MiB inspected input; 64 MiB response body input |
| One response | 64 KiB headers, 128 header fields, 8 KiB per field; 10 MiB UTF-8 body |
| Chunked response framing | 8 KiB per size/extension line, 4,096 data chunks, 64 KiB cumulative extensions and 192 KiB cumulative framing |
| Response metadata | 128 Connection members per header block; 128 Content-Type parameter slots |
| Content-Digest / Repr-Digest | Per field: 1,024 algorithm members across repeated lines and 256 parameters per member; shared 8 KiB field and 64 KiB block ceilings; only two supported hash algorithms |
| Want-Content-Digest / Want-Repr-Digest | Per field: 1,024 algorithm preferences and 256 parameters per member, within the same header ceilings; integer weights 0..10 |
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
Timer expiry uses private cancellation until the budget boundary, so ordinary
parser and network error handlers cannot swallow it. The boundary restores the
previous signal handler, rejects a suppressed expiry, and checks the absolute
monotonic deadline before starting work and accepting success. Python can
[delay signal-handler execution during native code](https://docs.python.org/3/library/signal.html#execution-of-python-signal-handlers),
so these are result-admission checks, not a hard real-time preemption guarantee;
an external supervisor is still needed for process resource enforcement.
DNS worker objects are allocated before reserving one of the four resolver slots.
The main thread defers its owned deadline exception only while acquiring a slot
and handing it to a worker. Expiry is still recorded immediately and rejected
after that handoff; a running lookup retains its slot until it finishes, even if
its caller has timed out. Workers only resolve names and never open destination
connections. This preserves capacity ownership without promising to preempt OS
thread startup or a libc resolver that does not return.

Responses include `header_values` with every value as a separate array entry;
use this representation when repeatable fields matter. The compatibility
`headers` object keeps `Set-Cookie` as an array; other repeated fields are joined
by Go and retain their last value in Python. Retrieved text remains untrusted content. It is not
automatically scanned for semantic prompt injection or declared safe to execute.

Before MCP delivers a complete response labelled `application/json` or a subtype
ending in `+json`, both implementations apply the same bounded JSON contract as
outgoing requests. This covers any top-level media type using the
[structured JSON suffix](https://www.rfc-editor.org/rfc/rfc6839.html#section-3.1),
including `model/gltf+json`. Malformed syntax, duplicate decoded keys, unpaired
surrogates, noncharacters, nonfinite numbers and integral values outside the local
safe-integer range are rejected. The 64-container and 100,000-token limits also
apply. Accepted JSON is returned byte-for-byte, without decoding and rewriting it;
rejected body bytes still consume the process response budget.

HEAD, 204, 205 and 304 provide no content to validate. A 206 single range receives
the same JSON checks when Content-Range establishes coverage from byte zero to
the known complete length. For multipart ranges, any part declaring JSON selects
the JSON contract for the representation. The broker checks it when the parts
within that response cover every byte of a known complete length. This also
covers reordered, duplicate and consistent overlapping parts, and a total stated
by only one part. The representation is assembled only for this check after
proving full coverage within the 10 MiB body budget; untrusted offsets cannot
determine an unbounded allocation. The original MIME body is returned unchanged.
Incomplete or unknown-length ranges remain fragments; these checks do not
establish their whole-document validity or combine separate responses.
Missing or other media types are not sniffed as JSON; JSON sequences, newline
delimited formats and application-specific schemas need separate consumers.
Ordinary and complete single-range JSON validation happens at the MCP return
boundary, after the bounded read. Direct users of Go's HTTP client must call
`CheckResponseBody` for the same content policy; its multipart range guard also
checks complete JSON at EOF. Valid JSON remains untrusted application data.

Complete responses labelled `application/xml`, `text/xml`, or a subtype ending
in `+xml` receive XML admission checks at the same boundary. This includes SVG
and XHTML media types without treating their content as safe to render. The
recognizer checks one properly nested root, XML characters and Fifth Edition
Unicode names, quoted attributes, comments, CDATA, processing instructions and
the placement/syntax of a UTF-8 XML 1.0 declaration. A leading UTF-8 BOM is allowed.
Namespace bindings are scoped and restored; undeclared/reserved prefixes,
duplicate attributes and collisions after namespace expansion are rejected.
Attribute references and line endings are normalized only for internal namespace
comparison. The original document bytes are preserved.

This profile rejects every DTD and entity declaration, including otherwise valid
documents that use them. Only the five predefined entities and valid numeric
character references are admitted. It never loads external entities, schemas,
stylesheets or XInclude resources. It allows up to 64 nested elements, 128
attributes per start tag, 1,024 UTF-8 bytes per name, 65,536 bytes per tag/comment/PI,
32 bytes per reference and 100,000 markup/reference units, within the existing
10 MiB body limit. Large text and CDATA are governed by that body limit. These
are explicit resource restrictions, not XML specification limits. Namespace URI
values reject ASCII whitespace/control characters; general URI-reference syntax
is not certified.

XML uses the same complete-range coverage proof as JSON. Any multipart part
declaring XML selects the XML contract; if parts also declare JSON, both
contracts must pass. Incomplete/unknown-length fragments and other media types
are not sniffed or assembled across responses. Direct Go HTTP-client consumers
must call `CheckResponseBody` for ordinary/single-range content validation; the
multipart guard validates complete content at EOF. Admission does not validate
application schemas, signatures, stylesheet behavior, active content or intent.

Byte ranges follow [RFC 9110 section 14](https://www.rfc-editor.org/rfc/rfc9110.html#section-14)
syntax, with deliberately narrower local admission policy. Intervals must be
ascending and disjoint; an open interval must be last; a suffix must stand alone.
Units are case insensitive and leading zeroes remain decimal. A bounded number
of empty list members is accepted, but counts toward the 16-slot ceiling. Values
larger than 2^63-1 are rejected before integer overflow or downstream dispatch.
The numeric ceiling, GET-only use, unknown-unit rejection and stricter overlap,
ordering and suffix restrictions are broker choices, not universal RFC bans.
No resource length or range satisfiability is inferred. A server can still ignore
Range and return a full response, which remains subject to normal body limits.
This addresses the request-amplification class discussed in
[RFC 9110 section 17.15](https://www.rfc-editor.org/rfc/rfc9110.html#section-17.15);
it does not prove protection against all server resource-exhaustion behavior.

Content-Range follows [RFC 9110 section 14.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.4)
with the same local bytes-only and numeric limits. Partial uploads require PUT,
one fulfilled range and an exact content byte count. Application support and
authorization for partial PUT are not inferred. Responses accept Content-Range
only on 206 (fulfilled) or 416 (unsatisfied; an omitted field remains permitted).
The production broker requires an original GET Range request for a 206 response.
Single-part responses must carry a range matching their content byte length,
including when the HTTP body is chunked or ends on connection close.

Returned intervals also have to match the request's bounds: each endpoint must
fall within a requested interval after applying any known representation length.
This local contract permits smaller subsets and coalescing across requested
intervals; it rejects unrelated ranges and endpoints that land in unrequested
gaps. Open ranges and suffixes are resolved against a known total. For an unknown
total, a suffix response can only be checked against the requested maximum size;
its absolute origin is not inferred. A zero-length suffix cannot produce a 206.
No fixed gap limit is imposed for coalescing because the hypothetical multipart
overhead is unavailable. These checks do not authenticate the resource bytes.

Multipart 206 responses require a valid boundary and a multiple-range request,
have no outer Content-Range, and must include a fulfilled range in every part.
Known total lengths must agree and cover every returned interval. Parts may be
reordered or coalesced, as described by
[RFC 9110 section 15.3.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.7).
A known total from any part also constrains parts that declare an unknown total;
request-bound checks run for every part before MCP delivers the complete body.
Overlapping intervals within one response must also contain identical bytes at
every shared position. This broker integrity check follows the selected
representation semantics above; consistent overlaps and duplicates remain
accepted. Comparison uses body-relative byte slices, including for UTF-8 and
very large resource offsets, without reconstructing a whole representation.
The 16-part ceiling bounds comparisons to 120 pairs within the existing 10 MiB
body limit. Views reference the bounded body instead of copying overlapping data.
Boundary parsing follows [RFC 2046 section 5.1.1](https://www.rfc-editor.org/rfc/rfc2046.html#section-5.1.1),
including quoted boundaries, transport padding, preambles and epilogues.
Premature boundary prefixes, folded headers, missing closing delimiters,
inconsistent octet counts and oversized part metadata are rejected. Additional
local restrictions allow only absent/binary Content-Transfer-Encoding and
absent/identity Content-Encoding in parts, and reject part-level HTTP framing.
Some otherwise valid MIME representations are therefore intentionally denied.
Go retains a bounded copy of multipart content for validation at EOF; ordinary
responses retain their streaming behavior. Both MCP implementations consume and
validate the complete response before returning it. A direct Go transport caller
must read to EOF and honor errors; partial reads are not a validated response.
Valid wire content is preserved and parts are not cached or replaced by the
temporary complete-JSON representation used for validation.

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
The [Content-Digest validation record](http-content-digest-validation.json)
covers 130 shared response fixtures: 53 accepted and 77 denied, through raw
Go transport and Python MCP delivery, plus 126 Go MCP cases using a custom test
transport. They exercise syntax, supported algorithms, repeated fields, opaque
parameters, exact octets, bodyless/interim responses, all three body framing
modes, fragments, multipart content and the RFC dictionary/parameter capacities.
Seven additional selected controls cover maximum-body streaming/read sizes,
final-byte changes, oversize input, empty internal field lists and repeated-field
preservation. The original 127-case baseline delivered all 77 rejection fixtures
in both raw runtime paths. After the capacity review, 123 final cases are
identical to that baseline, including 75 rejection cases; four capacity fixtures
were revised and three additional standards controls have no baseline run.
All final cases and the full Go security race suite pass, as do Go vet/build and
all 140 Python security test methods at that validation snapshot. That response-only run did not verify request digest fields,
representation digests, message signatures, a live deployment or universal
attack prevention. No new Snort SID is involved.

The subsequent [request Content-Digest validation record](http-request-digest-validation.json)
covers 65 shared fixtures (30 accepted, 35 denied) through Go/Python MCP
dispatch and diagnostics, and the direct Go transport. Before repair, each
path admitted 34 of the 35 denied fixtures; the duplicate header-name control
was already denied. All 65 now pass. Twenty direct-stream cases verify byte
identity, lengths, maximum/overflow reads, repeated fields, read errors,
body closure and independence from caller replay bodies. Two cancellation cases
verify rejection before reading and interruption during reading. One shared
signature control confirms that a correct digest cannot authorize forbidden
content. Overlapping Python capacity checks and repeated runtime passes are
not added to the combined count. The full Go race suite, Go vet/build and all
142 Python security methods pass. The existing response digest corpus also
passes after the parser was moved into the shared Go HTTP guard. These changes
add 88 selected cases to the recorded lower bound and no Snort SID.

The [representation-digest validation record](http-representation-digest-validation.json)
adds 33 shared request fixtures (14 admitted, 19 denied), 63 response fixtures
(31 admitted, 32 denied) and four selected capacity/metadata controls.
Before repair, both MCP request paths and direct Go egress admitted 17 denied
request fixtures. The raw Go and Python response paths admitted 30 denied
response fixtures; the custom Go MCP transport admitted all 30 denied fixtures
in its 60-case subset. Denials include local-policy cases where representation
data is unavailable, not only malformed messages. All final cases pass.
The Go race suite passes, with the Snort package cached and the other tested
packages fresh; vet/build and all 145 Python security methods also pass.
Baseline comparisons, duplicate runtime executions, diagnostic calls and
overlapping capacity controls are excluded from the additional 100 counted
cases. The existing 114-case response metadata corpus changes only its
protected-field inventory. No Snort SID is added and no deployment is verified.

The [digest preference validation record](http-digest-preferences-validation.json)
adds 108 request fixtures (40 admitted, 68 denied), 132 response fixtures
(52 admitted, 80 denied), and six selected metadata controls. The original
224-case baseline remains byte-for-byte identical in the final corpus; sixteen
bodyless-response cases were added after repair. Before repair, each request
path admitted 60 denied fixtures, while raw Go and Python response paths
admitted 68. The Go MCP custom transport admitted 64 denied cases in its
110-case baseline response subset. All final cases pass, including empty
dictionaries, numeric type boundaries, dictionary/parameter capacities,
repeated fields, interim/bodyless responses and independence from actual digest
validation. The metadata controls check empty internal field lists, MIME
separation and preservation of repeated output fields for both preferences.
The final Go race suite and all 148 Python security methods pass; vet/build
also pass. Shared runtime repetitions, baseline comparisons and overlapping
metadata checks are excluded from the additional 246 counted cases.
These are admission controls, with no new Snort SID or deployment verification.

The [HTTPWG Structured Fields audit](http-structured-fields-validation.json)
checks 1,547 selected source cases from the pinned public HTTP Working Group
corpus. Original dictionaries exercise both preference fields; single-line,
comma-free Items and single-item Lists are embedded as opaque parameters in
all four digest fields. The adapter removes outer SP, preserves the remaining
input, and classifies edition, field-type, duplicate-key and resource-policy
denials independently of the production parsers. It excludes 46 cases whose
structure cannot be preserved by that embedding. The source corpus follows
RFC 9651; these RFC 9530 fields still use RFC 8941, so Date and Display String
types are deliberately denied. The audit compares admission verdicts only,
without asserting generic value decoding, serialization or full conformance.

Go and Python agree on all selected cases: 650 admitted and 897 denied, with
zero unexpected verdicts. Four source cases permit either result and are
checked for implementation agreement; the other 1,543 have required profile
verdicts. The 1,547 source cases contain 1,536 distinct original field-value
arrays. Their 5,324 field executions per runtime, preliminary classification
pass and regression reruns are counted only once per selected source case in
the combined inventory. Existing Go digest regressions pass under the race
detector, and all eleven selected Python digest methods pass. No production
parser change or new Snort SID was needed. The helper performs no network
access, does not extract or execute upstream files, and preserves the upstream
license alongside generated audit inputs:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 pkg/security/egress/testdata/audit_httpwg_structured.py \
  --archive /path/to/pinned-httpwg-structured-fields.tar.gz --go /path/to/go \
  --output-dir /path/to/httpwg-structured-audit
```

The [URI-reference validation record](http-uri-reference-validation.json)
covers 133 request fixtures (54 admitted, 79 denied), 271 response fixtures
(117 admitted, 154 denied), and six selected internal-field/MIME controls.
Before repair, Go and Python each admitted 77 denied request fixtures and
146 denied raw or parsed response fixtures. The custom Go MCP response path
admitted all 152 denied fixtures in its 269-case subset; Connection nomination
uses the production header-stage path. The final corpus is unchanged from the
baseline. Original URI spelling and the actual request destination are checked
on accepted paths. Two Go empty internal response fields also failed before
repair; two direct request empty/repeated-value controls were added afterward.
All final cases pass, as do the Go security race suite, vet/build, and all 153
Python security methods. DNS and Snort package results in that Go run were
cached; egress, HTTP guard and MCP ran fresh. The 404 shared fixtures and six
controls are counted once across runtimes and paths; reruns and assertions are
not added. This adds protocol admission checks, with no new Snort SID or verified
deployment.

The [XML response validation record](xml-response-validation.json) covers 207
document fixtures through ordinary, complete single-range and multipart delivery,
plus 112 media/framing/range cases and five maximum-size/early-budget checks.
Before XML admission, both implementations delivered all 146 document rejection
fixtures; the 61 accepted controls remain accepted. The 25,000-input reproducible
ASCII mutation audit agrees across Go/Python, and every accepted mutation also
passes the independent Expat namespace parser. This does not make Expat an oracle
for Fifth Edition Unicode names: those are tested from the W3C ranges directly.
The current Go security race suite, vet/build and all 137 Python security test
methods pass. Inputs and repeated checks are counted conservatively in the
combined inventory; this does not establish deployment or universal coverage.
The [official W3C XML collection audit](w3c-xml-validation.json) checks 2,001
applicable catalog inputs from the pinned 20130923 release against both
recognizers, with identical results: 72 admitted and 1,929 denied. All 1,017
`not-wf` cases are denied. Of the catalog's well-formed cases, 886 are deliberately
denied by the local profile: 875 declare DTDs, nine use other encodings and two
require namespace processing disabled. Catalog `invalid` means DTD-invalid,
not malformed XML; 71 such documents fit the nonvalidating admission profile.
The remaining 27 catalog `error` cases permit either outcome and are checked
for Go/Python agreement. Another 584 cases target earlier editions or XML /
Namespaces 1.1 and are excluded. The 2,001 executions contain 1,983 distinct
payloads and are counted once across runtimes. This is a profile audit, not
full XML conformance or document interpretation; no production parser change
was needed. As the [W3C FAQ](https://www.w3.org/XML/Test/faq.html) explains, even
passing a complete test collection would not prove full specification coverage.
The reproducible helper reads the official archive without extraction, network
access or external-entity resolution:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 pkg/security/egress/testdata/audit_w3c_xml.py \
  --archive /path/to/xmlts20130923.zip --go /path/to/go \
  --output-dir /path/to/w3c-xml-audit
```

The archive URL and required SHA-256 are recorded in the audit. Test documents
are unchanged; the helper verifies only admission and implementation agreement,
not canonical output, DTD validity or external-resource behavior.
The [TLS identity validation record](tls-service-identity-validation.json) adds
66 shared real TLS exchanges: 33 certificate cases under TLS 1.2 and TLS 1.3,
with 18 accepted controls and 48 denials. Go already passed; Python previously
accepted ten cases through Common Name fallback. All now pass, including checks
that rejected identities receive no HTTP request or Authorization header. Three
additional Python checks reject unavailable or obsolete native verification
support before creating an opener. The tests use published fixture keys, an
isolated fixture CA, simulated resolution and local socket pairs; they install
no machine trust and contact no external destination. Current Go egress race
checks and all 134 Python security test methods pass. This is not a complete
PKIX, revocation, TLS or certificate-issuance audit.
`pkg/security/egress/testdata/response_metadata_cases.json` adds 114 shared response
metadata cases, with additional raw final/interim-header regressions. Its
singleton declaration now includes Content-Disposition; the original 114 cases
are unchanged. The [Content-Disposition validation record](http-content-disposition-validation.json)
adds 190 shared fixtures, with 70 accepted controls and 120 rejections. Both
runtimes previously admitted 119 of the rejected cases; one oversized field was
already rejected. All cases now pass through parsed and raw final/interim header
checks, including Python MCP delivery. Two additional MIME-context controls
remain accepted. Go race tests and 132 Python security test methods pass; current
Go/Python Unicode control/format classifications also agree for this policy.
These are local parser and delivery tests with simulated peers. The
57 shared cases in `pkg/security/httpguard/testdata/range_cases.json` verify Range
admission through both actual dispatch and diagnostics in Go and Python. Before
the range policy, 37 of its rejected cases reached each runtime's test transport;
all 57 now pass, including 15 admitted controls. Direct Go transport tests add
12 denials before DNS/dialing and six cases preserving the inspected Range bytes.
See the [range validation record](http-range-validation.json) for source hashes,
baseline cases and completed checks. A further 129 shared Content-Range fixtures
cover 38 upload and 91 response cases in both implementations, including 38
accepted controls. The original 111-case baseline reproduced 79 unexpected
acceptances in each runtime. All current cases pass, as do eight direct Go
transport denials before DNS, two unchanged-upload controls and six multipart
header-budget checks in each runtime. The
[Content-Range validation record](http-content-range-validation.json) records
the source hashes, local restrictions and completed checks. A further 308 shared
conditional/validator fixtures cover 220 requests and 88 responses, including
78 accepted controls. Before the fix, 164 invalid requests reached each runtime's
test transport and 63 invalid responses were accepted. All now pass. Additional
checks cover 16 fixed-clock date boundaries in each runtime, 26 direct Go
transport denials before DNS/dialing and three controls preserving the inspected
fields. See the [conditional validation record](http-conditional-validation.json)
for source hashes and the limits on these claims. A further 194 shared response
correlation cases pass in Go and Python: 89 rejection cases that were accepted
before the change and 105 compatibility controls. The
[response correlation validation record](http-response-correlation-validation.json)
records the baseline, source hashes and scope. The combined historical execution
count is maintained in [the test inventory](security-test-inventory.json);
shared fixtures and repeated runs are not added once per implementation. A further
123 shared JSON-response cases pass through both MCP implementations: 57 accepted
controls and 66 denials. Before content validation, 63 of the denied cases were
delivered by each runtime; three malformed UTF-8 cases were already rejected.
Cases also verify preservation of accepted bytes and charging of consumed bodies
on rejection. The [JSON-response validation record](http-response-json-validation.json)
records the evidence and exclusions. The
88 shared range-correlation cases also pass in both implementations: 50 accepted
controls and 38 denials that both runtimes previously accepted. They cover closed,
open and suffix intervals, subsets, coalescing, unknown lengths, numeric limits,
multipart ordering and all supported body framing. Four existing positive
Content-Range fixtures now request the bytes that their responses contain,
preserving their Unicode and part-count test purposes. These are corrections to
existing cases, not four additional tests. The
[range-correlation validation record](http-range-correlation-validation.json)
records the baseline and corrections; the older Content-Range record retains its
historical hashes. A further 129 shared multipart-content cases pass in both
implementations, including 69 consistent controls and 60 conflicting responses
that both runtimes previously accepted. They compare duplicate, nested, partial,
reordered and nonadjacent overlaps under length, chunked and close framing.
Additional checks exercise 16 overlapping parts in a 10,482,411-byte body and a
conflict in its final content byte. The
[multipart consistency validation record](http-multipart-consistency-validation.json)
records the evidence, generator and bounded comparison policy.
The [complete-range JSON validation record](http-complete-range-json-validation.json)
adds 156 shared cases: 75 accepted controls and 81 malformed complete documents
that both runtimes previously accepted under status 206. It covers single and
multipart responses, all three supported body framing modes, gaps, unknown
totals, large offsets, mixed part declarations and structured JSON suffixes.
All 54 single-range cases also pass through the Go MCP return boundary; Python
exercises all cases through MCP. Additional checks validate a near-10 MiB complete
multipart document and reject a malformed final JSON byte without changing MIME
framing. Existing smaller fragments remain accepted and consumed bytes remain
accounted for on rejection. No signature or SID was added for these controls.
The [Python deadline validation record](python-deadline-validation.json) adds
20 cases across seven test methods, with 14 baseline failures. One case delivers
a real local alarm during IP-literal parsing and verifies that resolution stops;
another simulates expiry through MCP dispatch and verifies that no successful
tool result is delivered. The remaining cases cover ordinary error handlers,
suppressed expiry, absolute clock boundaries and error identity. Simulated clocks
and handler calls test control flow; they do not establish remote attack timing
or hard real-time cancellation. That validation passed 120 Python security test
methods. The [DNS worker lifecycle record](python-dns-worker-lifecycle-validation.json)
adds 20 cases across nine methods, including two real local alarms and controlled
interruptions during setup, slot acquisition, startup and completion waiting.
Nine cases failed before repair; repeated setup cancellation consumed all four
slots and caused later requests to fail with capacity exhaustion. The repaired
tests verify capacity recovery and retained ownership during an unfinished lookup,
including resolver failure and startup failure. All 129 Python security test
methods pass, including the previous deadline cases. These are local lifecycle
tests with fake DNS resolution, not live remote denial-of-service measurements.
The 2,618 signature fixtures cover the imported and local rules, and the import
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
The subsequent [fragment final-length repair](../native-snort3/patches/fragment-extent.md)
passes 840 paired cases and all 17 preceding suites. It corrects forwarding
in 612 cases involving inconsistent length declarations, preserves 168 valid
controls and adds an exact coverage check before reconstruction. Rejecting
contradictory contexts is strict local policy grounded in the RFC fragment
field definitions, not a claim about every endpoint's behavior.
The subsequent [fragment identity repair](../native-snort3/patches/fragment-identity.md)
passes 694 paired cases. It closes 60 reproduced bypasses of a temporary content
blocking rule, restores checksum rejection in 80 cases and restores valid
forwarding in 28 isolation cases. Ordinary wire fragment identities are kept
separate from the ICMP session normalization that previously changed their
addresses or ID bits. This does not establish logical Mobile IPv6 grouping.
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
