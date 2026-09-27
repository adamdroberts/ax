# Sandboxed DNS without an agent-controlled upstream channel

`ax-dns-proxy` exposes a small DNS namespace over UDP and TCP. Its default is to
deny every name and every client. Only the operator's exact hostnames can resolve;
wildcards and arbitrary subdomains are unsupported. Run the proxy outside the
agent sandbox, with its executable and configuration controlled by the operator.

Client queries **never trigger upstream lookups**. A separate refresh loop asks
for A and AAAA records for each configured hostname, using new random transaction
IDs and a fixed request shape. Agents receive reconstructed cache answers. The
refresh list, timing, query types and upstream address do not come from requests.
Case, transaction IDs, EDNS data and opaque payloads are never relayed. Failed
refreshes replace old answers with failure; expired entries return SERVFAIL
without an on-demand lookup or fallback resolver.

This prevents encrypted data embedded in unapproved DNS names or additional
fields from being carried upstream. Encryption does not make a name admissible:
the full canonical name must equal an approved name. Rejection does not depend
on a length or entropy threshold.

The listener accepts plain DNS only. DoT/TLS, DoQ/QUIC, DNSCrypt and DoH/HTTP
bytes sent to its DNS socket do not open encrypted tunnels. There is no TLS, HTTP,
CONNECT or arbitrary-packet forwarding listener. This does **not** decrypt or
classify a tunnel sent over another permitted HTTPS connection. All sandbox
traffic must be forced through the DNS proxy and the inspected HTTP broker.

## Start the proxy

```sh
go build -o bin/ax-dns-proxy ./cmd/ax-dns-proxy

# Replace these illustrative networks and approved application names.
# A trusted service/NAT can expose the unprivileged listener on port 53.
bin/ax-dns-proxy \
  --listen 10.40.0.53:5353 \
  --client-net 10.20.0.0/24 \
  --client-net fd00:20::/64 \
  --upstream 10.50.0.53:53 \
  --allow-name api.company.example \
  --allow-name storage.company.example \
  --refresh 1m
```

Use a trusted, validating recursive resolver at `--upstream`. Only this numeric
IP and port are contacted, including TCP fallback; the OS resolver, search
suffixes and environment proxies are not used. The upstream connection is plain
DNS on the trusted network, not authenticated TLS. No external public resolver
is supplied by default.

Every returned address must be publicly routable under AX's existing HTTP egress
policy. Mixed public/private answers fail as a set. `--answer-net` optionally
replaces that default with explicit permitted CIDRs, for example an exact private
broker `/32` or `/128`. Every address must match a configured range. Loopback,
multicast, mapped IPv6 and non-unicast addresses remain excluded. Do not authorize
attacker-owned names or names controlled by the agent.

The refresh interval is 10 seconds to 5 minutes, default 1 minute. Cached answers
expire no later than the minimum upstream address/CNAME TTL and twice that
interval; lookup time is subtracted conservatively. Short-TTL names can therefore
be unavailable between scheduled refreshes. A cache miss deliberately does not
create a new agent-controlled network event. Upstream aliases, TXT records,
additional data and response flags are discarded. Only address records and a
locally constructed empty OPT response are emitted. The proxy does not assert
DNSSEC validation or the AD bit.
Received TTLs with the high bit set are treated as zero, following
[RFC 2181 section 8](https://www.rfc-editor.org/rfc/rfc2181.html#section-8).

## Sandbox routing contract

Apply these restrictions **before starting the agent**, for IPv4 and IPv6:

| Source | Permitted destination | Protocol |
| --- | --- | --- |
| Sandbox | Exact DNS proxy endpoint | UDP and TCP, DNS port only |
| Sandbox | Exact HTTP broker endpoint | TCP, broker port only |
| DNS proxy | Exact trusted resolver endpoint | UDP and TCP, resolver port only |
| Sandbox | Everything else | Deny |

Configure the sandbox resolver with only the DNS proxy IP. Use absolute names,
an empty search list and `ndots:1`. A DNS answer does not grant direct socket
access to the resulting address. Keep the HTTP broker's exact-origin allowlist
and strict inspection enabled. Its allowed origins need corresponding approved
DNS names if it uses this resolver. The sandbox must not be able to change network
policy, use a host network, contact another forwarding service on the broker or
modify proxy configuration.

[The Kubernetes example](../examples/dns-proxy/kubernetes.yaml) includes a DNS
Deployment, Service and policies for ordinary sandbox pods. It is a template
with illustrative addresses, not an applied deployment. Set the sandbox resolver
to the allocated Service IP after creating the Service. NetworkPolicy permissions
are additive: another broader policy defeats these restrictions. Verify service
translation and IPv6 enforcement with the actual CNI. See the
[Kubernetes NetworkPolicy documentation](https://kubernetes.io/docs/concepts/services-networking/network-policies/).

AX's Substrate-backed actors are not ordinary sandbox pods. Its pinned egress
API cannot express destination ports. A host-only allowlist for the DNS proxy IP
needs a separate port-aware sandbox/host policy and trusted resolver configuration;
the Kubernetes example does not implement that backend change. Existing native
Snort `perimeter` rules intentionally deny all non-TCP agent traffic, including
DNS. Keep those rules on a broker-only sensor, or replace that boundary with a
reviewed DNS-aware policy; layering them on this route blocks UDP queries. The
protocol-only native profile remains usable. See [network admission](networking.md).

Restricting only DNS ports while retaining unrestricted Internet HTTPS is
insufficient. DoH can use a custom URL path over ordinary HTTPS, as specified in
[RFC 8484](https://www.rfc-editor.org/rfc/rfc8484.html#section-4.1). The deny-all
destination policy also closes alternate ports, multicast name resolution, DoT,
DoQ, DNSCrypt and other direct transports. Abuse of an approved HTTP application
still requires endpoint/tool authorization.

## DNS contract and limits

The proxy implements DNS header/label/TCP framing from
[RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html), TCP reuse from
[RFC 7766](https://www.rfc-editor.org/rfc/rfc7766.html) and limited EDNS(0) from
[RFC 6891](https://www.rfc-editor.org/rfc/rfc6891.html). The following are strict
**local policy restrictions**, not claims that all rejected DNS features violate
these standards:

- One uncompressed IN A or AAAA hostname question, at most 512 bytes. Compressed
  or binary labels, extra questions, trailing data, answer/authority sections,
  updates, transfers, TXT, NULL, ANY, HTTPS/SVCB and other types are rejected.
- Optional single empty, root-owned EDNS(0) OPT. DO is accepted but not forwarded;
  options including padding, cookies and client subnet are rejected. Unsupported
  versions, extended RCODEs and reserved flags are rejected. RD and AD request
  bits cannot influence upstream traffic; CD and other header flags are denied.
- At most 256 configured names, client networks and answer networks; 32 addresses
  per name, eight concurrent refresh lookups, a three-second default timeout and
  an eight-link CNAME chain. A bad response, wrong transaction/question, alias
  conflict/cycle or invalid address set fails closed. CNAME targets are used only
  within the received answer, never queried on behalf of an agent.
- Shared 128-worker limit and 50 queries/second with a burst of 100; no unbounded
  per-client/name allocation. TCP supports 32 queries per connection, three-second
  read/write deadlines and a 30-second lifetime. Shutdown closes listeners and
  active connections. UDP replies respect 512 bytes or a capped EDNS size of
  1,232; oversized answers truncate cleanly for TCP retry.
- Logs contain aggregate counters, not requested names, payloads or packet bytes.

This is a restricted address broker, not a full recursive resolver or universal
RFC implementation. Approved names, the trusted resolver, host isolation, timing
side channels, compromised trusted endpoints and resource exhaustion remain part
of the threat model.

## HTTP signatures and counts

Eight new default blocking rules, SIDs `1101101–1101108`, cover DNS wire query
parameters on arbitrary HTTP routes, DNS Accept types, JSON/oblivious DNS content
types, forms/JSON, JSON resolve APIs, alternate routes and recognizable DNS wire
bodies. Six strict rules, `1200201–1200206`, cover tunneling tools, direct DNS
commands, DNS library calls, encrypted-resolver stamps and DNS destination ports.
These signatures also match some legitimate DNS administration; they do not
replace authorization or recognize every custom tunnel.

Existing `9102038` retains the DNS-message content-type block. Existing `9104053`
retains `/dns-query` telemetry and strict blocking promotion. The narrower,
redundant `1200133` was retired in favor of that rule; import accounting and
fixtures record the alias. No imported source rules were lost.

There are now **894 default HTTP signatures** (156 blocking, 738 advisory), or
**922 with strict mode** (746 blocking, 176 advisory). Native Snort remains 278
with both overlays: 188 blocking and 90 advisory. That is **1,200 rule definitions
across both layers**. DNS validation, cache policy and network policy are additional
controls, not additional Snort signatures. These are source configuration counts,
not a verified running deployment.

## Verification

`pkg/security/dnsproxy` tests use fake resolvers and local IPv4/IPv6 sockets. They
exercise malformed framing, encrypted input, EDNS payloads, exact names, blocked
types, expiry, refresh failures, address sets, TTLs, TCP splitting/reuse, UDP
truncation and source restrictions. An upstream fixture verifies canonical queries,
TCP fallback to the same pinned resolver, response matching and opaque-record
removal. Race tests cover concurrent refresh and requests; fuzzing checks that
client wire data cannot schedule resolver calls. No public DNS service is used.

The shared HTTP corpus has 2,618 fixtures, each evaluated independently in Go and
Python, including encoded parameter names and JSON escapes. Import checks reject
duplicate SIDs and detection predicates. Local results do not establish that a
production sandbox routes every packet through these controls.

The [local validation record](dns-proxy-validation.json) records passing Go race
checks, 97 Python tests, 24 DNS-before-dispatch cases in each runtime, 953,177
client fuzz executions and 58,484 upstream-envelope fuzz executions. It includes
source and binary hashes. The Kubernetes template was parsed, not applied or
tested against a cluster.
