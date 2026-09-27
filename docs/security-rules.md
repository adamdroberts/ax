# Agent HTTP intrusion prevention rules

AX's MCP proxy inspects outbound `http_request` tool calls before sending them.
The built-in catalog contains 886 default signatures (148 blocking, 738 advisory),
shared by the Go and Python implementations. Strict mode promotes 562 advisory
signatures and adds 23 rules, for 909 unique signatures (733 blocking, 176 advisory). It detects
known payload patterns and policy violations; it cannot establish that an action
is authorized, understand every instruction, or guarantee prevention of all
hostile agent behavior.

The proxy also enforces [strict protocol and egress controls](protocol-security.md).
Both profiles deny network access until an administrator configures allowed origins.

## Run a profile

```sh
# Built-in exploit, exfiltration, sabotage, and advisory behavior signatures.
ax-mcp-proxy --profile default --allow-origin https://api.company.example

# Add restrictive policy rules for agents with tightly constrained jobs.
ax-mcp-proxy --profile strict --allow-origin https://api.company.example

# Append reviewed organization-specific rules.
ax-mcp-proxy --profile strict --allow-origin https://api.company.example --rules /etc/ax/organization.rules

# Explicit replacement; a nonempty, valid custom catalog is required.
ax-mcp-proxy --only-custom-rules --allow-origin https://api.company.example --rules /etc/ax/organization.rules
```

A Workspace can set `args: ["--profile", "strict", "--allow-origin", "https://api.company.example"]` on its
`ax-security-proxy` MCP server. The automatically registered server uses the
`default` profile and denies egress until allowed origins are configured. This change does not deploy or change running workspaces.

The Go binary embeds both catalogs at build time. The Python development proxy
reads `pkg/security/snort/rules/{default,strict}.rules` relative to its source
location. Distributing Python requires preserving those files and the directory
layout, or explicitly supplying a replacement with `--only-custom-rules`.
Missing or invalid catalogs cause startup failure. Strict mode also requires the
action-promotion file; duplicate IDs, unknown IDs, nonblocking actions and attempts
to change an already-blocking rule fail atomically.

## Catalog and actions

- [Default catalog](../pkg/security/snort/rules/default.rules): broad request
  inspection; ambiguous prompt-manipulation and administrative behavior produce
  alerts. Concrete exploit and abuse signatures block.
- [Strict catalog](../pkg/security/snort/rules/strict.rules): additional blocking
  policy for operations that may be legitimate in normal development. Review it
  against the agent's actual permissions before enabling it.
- [Agent Guard import](../pkg/security/snort/imports/agent-guard-snort3/README.md):
  accounting for all 825 source signatures, coverage aliases, compatibility
  adaptations and 70 separate native-only Snort rules.
- [Organization examples](../examples/snort-rules.rules): custom rules in the
  `2000000` SID range. These are examples, not a destination allowlist.
- [Regression corpus](../pkg/security/snort/testdata/rule_cases.json): 2,580 fixtures, including positive
  and benign near-miss cases for every signature, shared by both implementations.

`drop`, `reject`, and `block` all prevent dispatch. `alert` logs its SID and action but
allows dispatch. There is no rule-level allow override: matching blocking rules
win over all alerts. Evaluation returns the first blocking rule in catalog order,
or the first alert when no blocking rule matches. It does not return every match.
`check_security_payload` exercises the same validation and inspection without
network transmission; its result distinguishes a signature match from a request
rejected for invalid input or exceeding limits.

Strict action changes are stored in
[`strict-actions.json`](../pkg/security/snort/rules/strict-actions.json), so an
advisory that becomes blocking reuses the same SID and predicate. There are no
duplicate detection fingerprints across the enabled default and strict packs. Test fixtures isolate each SID so an earlier,
broader signature cannot conceal a broken later rule. Integration tests separately
cover complete-profile behavior and ordinary API, model, build, and query traffic.
These examples are regression coverage, not evidence of a real-world detection
rate or a false-positive rate.

## Coverage

The catalog covers command injection and reverse-shell indicators; dangerous
shell/interpreter execution; persistence, security-control tampering and destructive
commands; exposed credentials and key material; metadata and internal-service
probes; traversal and sensitive-file access; SQL, NoSQL, LDAP and XPath injection;
XML external entities; template, expression and framework exploitation;
deserialization; browser/script injection; HTTP abuse; reconnaissance; cloud,
container and orchestration abuse; mining; and agent instruction/tool manipulation.
Exact enabled signatures, actions, scope and revision numbers live in the catalogs.

Security work, infrastructure administration, or sending code samples to model APIs
can legitimately contain blocked syntax. Authentication credentials in ordinary
Authorization/API-key headers are not generically treated as exfiltration. The
imported GitHub-token Authorization signature is advisory in both profiles;
credential shapes in bodies, URLs, cookies or Referer headers have separate policy. Credential
body/URL signatures can still block legitimate credential-management operations.
Tune trusted server-owned policy to the job; never let the agent rewrite rules,
disable inspection, select its profile, or approve its own exceptions.

## Supported rule language

This is **AX's Snort-style HTTP subset**, not the Snort engine, a packet IDS, or an
importer for arbitrary Snort/Suricata rule feeds. It has no stream reassembly,
flowbits, network-header matching, protocol inspectors or Snort 3 sticky buffers.

```text
drop tcp any any -> any any (msg:"Example rule"; content:"dangerous-pattern"; nocase; http_client_body; classtype:"policy-violation"; sid:2000100; rev:1;)
```

| Element | AX behavior |
| --- | --- |
| Header | `tcp` or `http`, with `any any -> any any`; addresses, ports, variables and other directions are rejected |
| Actions | `alert`, `drop`, `reject`, `block`; `pass` is rejected |
| Metadata | `msg`, positive 32-bit `sid`, optional positive 32-bit `rev` (default 1), `classtype` |
| Literal match | `content:"text"`, optional `!` negation, hex bytes such as `|0d 0a|`, escaped quotes, backslashes, semicolons, colons and pipes |
| Literal modifiers | `nocase` (ASCII bytes), nonnegative `offset`, positive `depth`; offsets/depth are byte-based and apply independently in each view |
| Regex match | `pcre:"/pattern/ism"`, optional `!` negation; use the shared Go RE2/Python-compatible subset, without backreferences or lookarounds |
| Match targets | `http_uri`, `http_header`, `http_client_body`, `http_method`, `http_raw_uri`, `http_raw_body`, placed **after the matcher** they modify |
| Header fields | `http_header:field host` (or another valid header name) examines only that field's normalized values; absent fields cannot satisfy any matcher, including negation |
| Raw targets | `http_raw_uri` examines the request-target path/query, `http_raw_body` examines the original body; neither adds decoding alternatives |
| Default target | Raw combined request and individual URI, header and body inspection views |
| Boolean behavior | All matchers in a rule must match; positive matchers can match any view; negated matchers must be absent from every view |

One rule per line; comments begin with `#`; every option ends with a semicolon.
Unknown options, unsupported headers/actions/regex flags, empty matchers, malformed
quoting, missing SIDs and duplicate SIDs fail loading. Loading is atomic and never
partially installs a broken file. Adding rules only takes effect when the process
loads them; editing a catalog does not hot-reload running proxies.

The Go runtime uses RE2-style linear-time regular expressions. Python uses its
standard backtracking regular expression engine and rejects several unsupported
constructs, but it cannot guarantee equivalent runtime cost or all Unicode
semantics for arbitrary custom expressions. Python limits each inspection to two
seconds with a POSIX main-thread timer and rejects requests if that timer is
unavailable, already in use, or expires. It does not provide an unbounded fallback
on Windows or worker threads. Prefer the Go binary for production traffic; only
administrators should author custom rules.

## Normalization and resource limits

Inspection retains original strings and constructs bounded alternative views with
up to three rounds of percent decoding (path and form conventions), HTML entity
decoding, and extraction of string keys/values from valid JSON. A separate inspection view
retains JSON punctuation while decoding string literals, exposing escaped property
names to structural signatures. JSON duplicate keys
remain visible in raw engine analysis; the MCP request gate rejects duplicates.
Each field is limited to 16 views and eight times its configured
size limit. Exceeding an inspection budget rejects the request; it never silently
inspects a truncated prefix. If a further unseen decoded view remains after three
rounds, the request is rejected. Matching examines alternatives individually, avoiding
artificial matches across concatenated decoded versions.

| Input | Limit/behavior |
| --- | --- |
| URL | 16 KiB; strict absolute HTTP/HTTPS URI syntax; exact origin authorization and public-IP pinning |
| Body | 1 MiB of UTF-8 request bytes |
| Headers | 128 fields, 64 KiB aggregate, 8 KiB per field; no caller framing, routing or browser-context assertions |
| Method | Uppercase GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS; GET/HEAD bodies rejected |
| Content encoding | Identity only; UTF-8 text, JSON and forms; unsupported formats rejected |
| Framing | Managed entirely by the proxy; raw response headers validated before client normalization |
| Redirects | Returned as 3xx; never followed automatically |
| Timeout | 1–120 seconds, default 30 |
| Response body | 10 MiB; overflow is reported as an error |
| Cumulative limits | Per-process request, RPC and byte budgets; see the protocol contract |

Transport-generated headers and HTTP framing are outside the agent-supplied
payload buffers. Cookie jars are disabled in the Go proxy so they cannot append
uninspected credentials. Logs record rule IDs/validation status and omit blocked
URLs, headers and bodies. An alert is not a security approval. A passed-request
counter means inspection permitted dispatch, not that the remote operation succeeded.

## Enforcement boundary

The proxy is an MCP tool, not an operating-system firewall. Registering it does
not force an agent's shell, other MCP servers, browser, raw sockets, DNS, or file
operations through it. Apply network and tool permissions independently:

1. Enforce an external default-deny egress policy so agent traffic can only use
   the proxy. The production proxy now validates exact origins and public IPs at
   connection time, including mixed DNS answers, IPv6 and rebinding; this does not
   constrain tools or sockets outside the proxy process.
2. Use separate per-task credentials with the minimum tool/action/resource scope.
   Enforce authorization and spending/rate limits on the server performing the
   action, even when the request looks syntactically harmless.
3. Gate irreversible actions with an independently enforced approval policy;
   isolate filesystem/process access and keep policy/configuration outside the
   agent's writable workspace.
4. Treat retrieved pages, documents, tool responses and model output as untrusted.
   This proxy does not inspect response bodies for prompt injection. Its outbound
   prompt indicators cannot recognize arbitrary semantic or indirect injection.

Additional blind spots include encrypted/application-encoded content, arbitrary
base64 programs, multipart binary formats, custom encodings, payloads outside a signature's bounded matching span, cross-request and
low-and-slow attacks, secret values without recognizable syntax, destination
ownership, novel exploits, and authorized APIs used for unauthorized purposes.
A larger signature count does not close these gaps.

These boundaries align with [OWASP's prompt-injection prevention guidance](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
and [Excessive Agency guidance](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/).
For actual Snort syntax and semantics, see the [Snort rule documentation](https://docs.snort.org/rules/options/payload/http/),
which differs from this application's deliberately restricted parser.

## Validation

```sh
go test ./pkg/security/... ./pkg/mcp/proxy ./cmd/ax-mcp-proxy
go test -race ./pkg/security/... ./pkg/mcp/proxy
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*.py'
PYTHONDONTWRITEBYTECODE=1 python3 tools/import_agent_guard.py --check
```

When changing a signature, retain its SID, increment its revision, and update both
positive and benign fixtures. For new signatures reserve a unique SID, explain the
threat in its message and use a target narrow enough to avoid blocking unrelated
fields. Test realistic benign agent traffic before deployment. No external exploit
requests are required to run the rule corpus.

The Agent Guard importer uses the pinned source-data snapshot and reviewed coverage
mappings. It verifies provenance hashes, reproducibility, unique detection
fingerprints, source-SID accounting and effective default/strict actions. Do not
manually edit its generated section: update the reviewed inputs or importer,
regenerate, and rerun both runtime suites. Native-only signatures remain outside
AX's embed/load paths. All 70 parse in the separately configured
[native Snort 3.12.2.0 overlay](../native-snort3/README.md), with their original
IDs/actions checked. Its [offline packet replay](../native-snort3/replay-validation.json)
tests the native protocol controls; it is not a behavioral test of all 70 imported
signatures or proof of live inline blocking.
