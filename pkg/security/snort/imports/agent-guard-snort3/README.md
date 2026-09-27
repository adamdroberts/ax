# Agent Guard import into AX

The user supplied `agent-guard-snort3.zip`, an authored Snort 3 development bundle
with 825 canonical signatures. Category files and selectable profile files repeat
those signatures. This import reads the canonical catalog exactly once. Archive
documents and helper scripts were treated as source material, not instructions;
no bundled script or firewall configuration was executed. Separate, locally authored
synthetic packet tests are described below; no live deployment was changed.

## Result

| Source disposition | Count | Meaning |
| --- | ---: | --- |
| Imported into AX | 664 | Converted to the supported request-inspection language |
| Covered by retained signatures | 77 | Exact equivalents or reviewed subsumptions; the report maps each source SID to its retained AX SID |
| Already enforced by proxy validation | 14 | Framing, invalid headers/URLs, body limits and compressed-body rejection |
| Retained for native Snort only | 70 | Packet, response, original wire-header, counter or incompatible contract predicates |
| Total source inventory | 825 | Every source SID has exactly one disposition |

Six exact duplicates in the original AX default/strict catalogs were consolidated
without losing their blocking behavior. Policy promotion now changes the action of
one retained SID rather than registering a second signature.

The current merged default profile has **894 rules: 156 blocking and 738 advisory**. Strict
mode promotes 562 of those alerts and adds 28 signatures, producing **922 unique
active rules: 746 blocking and 176 advisory**. This includes the later DNS rules
and retirement of redundant SID 1200133 in favor of 9104053. Counts describe signatures, not
independent attacks or a measured prevention rate.

## Files and provenance

- [`source-catalog.json`](source-catalog.json) is the byte-identical canonical JSON
  from the supplied archive. It is reference data, not another loadable rule pack.
- [`dedup-review.json`](dedup-review.json) records reviewed source-to-existing and
  source-to-source coverage relationships with their reasoning.
- [`import-report.json`](import-report.json) records every source SID, disposition,
  retained SID, adaptation and effective profile action.
- [`native-only.rules`](native-only.rules) retains 70 original native predicates,
  rendered with the original balanced-profile actions and network variables.
  **AX does not load this file.** It requires a separately configured Snort sensor.
- [`../../rules/strict-actions.json`](../../rules/strict-actions.json) stores strict
  action promotions without duplicate signatures.

Archive SHA-256:
`b1555e5100070173700dbdd06032a3e22c43de09d2ca3bb1492d37f385c882ba`

Canonical source SHA-256:
`fad4889422b121d0c57680ce90b0ca1a790918ca781f9a69d04031bcaf7707ba`

All 912 checksum entries supplied in the archive were independently verified.
Checksum consistency establishes integrity of this input, not third-party
certification or authorship. The archive itself states native Snort parsing,
packet detection and inline prevention were unvalidated. Subsequent validation of
the retained native subset is reported separately from those archive claims.

## Compatibility and policy decisions

The HTTP request rules are adapted to AX's outbound application context. Original
sensor address/port variables and `flow` qualifiers belong to the Snort inspection
hop and are not silently treated as an AX destination allowlist. `fast_pattern`
selection is omitted as an optimization hint. Match targets are explicit modifiers
after each predicate; URI/body surfaces remain distinct.

Raw URI and raw body rules use undecoded request-target/body buffers. Header-field
rules see normalized field values, with Host taken from the actual request
authority. Original raw wire headers cannot be reconstructed faithfully from MCP
header maps; such rules remain native-only unless the proxy already rejects the
condition before dispatch.

Eighteen standalone patterns use terminal positive lookahead. Their final delimiter
check is translated into an equivalent consuming group for Go RE2. No relative
matching or subsequent capture use depends on the consumed delimiter. All other
unsupported native semantics remain separate; no parser option is discarded to
make a rule appear active.

The strict-only retained rules for CONNECT, DELETE, grouped WebDAV mutations,
shell invocation, recursive deletion and Terraform now provide equivalent default
coverage on their existing SIDs. CONNECT blocks in default, matching the source;
the others are advisory in default and retain strict blocking. Existing blocking
signatures are never downgraded when they cover source alerts.

**One source policy is deliberately adapted:** SID 9114035 detects a GitHub-shaped
token in Authorization. It remains advisory in both profiles because authenticated
API traffic normally carries credentials there. The source strict action was
blocking. Body/URL credential signatures retain blocking; cookie and Referer
signatures retain their separate source policy. This exception is explicit in the
report and tested.

Deduplication compares buffers, predicates, case behavior, negation and byte windows,
ignoring titles/SIDs/actions. Reviewed containment proofs remove additional rules
with redundant coverage. Similar threat names, a single shared example or different
URI/body/header scopes are not enough to declare two rules duplicates. Broader
boundary/case variants are retained when they add coverage; overlapping signatures
are not necessarily equivalent.

## Native-only boundary

The retained native rules include network perimeter predicates, response/file
inspection, raw packet protocol indicators, raw HTTP header checks, rate counters
and broker-specific thresholds. For example, the source's 4 KiB URI and 64-header
contract differs from AX's 16 KiB URI and 128-header limits. Those stronger source
limits are not claimed as active in AX. The report explains each retained record.

All 70 retained native signatures now load in a separate, release-pinned
[Snort 3.12.2.0 profile](../../../../../native-snort3/README.md), with their exact
IDs and actions verified. The original 825-signature source pack and the converted
AX catalog have not been certified as native Snort packs; the import report's
`source_engine_validated` remains false for that broader claim. The native replay
report tests packet/stream controls, not every retained HTTP signature. Live
inline enforcement remains unverified. The archive's example network variables
must not be mistaken for site-specific deployment settings.

## Reproduction and validation

From the AX repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/import_agent_guard.py --check
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*.py'
go test ./pkg/security/snort ./pkg/mcp/proxy ./cmd/ax-mcp-proxy
```

Running the importer without `--check` regenerates its marked rule section, the
strict promotion map, native-only file, import report and shared fixture corpus.
It does not execute source scripts. Existing hand-authored AX rules outside the
marked section are retained, subject to the explicitly reviewed baseline aliases.

The shared corpus contains **2,580 cases**, including a positive example for every
retained source mapping, benign cases and wrong-field checks for each new active
signature. Tests independently verify unique SIDs/predicates, all source dispositions,
profile actions, promotion failures, scoped buffers, the authentication exception,
terminal-lookahead equivalence and byte-for-byte reproducibility. String regression
results do not establish native Snort compatibility or real-world detection rates.
