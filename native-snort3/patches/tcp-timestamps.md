# TCP timestamp and SYN-data repair

The cumulative Snort 3.12.2.0 engine can lose timestamp enforcement after a
zero-valued handshake clock or after data on the opening SYN. It can also infer
negotiation from later options and reject traffic that should ignore those
options. Its Linux PAWS tolerance permits a timestamp one tick older than the
saved value.

The repair follows the negotiation and missing-option rules in
[RFC 7323 section 3.2](https://www.rfc-editor.org/rfc/rfc7323.html#section-3.2)
and the timestamp ordering and reset exceptions in
[sections 5.2 and 5.3](https://www.rfc-editor.org/rfc/rfc7323.html#section-5.2).
Data on SYN is supported by TCP and used by
[RFC 7413 section 4.2.2](https://www.rfc-editor.org/rfc/rfc7413.html#section-4.2.2).

Four source files change:

- `tcp_normalizer.cc` ignores unnegotiated timestamps on non-SYN packets without
  changing option bytes or enabling later PAWS state. Negotiated timestamp
  checks retain zero values and use wrap-aware ordering without the one-tick
  tolerance. The existing reset exception remains in place. The opening SYN
  precedes an advertised peer window, so its permitted data is queued without
  applying a fictional zero window; configured SYN-payload trimming still
  applies before that path.
- `tcp_session.cc` keeps the selected normalization policy when the opening SYN
  contains data. The previous missing-handshake downgrade disabled timestamp
  and other checks for the rest of the connection.
- `tcp_stream_tracker.cc` starts SYN receive sequence tracking after the SYN
  sequence byte, then lets the data-processing path validate and advance over
  the payload. Advancing over payload during handshake initialization caused
  valid SYN-ACK data to be trimmed as if already received.
- `tcp_state_syn_recv.cc` records the SYN-ACK acknowledgement of opening data.
  Subsequent PAWS updates use that acknowledged sequence boundary; leaving it
  behind prevented the saved timestamp from advancing.

The existing native events **129:4** and **129:14** enforce old and missing
negotiated timestamps. This repair adds no Snort signature and must be compiled
into the engine; loading the AX rule plugin alone does not apply it.

## Rebuild and validate

Apply the source delta after all cumulative repairs through fragment identity:

```sh
python3 native-snort3/patches/apply_tcp_timestamp_repair.py \
  --previous-build-root /path/to/verified/fragment-identity-build \
  --target-source /path/to/new/timestamp-source
```

The applicator verifies the complete preceding source manifest against the
recorded cumulative build, refuses an existing target, copies the source and
writes the patch plus before/after hashes. Build that copy using the existing
Snort build workflow. The timestamp build recorder verifies regular and ASan
snapshots against the same source and checks that configuration changes are
limited to output paths. No installer or live interface is involved.

`tests/tcp_timestamp_replay.py` checks actual file-only inline DAQ verdicts and
exact forwarded bytes across both IP families, both directions, DNS and broker
routes, zero and wrapping clocks, reset exceptions, ignored unnegotiated
options, missing and stale timestamps, and recovery after rejection. Handshake
and subject fragmentation are tested in both arrival orders. Explicit plain
Fast Open and SYN-data controls cover the normalization downgrade independently
of fragmentation.

The test oracle permits an orphan fragment from a rejected datagram but never
both fragments. Expected drops, successful recovery and byte preservation are
checked separately. Baseline comparisons, preliminary fixture corrections,
diagnostic builds and sanitizer repetitions must not be accumulated as new
cases in the combined test inventory.

The [build record](../tcp-timestamp-build-validation.json) binds the
[four-file patch](snort-tcp-timestamps.patch) to matching regular and ASan source
snapshots. The [final replay record](../tcp-timestamp-validation.json) passes
**3,120/3,120 cases** in both builds: 2,400 allowed controls and 720 denial cases.
The preceding cumulative engine failed 684 of these same inputs: 520 unexpected
admissions and 164 false rejections. Regular and instrumented runs have identical
verdicts, events and forwarded bytes. All 720 denials emit their expected native
timestamp event. The 3,884 existing SACK, TCP option, cumulative packet and DNS
perimeter checks also pass and are excluded from the new-case increment.

The full engine uses AddressSanitizer; the protocol plugin additionally uses
UndefinedBehaviorSanitizer. These records do not claim whole-engine UBSan
coverage. Earlier prototype builds and corrected fixture mistakes remain
identified in the final record instead of being counted as passing new tests.

## Scope

This is a strict local timestamp/handshake repair, including removal of legacy
OS timestamp tolerances. It does not implement timestamp authentication, verify
Fast Open cookies, prove all timestamp-echo/idle-aging behavior, or turn native
stream bookkeeping into a transaction committed only after final DAQ admission.
SACK's separate admission-state guard retains that narrower guarantee.
SYN-data cookie validation and application execution remain endpoint concerns.
The serial comparator also denies an exactly half-range timestamp difference
as conservative local policy; that ambiguous boundary is not separately covered
by this corpus. The existing long-idle timestamp handling is unchanged.
The tested behavior does not prove universal standards compliance, deployed
routing correctness, or prevention of every unknown attack.
