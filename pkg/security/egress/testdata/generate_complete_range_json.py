"""Shared complete/incomplete JSON range cases; no production parser imports."""
import argparse
import base64
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("complete_range_json_cases.json"))
    output = parser.parse_args().output
    cases = []

    def add(name, body, headers, accepted, layout, request="bytes=0-", framings=("fixed", "chunked", "close")):
        for framing in framings:
            fields = list(headers)
            payload = body
            if framing == "fixed":
                fields.append(("Content-Length", str(len(body))))
            elif framing == "chunked":
                fields.append(("Transfer-Encoding", "chunked"))
                cut = max(1, len(body) // 2)
                payload = b"".join(f"{len(part):x}\r\n".encode() + part + b"\r\n" for part in (body[:cut], body[cut:]) if part) + b"0\r\n\r\n"
            wire = b"HTTP/1.1 206 Partial Content\r\n" + b"".join(f"{key}: {value}\r\n".encode() for key, value in fields) + b"\r\n" + payload
            cases.append({"name": name + "-" + framing, "method": "GET", "accepted": accepted,
                          "layout": layout, "request_headers": {"Range": request},
                          "wire_base64": base64.b64encode(wire).decode(), "body_base64": base64.b64encode(body).decode()})

    def single(name, body, valid, media="application/json", first=0, total=None, full=True):
        total = len(body) if total is None else total
        headers = [("Content-Range", f"bytes {first}-{first + len(body) - 1}/{total}")]
        if media is not None:
            headers.append(("Content-Type", media))
        add(name, body, headers, valid if full else True, "single", request=f"bytes={first}-")

    def multipart(name, parts, valid, request="bytes=0-0,1-"):
        # Independent byte-position coverage oracle, not the interval scan used
        # by the brokers. Iterate supplied bytes only, never an advertised total.
        positions, totals = {}, set()
        is_json = False
        body = bytearray()
        for first, data, total, media in parts:
            if total != "*":
                totals.add(total)
            is_json |= media is not None and (media.lower().split(";")[0] == "application/json" or media.lower().split(";")[0].endswith("+json"))
            body.extend(f"--jsonrange\r\nContent-Range: bytes {first}-{first + len(data) - 1}/{total}\r\n".encode())
            if media is not None:
                body.extend(f"Content-Type: {media}\r\n".encode())
            body.extend(b"\r\n" + data + b"\r\n")
            for offset, octet in enumerate(data, first):
                assert offset not in positions or positions[offset] == octet
                positions[offset] = octet
        body.extend(b"--jsonrange--\r\n")
        assert len(totals) <= 1
        complete = next(iter(totals)) if totals else None
        covered = complete is not None and len(positions) == complete and min(positions) == 0 and max(positions) == complete - 1
        accepted = valid if is_json and covered else True
        add(name, bytes(body), [("Content-Type", "multipart/byteranges; boundary=jsonrange")], accepted, "multipart", request=request)

    documents = [
        ("object", b'{"ok":true}', True),
        ("scalar", b"42", True),
        ("array", b'[null,{"x":[1,2]}]', True),
        ("utf8", '{"label":"\u20ac"}'.encode(), True),
        ("duplicate", b'{"x":1,"x":2}', False),
        ("escaped-duplicate", b'{"x":1,"\\u0078":2}', False),
        ("unsafe-integer", b"9007199254740992", False),
        ("trailing-document", b"{}[]", False),
        ("lone-surrogate", b'"\\ud800"', False),
        ("unfinished", b'{"x":', False),
    ]
    for name, data, valid in documents:
        single("single-" + name, data, valid)
        boundaries = [i for i in range(1, len(data)) if data[i] < 128]
        cut = min(boundaries, key=lambda i: abs(i - len(data) // 2))
        multipart("adjacent-" + name, [(0, data[:cut], len(data), "application/json"), (cut, data[cut:], len(data), "application/json")], valid)
        # Extend the first interval to a complete UTF-8 boundary, then reverse
        # the overlapping parts. The wire MIME body still remains UTF-8 text.
        end = next((i for i in range(cut + 1, len(data)) if data[i] < 128), len(data))
        multipart("reversed-overlap-" + name, [(cut, data[cut:], len(data), "application/json"), (0, data[:end], len(data), "application/json")], valid)

    bad = b'{"x":1,"x":2}'
    total = len(bad)
    single("single-prefix-fragment", bad[:4], False, total=total, full=False)
    single("single-unknown-total", bad, False, total="*", full=False)
    single("single-offset-fragment", bad, False, first=10, total=10+total, full=False)
    single("single-untyped", bad, True, media=None)
    single("single-text", bad, True, media="text/plain")
    single("single-parameter-only", bad, True, media='text/plain; title="application/json"')
    single("single-json-suffix", bad, False, media="application/problem+json; charset=UTF-8")
    single("single-other-json-suffix", bad, False, media="TEXT/Example+JSON")
    multipart("unknown-total", [(0, bad[:6], "*", "application/json"), (6, bad[6:], "*", "application/json")], False)
    multipart("known-total-last", [(0, bad[:6], "*", "application/json"), (6, bad[6:], total, "application/json")], False)
    multipart("known-total-first", [(0, bad[:6], total, "application/json"), (6, bad[6:], "*", "application/json")], False)
    multipart("gap", [(0, bad[:5], total, "application/json"), (6, bad[6:], total, "application/json")], False)
    multipart("missing-prefix", [(1, bad[1:6], total, "application/json"), (6, bad[6:], total, "application/json")], False)
    multipart("missing-tail", [(0, bad[:6], total, "application/json"), (6, bad[6:-1], total, "application/json")], False)
    multipart("whole-part", [(0, bad, total, "application/json")], False)
    multipart("whole-duplicate", [(0, bad, total, "application/json")] * 2, False)
    multipart("whole-untyped-json-fragment", [(0, bad, total, None), (3, bad[3:5], total, "application/json")], False)
    multipart("mixed-media-json-fragment", [(0, bad[:6], total, "text/plain"), (6, bad[6:], total, "application/json")], False)
    multipart("all-untyped", [(0, bad[:6], total, None), (6, bad[6:], total, None)], False)
    multipart("all-text", [(0, bad[:6], total, "text/plain"), (6, bad[6:], total, "text/plain")], False)
    multipart("sixteen-parts", [(i, bad[i:i+1], total, "application/json") for i in range(total)] + [(0, bad[:1], total, "application/json")] * (16-total), False)
    ceiling = (1 << 63) - 1
    multipart("huge-offset", [(ceiling-total, bad, ceiling, "application/json")], False, request=f"bytes=0-0,{ceiling-total}-")
    assert len({c["name"] for c in cases}) == len(cases)
    assert len({(c["wire_base64"], tuple(c["request_headers"].items())) for c in cases}) == len(cases)
    output.write_text(json.dumps({"version": 1, "cases": cases}, indent=2) + "\n")
    print(f"{len(cases)} cases: {sum(c['accepted'] for c in cases)} accepted, {sum(not c['accepted'] for c in cases)} denied")


if __name__ == "__main__":
    main()
