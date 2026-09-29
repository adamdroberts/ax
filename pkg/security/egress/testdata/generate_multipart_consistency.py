"""Generate paired wire cases from a small, independent byte-position oracle."""

import base64
import json
from pathlib import Path


BOUNDARY = b"range-consistency"
FRAMINGS = ("length", "chunked", "close")
CASES = []


def consistent(parts):
    positions = {}
    for first, data, _ in parts:
        for offset, value in enumerate(data, first):
            if offset in positions and positions[offset] != value:
                return False
            positions[offset] = value
    return True


def add(name, parts, requested="bytes=0-15,20-31", *, padding=False):
    body = b"ignored preamble\r\n" if padding else b""
    for first, data, total in parts:
        body += b"--" + BOUNDARY + b"\r\n"
        body += f"Content-Range: bytes {first}-{first + len(data) - 1}/{total}\r\n".encode()
        body += b"Content-Type: text/plain; charset=utf-8\r\n\r\n" + data + b"\r\n"
    body += b"--" + BOUNDARY + b"--\r\n"
    if padding:
        body += b"ignored epilogue"
    for framing in FRAMINGS:
        wire = b"HTTP/1.1 206 Partial Content\r\nContent-Type: multipart/byteranges; boundary=" + BOUNDARY + b"\r\n"
        if framing == "length":
            wire += f"Content-Length: {len(body)}\r\n\r\n".encode() + body
        elif framing == "chunked":
            wire += b"Transfer-Encoding: chunked\r\n\r\n"
            # Split MIME headers, content and multibyte characters across chunks.
            for i in range(0, len(body), 7):
                chunk = body[i:i + 7]
                wire += f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n"
            wire += b"0\r\n\r\n"
        else:
            wire += b"Connection: close\r\n\r\n" + body
        CASES.append({"name": f"{name}-{framing}", "method": "GET",
                      "accepted": consistent(parts), "request_headers": {"Range": requested},
                      "wire_base64": base64.b64encode(wire).decode(),
                      "body_base64": base64.b64encode(body).decode()})


def pair(name, intervals, *, totals=None, requested="bytes=0-15,20-31", padding=False):
    parts = [(first, bytes(97 + i % 26 for i in range(first, last + 1)),
              totals[n] if totals is not None else 64)
             for n, (first, last) in enumerate(intervals)]
    add(name + "-consistent", parts, requested, padding=padding)
    first, data, total = parts[-1]
    shared = sorted({position for a, b in intervals[:-1]
                     for position in range(max(a, first), min(b, intervals[-1][1]) + 1)})
    assert shared, name
    # Prefer an interior mismatch, so comparing only overlap endpoints is insufficient.
    position = shared[len(shared) // 2] - first
    altered = data[:position] + b"!" + data[position + 1:]
    parts[-1] = (first, altered, total)
    assert not consistent(parts)
    add(name + "-conflict", parts, requested, padding=padding)


def main():
    shapes = {
        "duplicate": [(0, 7), (0, 7)],
        "prefix": [(0, 8), (0, 3)],
        "suffix": [(0, 8), (5, 8)],
        "contained": [(0, 10), (3, 7)],
        "partial": [(0, 7), (4, 11)],
        "one-byte": [(0, 5), (5, 10)],
        "reverse-contained": [(3, 7), (0, 10)],
        "reverse-partial": [(4, 11), (0, 7)],
        "nonadjacent": [(0, 7), (20, 23), (3, 5)],
        "joins-two": [(0, 4), (8, 12), (3, 10)],
        "nested-three": [(0, 15), (4, 11), (6, 9)],
        "sixteen-parts": [(0, 7)] * 16,
    }
    for name, intervals in shapes.items():
        pair(name, intervals)
    for name, totals in (("unknown-total", ["*", "*"]),
                         ("first-known-total", [64, "*"]),
                         ("last-known-total", ["*", 64])):
        pair(name, shapes["partial"], totals=totals)
    ceiling = (1 << 63) - 1
    offsets = [(ceiling - 15, ceiling - 7), (ceiling - 10, ceiling - 3)]
    requested = f"bytes={ceiling - 20}-{ceiling - 12},{ceiling - 11}-"
    pair("large-known-offset", offsets, totals=[ceiling, ceiling], requested=requested)
    pair("large-unknown-offset", offsets, totals=["*", "*"], requested=requested)
    pair("preamble-epilogue", shapes["partial"], padding=True)
    for name, left, right, changed in (
            ("utf8-octets", "ab€cd", "€cdXY", "₭cdXY"),
            ("nul-crlf", "ab\x00\r\ncd", "\x00\r\ncdXY", "!\r\ncdXY")):
        parts = [(0, left.encode(), 64), (2, right.encode(), 64)]
        add(name + "-consistent", parts)
        parts[-1] = (2, changed.encode(), 64)
        add(name + "-conflict", parts)
    add("adjacent-different-values", [(0, b"abc", 64), (3, b"XYZ", 64)])
    add("disjoint-different-values", [(0, b"abc", 64), (20, b"XYZ", 64)])
    add("one-part", [(0, b"abc", 64)])
    assert len({case["name"] for case in CASES}) == len(CASES)
    path = Path(__file__).with_name("multipart_consistency_cases.json")
    path.write_text(json.dumps({"version": 1, "cases": CASES}, indent=2) + "\n")
    print(f"{len(CASES)} cases: {sum(case['accepted'] for case in CASES)} accepted controls")


if __name__ == "__main__":
    main()
