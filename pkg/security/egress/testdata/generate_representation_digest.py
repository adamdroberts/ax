"""Independent request/response Repr-Digest semantics and admission fixtures."""
import argparse
import base64
import hashlib
import json
from pathlib import Path


def digest(data, algorithm="sha-256"):
    if isinstance(data, str):
        data = data.encode()
    return algorithm + "=:" + base64.b64encode(hashlib.new(algorithm.replace("-", ""), data).digest()).decode() + ":"


def corpus():
    requests, responses = [], []

    def request(name, body="hello", value=None, accepted=True, method="POST", headers=None):
        fields = {"Content-Type": "text/plain"}
        if value is not None:
            fields["Repr-Digest"] = value
        fields.update(headers or {})
        requests.append({"name": name, "accepted": accepted, "arguments": {
            "url": "https://api.example.com/digest", "method": method, "body": body, "headers": fields}})

    good, empty, wrong = digest("hello"), digest(""), digest("other")
    for method in ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]:
        body = "" if method in ("GET", "HEAD") else "hello"
        request("valid-" + method, body=body, value=digest(body), method=method)
        request("mismatch-" + method, body=body, value=wrong, accepted=False, method=method)
    request("absent")
    request("sha512", value=digest("hello", "sha-512"))
    request("independent-fields", value=good, headers={"Content-Digest": good})
    request("invalid-content-with-valid-representation", value=good, headers={"Content-Digest": wrong}, accepted=False)
    request("invalid-representation-with-valid-content", value=wrong, headers={"Content-Digest": good}, accepted=False)
    request("partial-upload-unavailable", body="abc", value=digest("000abc999"), method="PUT",
            headers={"Content-Range": "bytes 3-5/9"}, accepted=False)
    request("partial-upload-fragment-is-not-whole", body="abc", value=digest("abc"), method="PUT",
            headers={"Content-Range": "bytes 3-5/9"}, accepted=False)
    request("complete-range-upload", body="abc", value=digest("abc"), method="PUT",
            headers={"Content-Range": "bytes 0-2/3"})
    request("unknown-upload-total", body="abc", value=digest("abc"), method="PUT",
            headers={"Content-Range": "bytes 0-2/*"}, accepted=False)
    request("patch-document", body='{"op":"replace"}', value=digest('{"op":"replace"}'), method="PATCH",
            headers={"Content-Type": "application/json"})
    request("utf8-exact", body="caf\u00e9", value=digest("caf\u00e9"))
    request("normalization-mismatch", body="cafe\u0301", value=digest("caf\u00e9"), accepted=False)
    for name, value in [("empty", ""), ("unsupported", "future=:AA==:"), ("duplicate", good + ", " + good),
                        ("wrong-output-length", "sha-256=:AA==:"), ("malformed", "sha-256=abc")]:
        request(name, value=value, accepted=False)
    request("field-case", headers={"rEpR-DiGeSt": good})
    request("duplicate-field-case", value=good, headers={"repr-digest": good}, accepted=False)

    def response(name, data=b"hello", values=None, accepted=True, status=200, method="GET",
                 headers=(), request_headers=None, framing="fixed", stage="body", interim=False):
        fields = list(headers) + [("Repr-Digest", v) for v in (values or [])]
        payload = data
        if framing == "fixed":
            fields.append(("Content-Length", str(len(data))))
        elif framing == "chunked":
            payload = (f"{len(data):x}\r\n".encode() + data + b"\r\n" if data else b"") + b"0\r\n\r\n"
            fields.append(("Transfer-Encoding", "chunked"))
        wire = f"HTTP/1.1 {status} Response\r\n".encode() + b"".join(f"{k}: {v}\r\n".encode() for k, v in fields) + b"\r\n" + payload
        if interim:
            wire = b"HTTP/1.1 103 Early Hints\r\n" + b"".join(f"Repr-Digest: {v}\r\n".encode() for v in values or []) + b"\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
            data = b"hello"
        responses.append({"name": name, "accepted": accepted, "method": method, "status": status,
                          "headers": fields, "request_headers": request_headers or {}, "interim": interim,
                          "body_base64": base64.b64encode(data).decode(),
                          "wire_base64": base64.b64encode(wire).decode(), "rejection_stage": None if accepted else stage})

    response("absent")
    for framing in ["fixed", "chunked", "close"]:
        response("valid-" + framing, values=[good], framing=framing)
        response("mismatch-" + framing, values=[wrong], accepted=False, framing=framing)
        response("empty-" + framing, data=b"", values=[empty], framing=framing)
        response("complete-single-" + framing, values=[good], status=206, headers=[("Content-Range", "bytes 0-4/5")],
                 request_headers={"Range": "bytes=0-"}, framing=framing)
        response("incomplete-single-" + framing, values=[good], status=206, headers=[("Content-Range", "bytes 0-4/10")],
                 request_headers={"Range": "bytes=0-"}, framing=framing, accepted=False, stage="headers")
    response("sha512", values=[digest("hello", "sha-512")])
    response("both-fields", values=[good], headers=[("Content-Digest", good)])
    response("separate-strong-values", values=[good, digest("hello", "sha-512")])
    response("one-declared-mismatch", values=[good, digest("other", "sha-512")], accepted=False)
    response("unknown-alongside", values=[good + ", future=::"])
    response("opaque-parameters", values=[good + ';v=1;flag;note="opaque"'])
    for name, value in [("empty-field", ""), ("unsupported-only", "future=::"),
                        ("wrong-length", "sha-256=:AA==:"), ("invalid-byte-sequence", "sha-256=bad"),
                        ("duplicate", good + ", " + good)]:
        response(name, values=[value], accepted=False, stage="headers")
    response("duplicate-across-fields", values=[good, good], accepted=False, stage="headers")
    response("connection-nomination", values=[good], headers=[("Connection", "repr-digest")], accepted=False, stage="headers")
    response("unknown-single-length", values=[good], status=206, headers=[("Content-Range", "bytes 0-4/*")],
             request_headers={"Range": "bytes=0-"}, accepted=False, stage="headers")
    for method, status in [("HEAD", 200), ("GET", 304)]:
        args = {"If-None-Match": "*"} if status == 304 else {}
        response(f"known-empty-{status}", data=b"", values=[empty], status=status, method=method, request_headers=args)
        response(f"known-empty-mismatch-{status}", data=b"", values=[good], status=status, method=method,
                 request_headers=args, accepted=False, stage="headers")
        response(f"unavailable-{status}", data=b"", values=[good], status=status, method=method,
                 headers=[("Content-Length", "5")], framing="close", request_headers=args, accepted=False, stage="headers")
        response(f"unknown-length-empty-claim-{status}", data=b"", values=[empty], status=status, method=method,
                 framing="close", request_headers=args, accepted=False, stage="headers")
    for status in [204, 205]:
        response(f"no-selected-bytes-{status}", data=b"", values=[empty], status=status, framing="close",
                 accepted=False, stage="headers")
    response("interim-empty", values=[empty], interim=True)
    response("interim-nonempty", values=[good], interim=True, accepted=False, stage="headers")
    for method, status in [("POST", 201), ("PATCH", 200), ("DELETE", 202), ("GET", 301), ("GET", 404), ("GET", 500)]:
        response(f"enclosed-{method}-{status}", values=[good], status=status, method=method,
                 headers=[("Content-Location", "/result"), ("Location", "/different")])

    def multipart(name, parts, accepted=True, value=None, extras=()):
        data = bytearray()
        for first, text, total, media in parts:
            data.extend(f"--rep\r\nContent-Range: bytes {first}-{first+len(text)-1}/{total}\r\n".encode())
            if media:
                data.extend(f"Content-Type: {media}\r\n".encode())
            data.extend(b"Repr-Digest: MIME metadata stays opaque\r\n\r\n" + text + b"\r\n")
        data.extend(b"--rep--\r\n")
        response("multipart-" + name, data=bytes(data), values=[good if value is None else value], status=206,
                 headers=[("Content-Type", "multipart/byteranges; boundary=rep"), *extras],
                 request_headers={"Range": "bytes=0-1,2-"}, accepted=accepted)
        return bytes(data)

    whole = [(0, b"he", 5, None), (2, b"llo", 5, None)]
    mime = multipart("complete", whole)
    multipart("reversed-overlap", [(2, b"llo", 5, None), (0, b"hel", 5, None)])
    multipart("duplicated-full", [(0, b"hello", 5, None)] * 2)
    multipart("late-total", [(0, b"he", "*", None), (2, b"llo", 5, None)])
    multipart("unknown-total", [(0, b"he", "*", None), (2, b"llo", "*", None)], False)
    multipart("gap", [(0, b"h", 5, None), (2, b"llo", 5, None)], False)
    multipart("missing-start", [(1, b"e", 5, None), (2, b"llo", 5, None)], False)
    multipart("missing-end", [(0, b"he", 5, None), (2, b"ll", 5, None)], False)
    multipart("huge-total", [(0, b"he", (1 << 63)-1, None), (2, b"llo", (1 << 63)-1, None)], False)
    multipart("envelope-is-not-representation", whole, False, digest(mime))
    multipart("independent-content-and-repr", whole, extras=[("Content-Digest", digest(mime))])
    multipart("conflicting-overlap", [(0, b"hel", 5, None), (2, b"Xlo", 5, None)], False)
    multipart("valid-json", [(0, b'{"ok":', 11, "application/json"), (6, b"true}", 11, None)], value=digest(b'{"ok":true}'))
    multipart("invalid-json-even-with-valid-digest", [(0, b"{}[]", 4, "application/json")], False, digest(b"{}[]"))
    multipart("valid-xml", [(0, b"<a", 4, "application/xml"), (2, b"/>", 4, None)], value=digest(b"<a/>"))
    return {"requests": requests, "responses": responses}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("representation_digest_cases.json"))
    destination = parser.parse_args().output
    destination.write_text(json.dumps(corpus(), indent=2) + "\n")
