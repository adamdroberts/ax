"""Independent RFC 9530 request fixtures; no production parser is imported."""
import base64
import hashlib
import json
from pathlib import Path


def digest(body, algorithm="sha-256"):
    raw = body.encode("utf-8") if isinstance(body, str) else body
    factory = {"sha-256": hashlib.sha256, "sha-512": hashlib.sha512}[algorithm]
    return algorithm + "=:" + base64.b64encode(factory(raw).digest()).decode() + ":"


cases = []


def add(name, accepted=True, body="hello", value=None, method="POST", headers=None):
    fields = {"Content-Type": "text/plain"}
    if value is not None:
        fields["Content-Digest"] = value
    fields.update(headers or {})
    cases.append({"name": name, "accepted": accepted, "arguments": {
        "url": "https://api.example.com/digest", "method": method,
        "headers": fields, "body": body,
    }})


add("absent")
for algorithm in ("sha-256", "sha-512"):
    add(algorithm, value=digest("hello", algorithm))
    add(algorithm + "-mismatch", False, value=digest("other", algorithm))
add("both-strong", value=digest("hello") + ", " + digest("hello", "sha-512"))
add("second-strong-mismatch", False, value=digest("hello") + ", " + digest("other", "sha-512"))
add("first-strong-mismatch", False, value=digest("other") + ", " + digest("hello", "sha-512"))
add("unknown-with-strong", value="future=:AA==:, " + digest("hello"))
add("deprecated-with-strong", value="md5=:AA==:, " + digest("hello"))
for name, value in [
    ("empty", ""), ("unknown-only", "future=:AA==:"), ("deprecated-only", "md5=:AA==:"),
    ("uppercase-algorithm", digest("hello").upper()),
    ("duplicate", digest("hello") + ", " + digest("hello")),
    ("duplicate-conflicting", digest("hello") + ", " + digest("other")),
    ("empty-byte-sequence", "sha-256=::"), ("wrong-output-size", "sha-256=:AA==:"),
    ("missing-colon", digest("hello")[:-1]), ("trailing-comma", digest("hello") + ","),
    ("leading-comma", "," + digest("hello")), ("empty-member", digest("hello") + ",,other=::"),
    ("bare-string", 'sha-256="abc"'), ("inner-list", "sha-256=(:AA==:)"),
    ("spacing-before-equals", digest("hello").replace("=", " =", 1)),
    ("spacing-after-equals", digest("hello").replace("=:", "= :", 1)),
    ("parameter-date", digest("hello") + ";created=@1"),
    ("parameter-invalid-bool", digest("hello") + ";flag=?2"),
]:
    add(name, False, value=value)
add("missing-base64-padding", value=digest("hello")[:-2] + ":")
add("opaque-parameters", value=digest("hello") + ';flag;weight=1.5;label="hello";token=foo/bar')
add("field-case", headers={"cOnTeNt-DiGeSt": digest("hello")})
add("duplicate-field-case", False, value=digest("hello"), headers={"content-digest": digest("hello")})
for method in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
    add("empty-" + method, body="", method=method, value=digest(""))
    add("empty-mismatch-" + method, False, body="", method=method, value=digest("hello"))
for method in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
    add("content-" + method, method=method, value=digest("hello"))
for name, body in [
    ("utf8", "caf\u00e9 \U0001f642"), ("nfd", "cafe\u0301"),
    ("bom", "\ufeffhello"), ("crlf", "hello\r\n"), ("lf", "hello\n"), ("nul", "hello\0"),
]:
    add(name, body=body, value=digest(body))
add("unicode-normalization-mismatch", False, body="cafe\u0301", value=digest("caf\u00e9"))
add("newline-normalization-mismatch", False, body="hello\r\n", value=digest("hello\n"))
add("json-exact-octets", body='{"b":2, "a":1}\n', value=digest('{"b":2, "a":1}\n'),
    headers={"Content-Type": "application/json"})
add("json-reserialization-mismatch", False, body='{"b":2, "a":1}\n', value=digest('{"a":1,"b":2}'),
    headers={"Content-Type": "application/json"})
add("form-wire-octets", body="q=hello+world", value=digest("q=hello+world"),
    headers={"Content-Type": "application/x-www-form-urlencoded"})
add("form-decoded-mismatch", False, body="q=hello+world", value=digest("q=hello world"),
    headers={"Content-Type": "application/x-www-form-urlencoded"})
add("partial-put-content", method="PUT", body="abc", value=digest("abc"),
    headers={"Content-Range": "bytes 3-5/9"})
add("partial-put-representation-mismatch", False, method="PUT", body="abc", value=digest("000abc999"),
    headers={"Content-Range": "bytes 3-5/9"})

assert len({case["name"] for case in cases}) == len(cases)
if __name__ == "__main__":
    Path(__file__).with_name("request_digest_cases.json").write_text(
        json.dumps({"cases": cases}, ensure_ascii=True, indent=2) + "\n")
