"""Independent, explicit HTTP Content-Disposition acceptance cases."""
import argparse
import json
from pathlib import Path
from urllib.parse import quote

cases = []
def add(name, value, accepted, category="syntax"):
    headers = value if isinstance(value, list) else [["Content-Disposition", value]]
    cases.append(dict(name=name, headers=headers, accepted=accepted, category=category))

for name, value in {
    "absent": [], "attachment": "attachment", "inline": "INLINE",
    "unknown-type": "x-custom; note=opaque", "token-name": "attachment; filename=report.txt",
    "quoted-name": 'attachment; filename="an example.txt"',
    "parameter-spaces": ' INLINE ; FILENAME = "report.txt" ',
    "quoted-separators": 'attachment; filename="comma,semi;equals=.txt"',
    "plus-is-literal": 'attachment; filename="one+two.txt"',
    "ordinary-percent": 'attachment; filename="100%.txt"',
    "dotfile": 'attachment; filename=".config"',
    "unknown-empty": 'attachment; x=""',
    "unknown-quoted-pair": 'attachment; x="a\\\"b"',
    "unknown-internal-star": 'attachment; x*y=value',
    "extended-empty-unknown": "attachment; title*=UTF-8''",
    "extended-attributes": "attachment; title*=UTF-8''!#$&+-.^_`|~",
    "fallback": "attachment; filename=EURO.txt; filename*=utf-8''%E2%82%AC.txt",
    "fallback-first-extended": "attachment; filename*=utf-8''%E2%82%AC.txt; filename=EURO.txt",
    "latin1-legacy": "attachment; filename*=ISO-8859-1''caf%E9.txt",
    "latin1-case": "attachment; filename*=iso-8859-1'en'%A3%20rates.txt",
}.items():
    add(name, value, True)

for name in ("café.txt", "€.txt", "日本語.txt", "😀.txt", "résumé 2026.txt", "a+b.txt"):
    add("utf8-" + name, "attachment; filename*=UTF-8''" + quote(name, safe=""), True, "encoding")

grandfathered = "en-GB-oed i-ami i-bnn i-default i-enochian i-hak i-klingon i-lux i-mingo i-navajo i-pwn i-tao i-tay i-tsu sgn-BE-FR sgn-BE-NL sgn-CH-DE art-lojban cel-gaulish no-bok no-nyn zh-guoyu zh-hakka zh-min zh-min-nan zh-xiang".split()
languages = ["", "en", "EN-us", "zh-Hant-TW", "de-CH-1901", "sl-rozaj-biske-1994", "es-419", "en-a-aaa-b-bbb-x-private", "x-company", "en-x-a", "abcd", "abcdefgh", "zh-cmn-Hans-CN", "en-abc-def-ghi", "en-0-aa", "en-u-ca-gregory"] + grandfathered
for index, tag in enumerate(languages):
    add("language-valid-" + str(index), "attachment; filename*=UTF-8'" + tag + "'name.txt", True, "language")
for index, tag in enumerate(["e", "abcdefghi", "en_uk", "en--US", "-en", "en-", "x", "en-x", "en-a", "en-a-x-private", "en-a-aa-A-bb", "de-1901-1901", "de-abcde-ABCDE", "en-US-Latn", "en-1234-US", "en-abc-def-ghi-jkl", "abcd-abc", "en-1", "en-x-abcdefghi", "en.USA", "en-12", "en-1234-abcd"]):
    add("language-invalid-" + str(index), "attachment; filename*=UTF-8'" + tag + "'name.txt", False, "language")

for name, value in {
    "empty": "", "space-only": " ", "bad-type": "attach/ment", "quoted-type": '"attachment"',
    "combined-types": "inline,attachment", "trailing-separator": "attachment;",
    "empty-slot": "attachment;; filename=a", "missing-equals": "attachment; filename",
    "empty-token": "attachment; filename=", "missing-name": "attachment; =a",
    "unterminated": 'attachment; filename="name', "truncated-escape": 'attachment; filename="name\\',
    "quoted-tail": 'attachment; filename="name"tail', "unquoted-space": "attachment; filename=one two",
    "unquoted-comma": "attachment; filename=one,two", "unquoted-equals": "attachment; filename=one=two",
    "duplicate-name": "attachment; filename=one; filename=two",
    "duplicate-name-case": "attachment; filename=one; FILENAME=one",
    "duplicate-extension": "attachment; x=one; X=two",
    "duplicate-extended": "attachment; filename*=UTF-8''one; FILENAME*=UTF-8''two",
    "quoted-extended": 'attachment; filename*="UTF-8\'\'name.txt"',
    "extended-no-charset": "attachment; filename*=''name.txt",
    "extended-no-quotes": "attachment; filename*=UTF-8name.txt",
    "extended-one-quote": "attachment; filename*=UTF-8'name.txt",
    "extended-extra-quote": "attachment; filename*=UTF-8''name'txt",
    "extended-star": "attachment; filename*=UTF-8''name*txt",
    "extended-braces": "attachment; filename*=UTF-8''{name}",
    "bad-percent": "attachment; filename*=UTF-8''name%GG.txt",
    "short-percent": "attachment; filename*=UTF-8''name%A",
    "bare-percent": "attachment; filename*=UTF-8''name%",
    "utf8-overlong": "attachment; filename*=UTF-8''%C0%AF.txt",
    "utf8-surrogate": "attachment; filename*=UTF-8''%ED%A0%80.txt",
    "utf8-out-of-range": "attachment; filename*=UTF-8''%F4%90%80%80.txt",
    "utf8-truncated": "attachment; filename*=UTF-8''%E2%82.txt",
    "unknown-extended-invalid": "attachment; title*=UTF-8''%FF",
}.items():
    add(name, value, False)

for name, value in {
    "continuation": "attachment; filename*0=name; filename*1=.txt",
    "encoded-continuation": "attachment; filename*0*=UTF-8''name; filename*1*=.txt",
    "extension-continuation": "attachment; x*0=a",
    "unsupported-charset": "attachment; filename*=UTF-16''%00a",
    "escaped-filename": 'attachment; filename="file\\name.txt"',
    "unsafe-fallback": "attachment; filename=..; filename*=UTF-8''safe.txt",
    "unsafe-preferred": "attachment; filename=safe.txt; filename*=UTF-8''..",
}.items():
    add(name, value, False, "local-policy")

unsafe_names = ["", ".", "..", "../report.txt", "folder/report.txt", "folder\\report.txt", "C:report.txt", "file:stream", " lead.txt", "tail.txt ", "tail.", "a<b.txt", "a>b.txt", "a|b.txt", "a?b.txt", "a*b.txt", 'a"b.txt', "name%20.txt", "name%2f.txt", "name%5C.txt"]
for index, name in enumerate(unsafe_names):
    quoted = name.replace("\\", "\\\\").replace('"', '\\"')
    add("unsafe-plain-" + str(index), 'attachment; filename="' + quoted + '"', False, "local-policy")
    add("unsafe-extended-" + str(index), "attachment; filename*=UTF-8''" + quote(name, safe=""), False, "local-policy")
for index, name in enumerate(["nul\x00.txt", "tab\t.txt", "line\n.txt", "del\x7f.txt", "c1\u0085.txt", "bidi\u202eexe.txt", "isolate\u2066.txt", "invisible\u200b.txt", "bom\ufeff.txt", "nonchar\ufdd0.txt", "last\U0010ffff.txt"]):
    add("unsafe-unicode-" + str(index), "attachment; filename*=UTF-8''" + quote(name, safe=""), False, "local-policy")
add("latin1-control", "attachment; filename*=ISO-8859-1''name%85.txt", False, "local-policy")
add("duplicate-fields", [["Content-Disposition", "inline"], ["content-disposition", "attachment"]], False)
add("identical-fields", [["Content-Disposition", "attachment"], ["Content-Disposition", "attachment"]], False)
for count in (128, 129):
    add("parameter-count-" + str(count), "attachment" + "".join("; p" + str(i) + "=v" for i in range(count)), count == 128, "limits")
for length in (8192, 8193):
    prefix = "attachment; x="
    value_length = length - len("Content-Disposition") - 4
    add("field-bytes-" + str(length), prefix + "a" * (value_length - len(prefix)), length == 8192, "limits")

assert len({case["name"] for case in cases}) == len(cases)
assert len({json.dumps(case["headers"]) for case in cases}) == len(cases)
parser = argparse.ArgumentParser()
parser.add_argument("--output", type=Path, default=Path(__file__).with_name("content_disposition_cases.json"))
args = parser.parse_args()
args.output.write_text(json.dumps({"version": 1, "scope": "HTTP response headers; filename policy is stricter than RFC syntax. MIME body-part fields are separate.", "cases": cases}, indent=2, ensure_ascii=True) + "\n")
print(json.dumps({"cases": len(cases), "accepted": sum(case["accepted"] for case in cases), "rejected": sum(not case["accepted"] for case in cases)}))
