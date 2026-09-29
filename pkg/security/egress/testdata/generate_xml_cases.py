"""XML admission fixtures derived from W3C grammar; no broker parser imports."""
import argparse
import base64
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("xml_response_cases.json"))
    output = parser.parse_args().output
    cases = []

    def add(name, document, accepted, category="grammar"):
        raw = document.encode("utf-8") if isinstance(document, str) else document
        cases.append({"name": name, "document_base64": base64.b64encode(raw).decode(), "accepted": accepted, "category": category})

    good = {
        "empty-root": "<r/>", "explicit-end": "<r></r>",
        "mixed-content": "<r>before<a/>after<b>nested</b></r>",
        "outer-misc": " \t\r\n<!--pre--><?pre data?><r/><?post?><!--end-->\r\n",
        "declaration": '<?xml version="1.0"?><r/>',
        "declaration-quotes": "<?xml\nversion = '1.0' encoding = 'uTf-8' standalone = 'yes' ?><r/>",
        "standalone-no": "<?xml version='1.0' standalone='no'?><r/>",
        "bom": "\ufeff<?xml version='1.0'?><r/>",
        "bom-content": "<r>\ufeff</r>",
        "attributes": "<r a = 'one' b=\"two\"\nthird='3'/>",
        "predefined-entities": "<r a='&amp;&lt;&gt;&quot;&apos;'>&amp;&lt;&gt;&quot;&apos;</r>",
        "character-references": "<r a='&#9;&#10;&#13;&#x20;'>&#x10FFFF;&#000065;&#x000041;</r>",
        "reference-once": "<r>&amp;missing;&amp;#x0;</r>",
        "cdata": "<r><![CDATA[<!DOCTYPE r> &missing; <x>]]></r>",
        "comment-literal": "<r><!-- <!DOCTYPE r> &missing; <x> --></r>",
        "pi-literal": "<r><?other <!DOCTYPE r> &missing; <x>?></r>",
        "stylesheet-pi": "<?xml-stylesheet href='https://example.invalid/style.xsl'?><r/>",
        "namespaces": "<p:r xmlns:p='urn:one' p:a='1'/>",
        "same-element-declaration": "<p:r p:a='1' xmlns:p='urn:one'/>",
        "namespace-unprefixed-attribute": "<r xmlns='urn:one' xmlns:p='urn:one' a='1' p:a='2'/>",
        "namespace-distinct-attributes": "<r xmlns:p='urn:one' xmlns:q='urn:two' p:a='1' q:a='2'/>",
        "namespace-restoration": "<r xmlns:p='urn:one'><p:a xmlns:p='urn:two'/><p:a/></r>",
        "default-undeclaration": "<r xmlns='urn:one'><a xmlns=''><b/></a><c/></r>",
        "xml-predefined": "<r xml:lang='en' xml:space='preserve'/>",
        "xml-explicit": "<r xmlns:xml='http://www.w3.org/XML/1998/namespace' xml:lang='en'/>",
        "namespace-exact-identity": "<r xmlns:p='urn:%78' xmlns:q='urn:x' p:a='1' q:a='2'/>",
        "unicode-name": "<漢字 é='yes'>é😀</漢字>",
        "unicode-combining-name": "<a\u0300 a\u00b7='v'/>",
        "case-sensitive-names": "<r A='1' a='2'/>",
        "comment-hyphen": "<!--a-b--><r/>",
        "nonascii-space-content": "<r>\u0085\u00a0\u2028</r>",
    }
    bad = {
        "empty": "", "whitespace-only": " \n", "no-root": "<!--only-->",
        "multiple-roots": "<r/><s/>", "text-before": "x<r/>", "text-after": "<r/>x",
        "reference-outside": "&#32;<r/>", "cdata-outside": "<![CDATA[ ]]><r/>",
        "cdata-after": "<r/><![CDATA[]]>", "unclosed-root": "<r>", "unmatched-end": "</r>",
        "mismatched-end": "<r></R>", "crossed-tags": "<r><s></r></s>",
        "end-attribute": "<r></r a='x'>", "end-empty": "<r></r/>",
        "empty-name": "</>", "digit-name": "<1r/>", "whitespace-start": "< r/>",
        "bare-attribute": "<r a/>", "unquoted-attribute": "<r a=x/>",
        "missing-attribute-separator": "<r a='1'b='2'/>", "duplicate-attribute": "<r a='1' a='2'/>",
        "literal-lt-attribute": "<r a='<'/>", "unclosed-attribute": "<r a='x/>",
        "unknown-entity": "<r>&missing;</r>", "unknown-attribute-entity": "<r a='&missing;'/>",
        "unfinished-entity": "<r>&amp</r>", "uppercase-entity": "<r>&AMP;</r>",
        "reference-no-digits": "<r>&#;</r>", "reference-no-hex": "<r>&#x;</r>",
        "reference-uppercase-x": "<r>&#X41;</r>", "reference-sign": "<r>&#+65;</r>",
        "reference-space": "<r>&# 65;</r>", "reference-overflow": "<r>&#x110000;</r>",
        "reference-null": "<r>&#0;</r>", "reference-surrogate": "<r>&#xD800;</r>",
        "reference-fffe": "<r>&#xFFFE;</r>", "reference-ffff": "<r>&#xFFFF;</r>",
        "text-cdata-close": "<r>]]></r>", "unfinished-cdata": "<r><![CDATA[x</r>",
        "bad-comment": "<!--a--b--><r/>", "trailing-comment-dash": "<!--a---><r/>",
        "unfinished-comment": "<r/><!--", "bad-directive": "<!THING r><r/>",
        "declaration-version": "<?xml version='1.1'?><r/>",
        "declaration-encoding": "<?xml version='1.0' encoding='UTF-16'?><r/>",
        "declaration-latin1": "<?xml version='1.0' encoding='ISO-8859-1'?><r/>",
        "declaration-missing-version": "<?xml encoding='UTF-8'?><r/>",
        "declaration-order": "<?xml encoding='UTF-8' version='1.0'?><r/>",
        "declaration-duplicate": "<?xml version='1.0' version='1.0'?><r/>",
        "declaration-extra": "<?xml version='1.0' extra='yes'?><r/>",
        "declaration-standalone": "<?xml version='1.0' standalone='true'?><r/>",
        "declaration-after-space": " <?xml version='1.0'?><r/>",
        "declaration-after-comment": "<!--pre--><?xml version='1.0'?><r/>",
        "declaration-inside": "<r><?xml version='1.0'?></r>",
        "declaration-second": "<?xml version='1.0'?><?xml version='1.0'?><r/>",
        "reserved-pi": "<?XML version='1.0'?><r/>", "pi-no-separator": "<?p=data?><r/>",
        "pi-colon": "<?p:q?><r/>", "unfinished-pi": "<r/><?p",
        "namespace-unbound-element": "<p:r/>", "namespace-unbound-attribute": "<r p:a='1'/>",
        "namespace-left-colon": "<:r/>", "namespace-right-colon": "<r:/>",
        "namespace-many-colons": "<p:r:s/>", "namespace-leading-digit": "<p:1 xmlns:p='urn:x'/>",
        "namespace-empty-prefix": "<r xmlns:p=''/>", "namespace-unbound-sibling": "<r><a xmlns:p='urn:x'/><p:b/></r>",
        "namespace-duplicate-binding": "<r xmlns:p='urn:x' xmlns:p='urn:y'/>",
        "namespace-expanded-duplicate": "<r xmlns:p='urn:x' xmlns:q='urn:x' p:a='1' q:a='2'/>",
        "namespace-reference-duplicate": "<r xmlns:p='urn:&#120;' xmlns:q='urn:x' p:a='1' q:a='2'/>",
        "namespace-xml-rebind": "<r xmlns:xml='urn:other'/>",
        "namespace-xml-other-prefix": "<r xmlns:p='http://www.w3.org/XML/1998/namespace'/>",
        "namespace-xml-default": "<r xmlns='http://www.w3.org/XML/1998/namespace'/>",
        "namespace-xmlns-prefix": "<r xmlns:xmlns='urn:x'/>",
        "namespace-xmlns-uri": "<r xmlns:p='http://www.w3.org/2000/xmlns/'/>",
        "namespace-xmlns-element": "<xmlns:r/>",
        "namespace-different-end-prefix": "<p:r xmlns:p='urn:x' xmlns:q='urn:x'></q:r>",
        "namespace-whitespace": "<r xmlns:p='urn:x y'/>",
        "doctype-empty": "<!DOCTYPE r><r/>",
        "doctype-external": "<!DOCTYPE r SYSTEM 'https://example.invalid/never-fetch'><r/>",
        "doctype-local-file": "<!DOCTYPE r [<!ENTITY e SYSTEM 'file:///nonexistent-ax-test'>]><r>&e;</r>",
        "doctype-entity-expansion": "<!DOCTYPE r [<!ENTITY a '123'><!ENTITY b '&a;&a;&a;'>]><r>&b;</r>",
        "doctype-parameter-entity": "<!DOCTYPE r [<!ENTITY % x SYSTEM 'https://example.invalid/never-fetch'>%x;]><r/>",
        "entity-outside-dtd": "<!ENTITY e 'x'><r/>",
    }
    for name, value in good.items(): add(name, value, True)
    for name, value in bad.items(): add(name, value, False)
    for c in (0, 1, 8, 11, 12, 14, 31, 0xFFFE, 0xFFFF):
        for layout in ("text", "comment", "pi", "attribute"):
            char = chr(c)
            value = {"text": f"<r>{char}</r>", "comment": f"<!--{char}--><r/>", "pi": f"<?p {char}?><r/>", "attribute": f"<r a='{char}'/>"}[layout]
            add(f"invalid-char-{c:x}-{layout}", value, False, "characters")
    # XML 1.0 Fifth Edition NameStartChar range boundaries, including characters
    # rejected by older-edition name tables in common runtime XML libraries.
    starts = [(0xC0,0xD6),(0xD8,0xF6),(0xF8,0x2FF),(0x370,0x37D),(0x37F,0x1FFF),
              (0x200C,0x200D),(0x2070,0x218F),(0x2C00,0x2FEF),(0x3001,0xD7FF),
              (0xF900,0xFDCF),(0xFDF0,0xFFFD),(0x10000,0xEFFFF)]
    for first,last in starts:
        for value in (first,last):
            char=chr(value)
            add(f"name-start-{value:x}", f"<{char} {char}='v'/>", True, "fifth-edition-names")
    for value in (0xB7,0xD7,0xF7,0x300,0x36F,0x37E,0x2000,0x200B,0x200E,0x206F,0x2190,0x2BFF,0x2FF0,0x3000,0xE000,0xF8FF,0xFDD0,0xFDEF,0xF0000):
        add(f"invalid-name-start-{value:x}", f"<{chr(value)}/>", False, "fifth-edition-names")
    add("depth-limit", "<r>"*64+"</r>"*64, True, "budget")
    add("depth-overflow", "<r>"*65+"</r>"*65, False, "budget")
    for count in (128,129):
        add(f"attribute-count-{count}", "<r"+"".join(f" a{i}='v'" for i in range(count))+"/>", count==128, "budget")
    for count in (1024,1025): add(f"name-bytes-{count}", "<"+"a"*count+"/>", count==1024, "budget")
    for count in (65536,65537): add(f"markup-bytes-{count}", "<r a='"+"a"*(count-9)+"'/>", count==65536, "budget")
    for count in (100000,100001): add(f"markup-units-{count}", "<r>"+"<a/>"*(count-2)+"</r>", count==100000, "budget")
    add("reference-length", "<r>&#"+"0"*27+"65;</r>", True, "budget")
    add("reference-length-overflow", "<r>&#"+"0"*28+"65;</r>", False, "budget")
    assert len({c['name'] for c in cases}) == len(cases)
    assert len({c['document_base64'] for c in cases}) == len(cases)
    output.write_text(json.dumps({"version":1, "cases":cases},indent=2)+"\n")
    print(f"{len(cases)} document cases: {sum(c['accepted'] for c in cases)} accepted, {sum(not c['accepted'] for c in cases)} denied")


if __name__ == '__main__':
    main()
