#!/usr/bin/env python3
"""
Extracts the examples of RFC 9901 (Selective Disclosure for JSON Web Tokens) into examples.json.

    python3 extract.py [rfc9901.txt]

The text rendering is downloaded from the RFC Editor when no path is given. The blocks of the examples are re-joined
across the line wrapping of the text rendering and otherwise untouched. The JWS JSON serialized SD-JWTs of section 8
are re-joined by removing all the whitespace of their blocks: the line wrapping cuts their strings, which contain
none. The only values computed here are checks of the extraction itself, and the "marked_claims" of each example:

  - every digest printed next to a Disclosure is the base64url SHA-256 of that Disclosure;
  - every "Contents" block equals the decoded Disclosure once the whitespace of the line wrapping is removed;
  - every presentation starts with the Issuer-signed JWT of its example;
  - every Disclosure of a JWS JSON serialized SD-JWT is referenced by an "_sd" digest of its payload;
  - "marked_claims" is the payload of the example processed with all its Disclosures, as RFC 9901 section 7.1
    describes, where each value that comes from a Disclosure is replaced by
    {"_selectively_disclosable": {"salt": <salt>, "value": <value>}}. It is the claim set an Issuer has to be given to
    produce the example: the processing is a second, independent implementation of the one under test.

See README.md for the copy of the RFC the committed file was produced from.
"""

import base64
import hashlib
import json
import os
import re
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
URL = "https://www.rfc-editor.org/rfc/rfc9901.txt"
MARKER = "_selectively_disclosable"

SECTIONS = {
    "section-5": ("5.1.  Issuance", "6.  Considerations on Nested Data in SD-JWTs"),
    "section-6.1": ("6.1.  Example: Flat SD-JWT", "6.2.  Example: Structured SD-JWT"),
    "section-6.2": ("6.2.  Example: Structured SD-JWT", "6.3.  Example: SD-JWT with Recursive Disclosures"),
    "section-6.3": ("6.3.  Example: SD-JWT with Recursive Disclosures", "7.  Verification and Processing"),
    "appendix-a.1": ("A.1.  Simple Structured SD-JWT", "A.2.  Complex Structured SD-JWT"),
    "appendix-a.2": ("A.2.  Complex Structured SD-JWT", "A.3.  SD-JWT-Based Verifiable Credentials (SD-JWT VC)"),
    "appendix-a.3": ("A.3.  SD-JWT-Based Verifiable Credentials (SD-JWT VC)", "A.4.  W3C Verifiable Credentials Data Model v2.0"),
    "appendix-a.4": ("A.4.  W3C Verifiable Credentials Data Model v2.0", "A.5.  Elliptic Curve Key Used in the Examples"),
}

JSON_CONTEXTS = [
    ("input JWT Claims Set", "claims"),
    ("following data about the user", "claims"),
    ("payload is used for the SD-JWT", "payload"),
    ("make the address claim contents", "payload"),
    ("treated as an object in the Disclosure", "payload"),
    ("permanently disclosed and hide only the other sub-claims", None),
    ("Key Binding JWT payload", "key_binding_payload"),
    ("payload of the corresponding Key Binding JWT", "key_binding_payload"),
    ("Processed SD-JWT Payload", "processed_payload"),
    ("Processed SD-", "processed_payload"),
]

TOKEN_CONTEXTS = [
    ("following Issuer-signed JWT", "issuer_signed_jwt"),
    ("produces the SD-JWT", "sd_jwt"),
    ("the issued SD-JWT", "sd_jwt"),
    ("presentation", "presentation"),
    ("SD-JWT+KB", "presentation"),
]

JSON_SERIALIZATION_SECTIONS = {
    "section-8.2": ("8.2.  Flattened JSON Serialization", "8.3.  General JSON Serialization"),
    "section-8.3": ("8.3.  General JSON Serialization", "8.4.  Verification of the JWS JSON Serialized SD-JWT"),
}

JSON_SERIALIZATION_CONTEXTS = [
    ("as issued", "sd_jwt"),
    ("SD-JWT+KB", "presentation"),
    ("a presentation", "presentation"),
]

PAGE_BREAK = re.compile(r"^(RFC 9901 |Fett, et al\. )|\f")


def b64url_decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def digest(disclosure):
    return base64.urlsafe_b64encode(hashlib.sha256(disclosure.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


def section_lines(lines, start, end):
    first = lines.index(start)
    last = lines.index(end, first + 1)
    return lines[first + 1:last]


def classify(context, table):
    for needle, key in table:
        if needle in context:
            return key
    raise ValueError("Unclassified block after: " + context)


def json_block(lines, i):
    """Collects a JSON value printed at an indentation of three spaces, up to its closing bracket."""
    opening = lines[i].strip()
    closing = "   " + ("}" if opening == "{" else "]")
    block = []
    while True:
        block.append(lines[i])
        if lines[i] == closing:
            return json.loads("\n".join(block)), i + 1
        i += 1


def json_serialization_block(lines, i):
    """Collects a JWS JSON serialized SD-JWT printed at an indentation of three spaces, skipping the page breaks."""
    block = []
    while True:
        if not PAGE_BREAK.search(lines[i]):
            block.append(lines[i])
        if lines[i] == "   }":
            return json.loads(re.sub(r"\s", "", "\n".join(block))), i + 1
        i += 1


def token_block(lines, i):
    """Collects a wrapped compact token: consecutive lines made of base64url characters, dots and tildes."""
    parts = []
    while i < len(lines) and re.fullmatch(r"   [A-Za-z0-9_\-.~]+", lines[i]):
        parts.append(lines[i].strip())
        i += 1
    return "".join(parts), i


def indented_block(lines, i, indent):
    """Collects the lines of a list item value, indented by at least the given number of spaces."""
    while lines[i] == "":
        i += 1
    block = []
    while i < len(lines) and (lines[i].startswith(" " * indent) or lines[i] == ""):
        if lines[i] == "" and (i + 1 >= len(lines) or not lines[i + 1].startswith(" " * indent)):
            break
        block.append(lines[i].strip())
        i += 1
    return block, i


def disclosure_item(lines, i, label):
    item = {"claim": label}
    while not lines[i].strip().startswith("-  SHA-256 Hash:"):
        i += 1
    block, i = indented_block(lines, i + 1, 9)
    item["digest"] = "".join(block)
    while not lines[i].strip().startswith("-  Disclosure:"):
        i += 1
    block, i = indented_block(lines, i + 1, 9)
    item["disclosure"] = "".join(block)
    while not lines[i].strip().startswith("-  Contents:"):
        i += 1
    block, i = indented_block(lines, i + 1, 9)
    printed = "".join(block)
    decoded = b64url_decode(item["disclosure"]).decode("utf-8")
    if re.sub(r"\s", "", printed) != re.sub(r"\s", "", decoded):
        raise ValueError("The contents of the Disclosure of " + str(label) + " do not match")
    if digest(item["disclosure"]) != item["digest"]:
        raise ValueError("The digest of the Disclosure of " + str(label) + " does not match")
    item["contents"] = decoded
    return item, i


def extract_section(lines):
    example = {}
    disclosures = []
    context = ""
    i = 0
    while i < len(lines):
        line = lines[i]
        item = re.fullmatch(r"   \*  (?:Claim (\S+)|(Array Entry)):", line)
        if item is not None:
            parsed, i = disclosure_item(lines, i + 1, item.group(1))
            disclosures.append(parsed)
            continue
        if line.startswith("   The following decoy digests are added:"):
            decoys = []
            i += 1
            while i < len(lines) and (lines[i] == "" or lines[i].startswith("   *  ")):
                if lines[i].startswith("   *  "):
                    decoys.append(lines[i][6:].strip())
                i += 1
            example["decoys"] = decoys
            continue
        if line in ("   {", "   ["):
            value, i = json_block(lines, i)
            key = classify(context, JSON_CONTEXTS)
            if key is not None and key not in example:
                example[key] = value
            continue
        if re.fullmatch(r"   eyJ[A-Za-z0-9_\-.~]+", line):
            value, i = token_block(lines, i)
            key = classify(context, TOKEN_CONTEXTS)
            example[key] = value
            continue
        if line.startswith("   ") and not line.startswith("    ") and line.strip() != "":
            paragraph = []
            while i < len(lines) and lines[i].strip() != "":
                paragraph.append(lines[i].strip())
                i += 1
            context = " ".join(paragraph)
            continue
        i += 1
    if disclosures:
        example["disclosures"] = disclosures
    return example


def extract_json_serialization(lines):
    example = {}
    context = ""
    i = 0
    while i < len(lines):
        line = lines[i]
        if line == "   {":
            value, i = json_serialization_block(lines, i)
            example[classify(context, JSON_SERIALIZATION_CONTEXTS)] = value
            continue
        if line.startswith("   ") and not line.startswith("    ") and line.strip() != "":
            paragraph = []
            while i < len(lines) and lines[i].strip() != "":
                paragraph.append(lines[i].strip())
                i += 1
            context = " ".join(paragraph)
            continue
        i += 1
    return example


def check_json_serialization(name, token):
    """Checks that every Disclosure of the first unprotected header is referenced by the payload."""
    signatures = token["signatures"] if "signatures" in token else [token]
    payload = json.loads(b64url_decode(token["payload"]))
    for disclosure in signatures[0]["header"]["disclosures"]:
        if digest(disclosure) not in payload["_sd"]:
            raise ValueError("A Disclosure of " + name + " is not referenced by its payload")


def marked(value, by_digest, used):
    """Processes a value of the payload with all the Disclosures, marking each value that comes from a Disclosure."""
    if isinstance(value, dict):
        result = {}
        for name, member in value.items():
            if name != "_sd":
                result[name] = marked(member, by_digest, used)
        for item in value.get("_sd", []):
            if item in by_digest:
                used.add(item)
                salt, name, member = json.loads(by_digest[item])
                result[name] = {MARKER: {"salt": salt, "value": marked(member, by_digest, used)}}
        return result
    if isinstance(value, list):
        result = []
        for element in value:
            if isinstance(element, dict) and list(element.keys()) == ["..."]:
                if element["..."] in by_digest:
                    used.add(element["..."])
                    salt, member = json.loads(by_digest[element["..."]])
                    result.append({MARKER: {"salt": salt, "value": marked(member, by_digest, used)}})
                continue
            result.append(marked(element, by_digest, used))
        return result
    return value


def main():
    if len(sys.argv) > 1:
        data = open(sys.argv[1], "rb").read()
    else:
        data = urllib.request.urlopen(URL).read()
    print("rfc9901.txt sha256", hashlib.sha256(data).hexdigest())
    lines = data.decode("utf-8-sig").splitlines()

    examples = {}
    for name, (start, end) in SECTIONS.items():
        example = extract_section(section_lines(lines, start, end))
        if "payload" in example and "disclosures" in example:
            by_digest = {item["digest"]: item["contents"] for item in example["disclosures"]}
            used = set()
            claims = dict(example["payload"])
            claims.pop("_sd_alg", None)
            example["marked_claims"] = marked(claims, by_digest, used)
            if used != set(by_digest):
                raise ValueError("Some Disclosures of " + name + " are not referenced by its payload")
        for token in ("sd_jwt", "presentation"):
            if token in example and "issuer_signed_jwt" in example:
                if not example[token].startswith(example["issuer_signed_jwt"] + "~"):
                    raise ValueError("The " + token + " of " + name + " does not start with its Issuer-signed JWT")
        examples[name] = example

    for name, (start, end) in JSON_SERIALIZATION_SECTIONS.items():
        example = extract_json_serialization(section_lines(lines, start, end))
        for token in example.values():
            check_json_serialization(name, token)
        examples[name] = example

    key_lines =section_lines(lines, "A.5.  Elliptic Curve Key Used in the Examples", "Appendix B.  Disclosure Format Considerations")
    start = key_lines.index("   {")
    examples["issuer_key"], _ = json_block(key_lines, start)

    with open(os.path.join(HERE, "examples.json"), "w", encoding="utf-8") as output:
        json.dump(examples, output, indent=4, ensure_ascii=False)
        output.write("\n")
    for name, example in examples.items():
        if name != "issuer_key":
            print(name, sorted(example.keys()), len(example.get("disclosures", [])), "disclosures")


if __name__ == "__main__":
    main()
