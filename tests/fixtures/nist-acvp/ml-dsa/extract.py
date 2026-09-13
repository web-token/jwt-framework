#!/usr/bin/env python3
"""
Extracts, from the NIST ACVP ML-DSA test vectors, the cases this library can be run against.

    python3 extract.py [ML-DSA-keyGen-FIPS204/internalProjection.json ML-DSA-sigGen-FIPS204/internalProjection.json]

The two files are downloaded from the usnistgov/ACVP-Server repository when no path is given. Nothing is
computed here; the selection is:

  keygen.json   ML-DSA-keyGen-FIPS204: the seed and the public key it expands to (ML-DSA.KeyGen_internal), the
                first KEYGEN_PER_SET cases of each parameter set. The expanded private key "sk" is dropped: RFC 9964
                represents a private key by its seed alone.
  siggen.json   ML-DSA-sigGen-FIPS204: the cases of the external interface (ML-DSA.Sign, FIPS 204 algorithm 2) in
                pure mode with an empty context string - the only mode RFC 9964 allows - as public key, message and
                signature. They are signature *generation* cases, whose signature this library verifies; the sigVer
                file of the same release has no pure-mode case with an empty context (every one carries a random
                context string, which openssl_verify() cannot be given), and is not used.

See README.md for the release the committed files were produced from.
"""

import hashlib
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/"
KEYGEN_PER_SET = 10


def load(path, name):
    if path is not None:
        data = open(path, "rb").read()
    else:
        data = urllib.request.urlopen(BASE + name + "/internalProjection.json").read()
    print(name, "sha256", hashlib.sha256(data).hexdigest())
    return json.loads(data)


def write(name, document):
    with open(os.path.join(HERE, name), "w") as handle:
        json.dump(document, handle, indent=1)
        handle.write("\n")
    print(name, "written")


def main():
    keygen_path = sys.argv[1] if len(sys.argv) > 2 else None
    siggen_path = sys.argv[2] if len(sys.argv) > 2 else None

    keygen = load(keygen_path, "ML-DSA-keyGen-FIPS204")
    write("keygen.json", {
        "source": "ML-DSA-keyGen-FIPS204/internalProjection.json",
        "vsId": keygen["vsId"],
        "testGroups": [
            {
                "tgId": group["tgId"],
                "parameterSet": group["parameterSet"],
                "tests": [
                    {"tcId": test["tcId"], "seed": test["seed"], "pk": test["pk"]}
                    for test in group["tests"][:KEYGEN_PER_SET]
                ],
            }
            for group in keygen["testGroups"]
        ],
    })

    siggen = load(siggen_path, "ML-DSA-sigGen-FIPS204")
    groups = []
    for group in siggen["testGroups"]:
        if group["signatureInterface"] != "external" or group["preHash"] != "pure":
            continue
        tests = [
            {"tcId": test["tcId"], "pk": test["pk"], "message": test["message"], "signature": test["signature"]}
            for test in group["tests"]
            if test["context"] == "" and test["hashAlg"] == "none"
        ]
        if tests:
            groups.append({
                "tgId": group["tgId"],
                "parameterSet": group["parameterSet"],
                "deterministic": group["deterministic"],
                "tests": tests,
            })
    write("siggen.json", {
        "source": "ML-DSA-sigGen-FIPS204/internalProjection.json",
        "vsId": siggen["vsId"],
        "selection": "signatureInterface external, preHash pure, hashAlg none, empty context",
        "testGroups": groups,
    })


if __name__ == "__main__":
    main()
