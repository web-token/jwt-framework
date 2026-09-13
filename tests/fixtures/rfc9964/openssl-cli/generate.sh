#!/usr/bin/env bash
#
# Produces, with the OpenSSL command line and independently of this library:
#
#   vectors.json                for each ML-DSA parameter set, a key pair expanded from a fixed seed and a signature
#                               over a fixed message
#   ml-dsa-44-certificate.pem   an X.509 certificate holding the ML-DSA-44 public key of vectors.json, issued by a
#                               throw-away P-256 CA: the shape a classical CA gives an ML-DSA leaf during a
#                               transition, and the one spomky-labs/pki-framework 1.6 can parse (it does not know
#                               the ML-DSA signature algorithms yet, so a certificate *signed* with ML-DSA is not
#                               produced here)
#
#     bash generate.sh
#
# Needs an openssl binary of 3.5 or later (ML-DSA in the default provider). ML-DSA signing is randomised by
# default, so re-running the script produces new signatures, and the certificate carries the date it was made;
# the keys come out byte for byte the same. See README.md for the version the committed files were produced with.

set -euo pipefail
cd "$(dirname "$0")"

MESSAGE="ML-DSA for COSE, RFC 9964: signed with the OpenSSL command line."
printf '%s' "$MESSAGE" > message.bin
trap 'rm -f message.bin seed.pem seed-44.pem pub.pem pub.der signature.bin ca.key ca.pem ca.srl leaf.csr' EXIT

echo '[' > vectors.json
first=1
for set in 44:1312:2420:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
           65:1952:3309:202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f \
           87:2592:4627:404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f; do
    IFS=: read -r name pub_length sig_length seed <<< "$set"
    algorithm="ML-DSA-$name"

    # The seed-only PrivateKeyInfo of RFC 9881 (the "seed [0]" choice), which is what an AKP "priv" maps to.
    openssl genpkey -algorithm "$algorithm" -pkeyopt "hexseed:$seed" \
        -provparam ml-dsa.output_formats=seed-only -out seed.pem
    [ "$name" = 44 ] && cp seed.pem seed-44.pem
    openssl pkey -in seed.pem -pubout -out pub.pem
    openssl pkey -pubin -in pub.pem -outform DER -out pub.der
    # The SubjectPublicKeyInfo is a fixed header - SEQUENCE, AlgorithmIdentifier, BIT STRING with no unused bit -
    # followed by the encoded public key: the last pub_length bytes are the key.
    pub=$(tail -c "$pub_length" pub.der | xxd -p | tr -d '\n')
    openssl pkeyutl -sign -inkey seed.pem -rawin -in message.bin -out signature.bin
    signature=$(xxd -p signature.bin | tr -d '\n')
    [ "$(stat -c %s signature.bin)" = "$sig_length" ] || { echo "unexpected signature size" >&2; exit 1; }
    openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in message.bin -sigfile signature.bin > /dev/null

    [ "$first" = 1 ] || echo ',' >> vectors.json
    first=0
    cat >> vectors.json <<JSON
 {
  "algorithm": "$algorithm",
  "seed_hex": "$seed",
  "private_key_pem": $(python3 -c 'import json,sys; print(json.dumps(open("seed.pem").read()))'),
  "public_key_pem": $(python3 -c 'import json,sys; print(json.dumps(open("pub.pem").read()))'),
  "pub_hex": "$pub",
  "message": $(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$MESSAGE"),
  "signature_hex": "$signature"
 }
JSON
    echo "$algorithm written"
done
echo ']' >> vectors.json

openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -subj "/CN=cose-lib test CA/O=cose-lib/C=FR" -days 36500 -out ca.pem
openssl req -new -key seed-44.pem -subj "/CN=cose-lib ML-DSA-44 test/O=cose-lib/C=FR" -out leaf.csr
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 36500 \
    -out ml-dsa-44-certificate.pem
echo "ml-dsa-44-certificate.pem written"
