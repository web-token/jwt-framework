# RFC 9964 fixtures

Vectors for the ML-DSA algorithms of [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html): `ML-DSA-44`,
`ML-DSA-65` and `ML-DSA-87`, over keys of the `AKP` type. The NIST ACVP vectors of FIPS 204 are under
[`../nist-acvp/ml-dsa/`](../nist-acvp/ml-dsa/).

## `appendix-a.json` — the JOSE examples of the RFC

Appendix A.1 of RFC 9964 prints, for each parameter set, a full key pair (the all-zero seed and the public key it
expands to) as a JWK whose `kid` is the RFC 7638 thumbprint of section 6, a JWS signed with it, and the raw bytes
signed. `appendix-a.json` is those three objects, re-joined across the line wrapping of the text rendering and
otherwise untouched: `priv` and `raw_*` are hexadecimal, `jwk` and `jws` are as printed, `raw_to_be_signed` is the
JWS signing input.

| | |
|---|---|
| Source | [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.txt), Appendix A.1 (December 2025) |
| Extractor | [`extract.py`](https://github.com/web-auth/cose-lib/blob/4.9.x/tests/fixtures/rfc9964/extract.py) of web-auth/cose-lib, whose `appendix-a.json` this file is the JOSE half of |
| Produced on | 2026-09-12 |

## `openssl-cli/` — vectors produced with the OpenSSL command line

`vectors.json` holds, for each parameter set, a key pair expanded by `openssl genpkey` from a fixed seed
(`-pkeyopt hexseed:…`), written as the seed-only PrivateKeyInfo of RFC 9881 that an AKP `priv` maps to, and a
signature over a fixed message made by `openssl pkeyutl -sign -rawin`. `ml-dsa-44-certificate.pem` is an X.509
certificate holding the ML-DSA-44 public key of the file, issued by a throw-away P-256 CA — the shape a classical CA
gives an ML-DSA leaf during a transition. No certificate *signed* with ML-DSA is included: spomky-labs/pki-framework
1.6 does not know the ML-DSA signature algorithm identifiers.

| | |
|---|---|
| Generator | [`openssl-cli/generate.sh`](openssl-cli/generate.sh), from web-auth/cose-lib |
| OpenSSL | 3.5.5 (27 Jan 2026), the default provider |
| Produced on | 2026-09-12 |
