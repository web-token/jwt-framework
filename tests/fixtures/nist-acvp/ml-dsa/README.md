# NIST ACVP vectors for ML-DSA (FIPS 204)

A selection of the ML-DSA test vectors NIST publishes for the
[Automated Cryptographic Validation Program](https://github.com/usnistgov/ACVP-Server), taken from the
`gen-val/json-files/` directory of the usnistgov/ACVP-Server repository.

| | |
|---|---|
| Release | [v1.1.0.43](https://github.com/usnistgov/ACVP-Server/releases/tag/v1.1.0.43), commit `2972def23bf9f3680c2c531561ed9bdd0f1086ad` |
| `ML-DSA-keyGen-FIPS204/internalProjection.json` | SHA-256 `e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf` |
| `ML-DSA-sigGen-FIPS204/internalProjection.json` | SHA-256 `72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22` |
| Extractor | [`extract.py`](extract.py), in this directory |
| Produced on | 2026-09-12 |

- `keygen.json`: the seed and the public key it expands to (ML-DSA.KeyGen_internal, FIPS 204 algorithm 6), ten
  cases per parameter set. The expanded private key is dropped, since RFC 9964 represents a private key by its seed
  alone.
- `siggen.json`: every case of the *external* signature interface (ML-DSA.Sign, FIPS 204 algorithm 2) in *pure*
  mode with an *empty* context string — the only mode RFC 9964 allows — as public key, message and signature. They
  come from the signature generation file, whose signatures this library verifies; the sigVer file of the same
  release has no pure-mode case with an empty context, and `openssl_verify()` cannot be given one.

NIST-developed software and data are provided as a public service and are not subject to copyright protection
within the United States; the National Institute of Standards and Technology is acknowledged as the source. The
files here are a reformatted subset, produced on the date above.
