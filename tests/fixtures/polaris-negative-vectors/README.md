# Polaris negative vectors

The negative test vectors of [Polaris](https://github.com/EgorKhaklin/polaris-id) for SD-JWT VC presentations: 36
presentations, each with the verdict a correct Verifier reaches.

## `vectors.json`: the vectors, as published

Each vector but the controls is a control with exactly one thing changed, re-signed wherever the change needs it, so
the only reason to reject it is the clause it cites. `layer` names the rules that require the verdict, `class` how
directly they require it, and `clauses` the sentences cited. `settings` gives what the Verifier is configured with:
its time, its tolerance, the audience, the nonce and the Issuer keys. The keys and certificates are test keys derived
from public seeds: never trust them.

`PolarisNegativeVectorsTest` runs the two controls and the 15 vectors of the `jose` and `sd-jwt` layers. The other 19
judge what this library leaves to its caller, and are not run:

| Layer | Vectors | Left to |
|---|---|---|
| `sd-jwt-vc` | `disclosed-exp`, `disclosed-iss` | a Verifier of the SD-JWT VC profile, which keeps registered claims out of the Disclosures |
| `openid4vp` | `kb-aud-no-prefix` | a Verifier receiving presentations over OpenID4VP, which checks the Client Identifier prefix |
| `haip-x509` | 5 | the caller that validates the `x5c` chain |
| `x5c-issuer` | 3 | the caller that binds `iss` to the `x5c` leaf |
| `status-list` | 8, with the control `accept-status-list` | the caller that checks the Token Status List |

| | |
|---|---|
| Source | [`lab/interop/negative-vectors/vectors.json`](https://github.com/EgorKhaklin/polaris-id/blob/681fbacab07e90915d999d13033cb506d7871e8f/lab/interop/negative-vectors/vectors.json), version 0.3.1 |
| SHA-256 of the source | `57be7019119665bbc1515559090099df8f34a483b1e2b6da0a96396adf897073` |
| Extractor | None: the file is copied byte for byte, and the test checks its SHA-256 |
| Produced on | 2026-10-31 |

## Licence

`vectors.json` is not under the MIT licence of this repository. It is part of Polaris, Identity Token System,
Copyright 2026 Egor Khaklin, licensed under the Apache License, Version 2.0, whose text, as the Apache Software
Foundation publishes it, is in [`LICENSE`](LICENSE).
