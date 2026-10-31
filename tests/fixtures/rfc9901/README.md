# RFC 9901 fixtures

The examples of [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html), Selective Disclosure for JSON Web Tokens.

## `examples.json` — the examples of the RFC

One entry per example: section 5 (issuance and presentation), sections 6.1 to 6.3 (flat, structured and recursive
structures) and appendices A.1 to A.4, plus `issuer_key`, the public key of appendix A.5 that verifies every
Issuer-signed JWT. The private key is not printed by the RFC: the Issuer-signed JWTs and the Key Binding JWTs can be
verified, not re-created.

| Member | Content |
|---|---|
| `claims` | The input JWT Claims Set, as printed |
| `payload` | The payload of the Issuer-signed JWT, as printed |
| `disclosures` | For each Disclosure: the claim name (`null` for an array element), the printed digest, the Disclosure and its `contents`, the decoded Disclosure |
| `decoys` | The decoy digests of appendix A.1 |
| `issuer_signed_jwt`, `sd_jwt`, `presentation` | The tokens, re-joined across the line wrapping |
| `key_binding_payload` | The payload of the Key Binding JWT, when printed |
| `processed_payload` | The Processed SD-JWT Payload a Verifier gets from `presentation` |
| `marked_claims` | The claim set an Issuer is given to produce the example, see below |

`marked_claims` is the only computed member. It is the payload processed with all the Disclosures of the example, as
section 7.1 describes, where each value that comes from a Disclosure is replaced by
`{"_selectively_disclosable": {"salt": <salt>, "value": <value>}}`. The processing is done by the extractor, so the
claim set the tests give to the Issuer does not come from the code under test.

The `contents` member is the decoded Disclosure and not the printed one, because the line wrapping of the text
rendering cannot be undone unambiguously: `"123` / `Main St"` lost a space, `"6c5c0a49-b589-431d-` / `bae7-…"` did
not. The extractor checks that both are equal once all whitespace is removed, and that every printed digest is the
SHA-256 of its Disclosure.

| | |
|---|---|
| Source | [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.txt), sections 5 and 6, appendix A (November 2025) |
| SHA-256 of the source | `fd4cb79184162fa7ef95f4f63abab8ee6d03c9a04c19b8f83758946464b284eb` |
| Extractor | [`extract.py`](extract.py) |
| Produced on | 2026-10-30 |
