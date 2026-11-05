# Threat model

This file steers the [OSS Scanner](https://github.com/anthropics/oss-scanner). Vulnerabilities found by other means
are reported as described in [SECURITY.md](../SECURITY.md).

## What this project does

A monorepo of six packages, each mirrored to a read-only repository (`.gitsplit.yml`):

- `src/Library` (`web-token/jwt-library`, namespace `Jose\Component`): JSON Object Signing and Encryption. JWS
  (RFC 7515), JWE (RFC 7516), JWK and JWK sets (RFC 7517), the algorithms of RFC 7518 and later RFCs (EdDSA, ML-DSA
  of RFC 9964), the header and claim checkers for JWT (RFC 7519), nested tokens, key factories, key analyzers and
  console commands.
- `src/Bundle` (`web-token/jwt-bundle`): the Symfony integration. Services built from the `jose` configuration, key
  and key set sources, the controller that publishes a key set, Symfony Serializer encoders, events and a profiler
  data collector.
- `src/SelectiveDisclosure` (`web-token/jwt-selective-disclosure`): SD-JWT (RFC 9901), with an issuer, a holder and a
  verifier that also checks key binding.
- `src/Rsa15` (`web-token/jwt-rsa15`): the `RSA1_5` key encryption algorithm, shipped apart.
- `src/Unsecured` (`web-token/jwt-unsecured`): the `none` signature algorithm, shipped apart.
- `src/Experimental` (`web-token/jwt-experimental`): algorithms that are not registered or not recommended (AES-CCM,
  AES-CTR key encryption, ChaCha20-Poly1305, RSA-OAEP-384 and 512, Brainpool curves, HS1, RS1, Blake2b, ...).

The application is the code that uses the framework: it issues tokens, or receives tokens and verifies or decrypts
them (OAuth 2.0 and OpenID Connect servers and clients, APIs that accept bearer tokens, wallets and verifiers).

## Where untrusted input enters

The attacker is anyone who can submit a token to the application, including the holder of a valid token who modifies
it, and anyone who can tell whether the application accepted or rejected a token. Everything a token carries is
untrusted:

- The serialized tokens given to `JWSLoader`, `JWELoader` and `NestedTokenLoader`, or unserialized by
  `JWSSerializerManager` and `JWESerializerManager` and then given to `JWSVerifier` and `JWEDecrypter`. The compact,
  JSON flattened and JSON general serializations are parsed by `src/Library/Signature/Serializer` and
  `src/Library/Encryption/Serializer`: protected and unprotected headers, payload, signatures, encrypted keys, IV,
  ciphertext, tag, AAD, and the number of signatures or recipients.
- The header parameters that drive the computation: `alg`, `enc`, `crit`, `b64`, and the key management parameters
  `epk`, `apu`, `apv`, `p2s`, `p2c`, `iv` and `tag`. The key related parameters (`kid`, `jwk`, `jku`, `x5u`, `x5c`,
  `x5t`) are only data: the library never selects or fetches a key from them. It tries the keys the application
  passes, one after the other.
- The SD-JWT presentations given to `SDJWTVerifier::verify()` and `verifyWithKeyBinding()`: the issuer-signed JWT,
  the disclosures and the key binding JWT. The holder key is read from the `cnf` claim of the issuer-signed JWT.
- The claims given to `ClaimCheckerManager`, which can hold any JSON type.
- The Symfony Serializer encoders of the bundle (`src/Bundle/Serializer`) only unserialize: a token decoded through
  them is not verified, and the application verifies it afterwards.

What is trusted:

- The configuration: the algorithms registered in the `AlgorithmManager` of each verifier, decrypter or loader, the
  header and claim checkers, and the bundle configuration (`jose.jws.loaders`, `jose.jwe.loaders`,
  `jose.checkers.headers`, `jose.checkers.claims`, `jose.selective_disclosure.verifiers`, ...). The algorithm manager
  is the list of allowed algorithms. Registering a weak or unsecured algorithm (`none`, `RSA1_5`, `HS1`, `RS1` or
  another experimental one) is the decision of the application.
- The keys and key sets the application passes, including their `alg`, `use` and `key_ops` members, which restrict
  how a key may be used. The URLs of the key sets loaded by `JKUFactory` and `X5UFactory`, or configured in
  `jose.key_sets.<name>.jku.url`, are chosen by the application.
- The clock given to the time based checkers.
- The issuer keys given to the SD-JWT verifier. The holder key in `cnf` is trusted only because the issuer signed it.

## Security properties that must hold

- A JWS is accepted only if one of the keys passed by the application verifies its signature, with an algorithm
  registered in the algorithm manager and read from the protected header. The unprotected header never changes the
  algorithm, the key or the signing input.
- `none` (`Jose\Unsecured\Signature\None`) is accepted only when the application registers it and passes a key of
  type `none`. Every algorithm checks the key type: no key of another type verifies an unsecured JWS, and an HMAC
  algorithm never takes an asymmetric key as its secret.
- A key is used only with the algorithm of its `alg` member and for the operations allowed by `use` and `key_ops`,
  when they are set (`KeyChecker`).
- A JWE is decrypted only with a key passed by the application and with algorithms registered in the decrypter. A
  change to the protected header, the AAD, the encrypted key, the IV, the ciphertext or the tag is rejected, and a
  rejected token reveals nothing beyond the rejection: no padding, tag length or key unwrap oracle, whether by result
  or by timing.
- With key agreement, the ephemeral public key `epk` is a point on the curve of the recipient key. A derived,
  unwrapped or decrypted CEK has the length the content encryption algorithm needs.
- The cost of processing one token is bounded whatever the attacker chooses: the PBES2 iteration count is capped
  (`PBES2AESKW::DEFAULT_MAX_COUNT`, adjustable through the constructor), and parsing is linear in the size of the
  token.
- When a `HeaderCheckerManager` runs, a header parameter checked by a checker whose `protectedHeaderOnly()` is true
  must be in the protected header, `crit` must be protected, and a token whose `crit` names a parameter that no
  checker checked is rejected. A header parameter may not appear in two header sets.
- When the claim is present, the claim checkers reject an expired or not yet valid token, a wrong audience or issuer,
  and a claim of an unexpected type; `ClaimCheckerManager::check()` rejects a missing mandatory claim.
- `NestedTokenLoader` accepts only a JWE whose `cty` is `JWT` (in any case), and verifies the inner JWS with the
  signature key set.
- SD-JWT: only disclosures whose digest the issuer signed are applied, each once; a disclosed claim never replaces a
  claim in clear; the hash algorithm is one the verifier accepts. With key binding, the key binding JWT is signed with
  a digital signature algorithm by the `cnf` key, has the type `kb+jwt`, is recent, and matches the expected audience,
  nonce and `sd_hash`.
- MACs, authentication tags, and the `sd_hash` and `nonce` of a key binding JWT are compared in constant time.

## Components that matter most

- The verification and decryption entry points: `JWSVerifier`, `JWSLoader`, `JWEDecrypter`, `JWELoader`,
  `NestedTokenLoader`, and their event dispatching decorators in `src/Bundle/Services`.
- The parsers of untrusted input: the JWS and JWE serializers, `Base64UrlSafe`, `JsonConverter` and
  `HeaderParameterChecker` (`src/Library/Core/Util`), `SDJWT` and `Disclosure`.
- The content encryption algorithms `AESCBCHS` and `AESGCM` (`src/Library/Encryption/Algorithm/ContentEncryption`)
  and the key management algorithms (`src/Library/Encryption/Algorithm/KeyEncryption`): `AESKW`, `AESGCMKW`,
  `PBES2AESKW`, `AbstractECDH` with `ConcatKDF`, `RSAOAEP` and `RSAOAEP256` with `RSACrypt`, and
  `Jose\Rsa15\KeyEncryption\RSA15`.
- The signature algorithms (`src/Library/Signature/Algorithm`): `ECDSA` with `ECSignature`, `RSAPKCS1`, `RSAPSS`,
  `HMAC`, `EdDSA` and `MLDSA`, with the key conversions they rely on (`ECKey`, `RSAKey`, `OKPKey`, `AKPKey` in
  `src/Library/Core/Util`) and the pure PHP elliptic curve code (`src/Library/Core/Util/Ecc`).
- The checkers (`src/Library/Checker`): `HeaderCheckerManager`, `ClaimCheckerManager` and the algorithm, type,
  audience, issuer and time checkers.
- SD-JWT (`src/SelectiveDisclosure`): `SDJWTVerifier` and `DisclosureProcessor`.
- Key selection: `KeyChecker`, `JWKSet::selectKey()`, `JWKSet::selectKeyByThumbprintUri()` and `JwkThumbprintUri`.

Less important but in scope: the experimental algorithms (`src/Experimental`), the key factories and loaders
(`JWKFactory`, `JKUFactory`, `X5UFactory`, `KeyConverter`), the key and key set analyzers, the bundle configuration
(`src/Bundle/DependencyInjection`), `JWKSetController`, the Symfony Serializer encoders and the environment variable
processor. Deprecated code paths are in scope as long as they ship.

## How to exercise it

The image has PHP 8.4 with OpenSSL 3.5 (ML-DSA is available), the dependencies installed in `vendor/`, and the QA
tools of the CI image on the `PATH`. Run the tests as the CI does, with `phpunit-11`; `vendor/bin/phpunit` and the
global `phpunit` are another major version and do not match the CI:

    composer exec -- phpunit-11 --configuration .ci-tools/phpunit.xml.dist
    composer exec -- phpunit-11 --configuration .ci-tools/phpunit.xml.dist --filter AlgorithmConfusionTest

- `tests/Component` drives the library through its public API (`Signature`, `Encryption`, `Checker`, `Core`,
  `KeyManagement`, `NestedToken`), with the RFC 7520 examples in `Signature/RFC7520` and `Encryption/RFC7520`.
  Regression tests of earlier fixes are there, such as `Signature/AlgorithmConfusionTest.php`,
  `Encryption/AuthenticationTagLengthTest.php`, `Encryption/InvalidCurveAttackTest.php`,
  `Encryption/RSA15ImplicitRejectionTest.php` and `Encryption/HeaderParameterConfusionTest.php`. A reproducer for the
  library goes there.
- `tests/SignatureAlgorithm` and `tests/EncryptionAlgorithm` test each algorithm, with test vectors in
  `tests/fixtures`.
- `tests/SelectiveDisclosure` covers SD-JWT, with the RFC 9901 examples and negative vectors
  (`tests/fixtures/rfc9901`, `tests/fixtures/polaris-negative-vectors`).
- `tests/Bundle/JoseFramework` boots a Symfony kernel (`AppKernel`, configuration in
  `tests/Bundle/JoseFramework/config/config_test.yml`) and uses the services built from the configuration;
  `Functional/` is organised by configuration section. A reproducer for the bundle goes there.
- The tests that load a key set from a URL use a mock HTTP client: the scan has no network access.

## How we rate severity

- Critical: forging a JWS, a JWE or SD-JWT claims that an application accepts while it registers only recommended
  algorithms, without holding any valid token or key (a signature or tag check that is skipped or always succeeds,
  `none` accepted without being registered); recovering a private or secret key; executing code or reading files
  through the processing of a token.
- High: a forgery or a disclosure of plaintext that needs a precondition the attacker can meet, such as holding one
  valid token or the application registering a given combination of algorithms; a check that the application
  configures and that does not run or can be skipped (header or claim checker, `crit`, mandatory claims, SD-JWT key
  binding); a single unauthenticated token that costs the server disproportionate CPU or memory.
- Medium: a decryption or padding oracle that needs many adaptive queries; private or secret key material,
  content encryption keys or plaintext in exception messages.
- Low: a weakness that needs a documented misconfiguration (a weak key that the analyzers flag, an algorithm the
  documentation advises against); an interoperability defect with no forgery or disclosure; a denial of service that
  needs sustained traffic; disclosure of non-sensitive internals.

A flaw in an algorithm that the application has to opt into from `web-token/jwt-experimental` or
`web-token/jwt-rsa15` is rated one level below the same flaw in a recommended algorithm.

For calibration, the published advisories were rated as follows:

- GHSA-jc38-x7x8-2xc8, `JWSVerifier` took `alg` from the unprotected header (algorithm confusion): high.
- GHSA-j265-mg9q-wpv9, AES-GCM accepted any tag length, so the holder of one JWE could forge others: high.
- GHSA-5pj7-wx9m-cjh6, the Concat KDF derived at most 256 bits, so `ECDH-ES` with `A256CBC-HS512` encrypted the
  content under an all-zero AES key: high.
- GHSA-3prj-6hqw-cm82, no upper bound on the PBES2 `p2c` iteration count: high.
- GHSA-5739-39v2-5754, `RSA1_5` decryption without implicit rejection (Bleichenbacher padding oracle): medium.
- GHSA-6vvh-pxr4-25r7, the experimental `Chacha20Poly1305` key encryption discarded its authentication tag: medium.

## Anything to leave alone

- Bugs in the dependencies (`spomky-labs/pki-framework`, `brick/math`, `spomky-labs/aes-key-wrap`, Symfony, the
  OpenSSL and sodium extensions of PHP, OpenSSL): they are separate projects.
- `tests/`, `performance/`, `.ci-tools/` and `castor.php`.
- The console commands (`src/Library/Console`) and the profiler data collector (`src/Bundle/DataCollector`), which
  run on the developer's machine with the developer's input.
- What an algorithm the application registered does by definition: no integrity with `none`, SHA-1 in `HS1` and
  `RS1`, the RSAES-PKCS1-v1_5 construction behind `RSA1_5`. A flaw in their implementation is in scope.
- Key selection from token headers (`kid`, `jku`, `x5u`, `x5c`, `jwk`) written by the application, and the choice of
  the algorithms, checkers and keys it passes.
- The hardening of RFC 8725 that the library offers as checkers to configure (`typ`, `aud`, `iss`, `exp`), unless a
  configured checker does not do its job.
- Compression: the `zip` header parameter has not been implemented since 4.0, and the library neither compresses nor
  decompresses.

## Reports

Include a reproducer written as a PHPUnit test in one of the directories above, the configuration it needs (the
algorithms registered, the checkers, the keys), and a patch against the scanned branch. The maintainers port the fix to
the maintained branches.
