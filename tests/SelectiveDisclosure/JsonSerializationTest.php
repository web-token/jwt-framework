<?php

declare(strict_types=1);

namespace Jose\Tests\SelectiveDisclosure;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\InvalidSerializationException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JSONFlattenedSerializer;
use Jose\Component\Signature\Serializer\JSONGeneralSerializer;
use Jose\SelectiveDisclosure\Disclosable;
use Jose\SelectiveDisclosure\Disclosure;
use Jose\SelectiveDisclosure\IssuerSignature;
use Jose\SelectiveDisclosure\SDJWT;
use Jose\SelectiveDisclosure\SDJWTVerifier;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function array_map;
use function hash;
use function sort;
use function sprintf;

/**
 * The JWS JSON serialization of SD-JWTs, RFC 9901 section 8: the Issuer-signed JWT is a JWS in the flattened or the
 * general JSON serialization, the Disclosures and the Key Binding JWT are the "disclosures" and "kb_jwt" parameters of
 * the unprotected header of its first signature, and the "sd_hash" of the Key Binding JWT is computed over the compact
 * serialization of that signature.
 *
 * @internal
 */
final class JsonSerializationTest extends SelectiveDisclosureTestCase
{
    private const PROTECTED_HEADER = [
        'alg' => 'ES256',
        'typ' => 'example+sd-jwt',
    ];

    private const KEY_BINDING_HEADER = [
        'alg' => 'ES256',
        'typ' => 'kb+jwt',
    ];

    private static ?JWK $otherIssuerKey = null;

    #[Test]
    public function aFlattenedSdJwtIsParsedAndSerializedBack(): void
    {
        $disclosure = Disclosure::forObjectProperty('given_name', 'John');
        $issuerSignedJwt = self::signJson(self::payload($disclosure), [[self::issuerKey(), self::PROTECTED_HEADER, [
            'kid' => 'issuer-key-1',
        ]]]);
        $token = self::jsonToken($issuerSignedJwt, [$disclosure->toString()]);

        $sdJwt = SDJWT::fromString($token);

        static::assertSame(JSONFlattenedSerializer::NAME, $sdJwt->getSerialization());
        static::assertSame([$disclosure->toString()], self::encoded($sdJwt->getDisclosures()));
        static::assertFalse($sdJwt->hasKeyBinding());
        static::assertSame(
            self::canonical(JsonConverter::decode($issuerSignedJwt)),
            self::canonical(JsonConverter::decode($sdJwt->getIssuerSignedJwt()))
        );
        static::assertSame(
            self::canonical(JsonConverter::decode($token)),
            self::canonical(JsonConverter::decode($sdJwt->toString()))
        );
    }

    #[Test]
    public function aGeneralSdJwtIsParsedAndSerializedBack(): void
    {
        $disclosure = Disclosure::forObjectProperty('given_name', 'John');
        $issuerSignedJwt = self::signJson(self::payload($disclosure), [
            [self::issuerKey(), self::PROTECTED_HEADER, [
                'kid' => 'issuer-key-1',
            ]],
            [self::otherIssuerKey(), [
                'alg' => 'ES384',
                'typ' => 'example+sd-jwt',
            ], [
                'kid' => 'issuer-key-2',
            ]],
        ]);
        $keyBindingJwt = self::sign([], self::KEY_BINDING_HEADER, self::holderKey());
        $token = self::jsonToken($issuerSignedJwt, [$disclosure->toString()], $keyBindingJwt);

        $sdJwt = SDJWT::fromString($token);

        static::assertSame(JSONGeneralSerializer::NAME, $sdJwt->getSerialization());
        static::assertSame([$disclosure->toString()], self::encoded($sdJwt->getDisclosures()));
        static::assertSame($keyBindingJwt, $sdJwt->getKeyBindingJwt());
        static::assertSame(
            self::canonical(JsonConverter::decode($issuerSignedJwt)),
            self::canonical(JsonConverter::decode($sdJwt->getIssuerSignedJwt()))
        );
        static::assertSame(
            self::canonical(JsonConverter::decode($token)),
            self::canonical(JsonConverter::decode($sdJwt->toString()))
        );
    }

    #[Test]
    public function aGeneralSdJwtMayHaveASingleSignature(): void
    {
        $issuerSignedJwt = self::signJson(self::payload(), general: true);

        $sdJwt = SDJWT::fromString(self::jsonToken($issuerSignedJwt));

        static::assertSame(JSONGeneralSerializer::NAME, $sdJwt->getSerialization());
        static::assertCount(1, JsonConverter::decode($sdJwt->toString())['signatures']);
    }

    #[Test]
    public function theSerializationOfACompactSdJwtIsTheCompactOne(): void
    {
        static::assertSame(CompactSerializer::NAME, SDJWT::fromString(self::token(self::sign([])))->getSerialization());
        static::assertSame(CompactSerializer::NAME, SDJWT::create(self::sign([]))->getSerialization());
    }

    /**
     * Section 8.1: the digest is computed over the SD-JWT in the compact serialization, built from the protected
     * header, the payload and the signature of the first signature.
     */
    #[Test]
    public function theSdHashIsComputedOverTheCompactSerializationOfTheFirstSignature(): void
    {
        $disclosure = Disclosure::forObjectProperty('given_name', 'John');
        $issuerSignedJwt = self::signJson(self::payload($disclosure), [
            [self::issuerKey(), self::PROTECTED_HEADER, []],
            [self::otherIssuerKey(), [
                'alg' => 'ES384',
            ], []],
        ]);
        $jws = JsonConverter::decode($issuerSignedJwt);
        $compact = $jws['signatures'][0]['protected'] . '.' . $jws['payload'] . '.' . $jws['signatures'][0]['signature'];

        $sdJwt = SDJWT::fromString(self::jsonToken($issuerSignedJwt, [$disclosure->toString()]));

        static::assertSame(
            Base64UrlSafe::encodeUnpadded(hash('sha256', $compact . '~' . $disclosure->toString() . '~', true)),
            $sdJwt->getSdHash()
        );
    }

    #[Test]
    public function aFlattenedSdJwtHasTheSdHashOfItsCompactSerialization(): void
    {
        $disclosure = Disclosure::forObjectProperty('given_name', 'John');
        $issuerSignedJwt = self::signJson(self::payload($disclosure));
        $jws = JsonConverter::decode($issuerSignedJwt);
        $compact = self::token(
            $jws['protected'] . '.' . $jws['payload'] . '.' . $jws['signature'],
            [$disclosure->toString()]
        );

        static::assertSame(
            SDJWT::fromString($compact)->getSdHash(),
            SDJWT::fromString(self::jsonToken($issuerSignedJwt, [$disclosure->toString()]))->getSdHash()
        );
    }

    #[Test]
    public function theJsonObjectMayBePrecededByWhiteSpace(): void
    {
        $issuerSignedJwt = self::signJson(self::payload());

        static::assertSame(
            JSONFlattenedSerializer::NAME,
            SDJWT::fromString(" \t\r\n" . self::jsonToken($issuerSignedJwt))->getSerialization()
        );
        static::assertSame(JSONFlattenedSerializer::NAME, SDJWT::create("\n" . $issuerSignedJwt)->getSerialization());
    }

    /**
     * Without "disclosures" header parameter, the SD-JWT has no Disclosure; the parameter is always written.
     */
    #[Test]
    public function anSdJwtWithoutDisclosuresParameterHasNoDisclosure(): void
    {
        $sdJwt = SDJWT::fromString(self::signJson(self::payload()));

        static::assertSame([], $sdJwt->getDisclosures());
        static::assertFalse($sdJwt->hasKeyBinding());
        static::assertSame([], JsonConverter::decode($sdJwt->toString())['header']['disclosures']);
    }

    #[Test]
    #[DataProvider('malformedJsonSdJwts')]
    public function aMalformedJsonSdJwtIsRejected(string $token, string $message): void
    {
        $this->expectException(InvalidSerializationException::class);
        $this->expectExceptionMessage($message);

        SDJWT::fromString($token);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function malformedJsonSdJwts(): iterable
    {
        $payload = '"payload":"eyJzdWIiOiJ1c2VyXzQyIn0"';
        $protected = '"protected":"eyJhbGciOiJFUzI1NiJ9"';
        $signature = '"signature":"c2lnbmF0dXJl"';
        $flattened = static fn (string $header): string => '{' . $payload . ',' . $protected . ',"header":' . $header . ',' . $signature . '}';
        $general = static fn (string $header): string => '{' . $payload . ',"signatures":[{' . $protected . ',' . $signature . '},{' . $protected . ',"header":' . $header . ',' . $signature . '}]}';
        $members = 'The JWS JSON serialization must have either a "signatures" member or a "signature" member.';
        $signatures = 'The "signatures" member must be a non-empty list of JSON objects.';
        $disclosures = 'The "disclosures" header parameter must be an array of strings.';
        $keyBindingJwt = 'The Key Binding JWT must be a JWS in compact serialization.';
        yield 'invalid JSON' => ['{' . $payload, 'The JWS JSON serialization must be a JSON object.'];
        yield 'neither signatures nor signature' => ['{' . $payload . ',' . $protected . '}', $members];
        yield 'both signatures and signature' => ['{' . $payload . ',' . $protected . ',' . $signature . ',"signatures":[{' . $protected . ',' . $signature . '}]}', $members];
        yield 'no payload' => ['{' . $protected . ',' . $signature . '}', 'The "payload" member must be a non-empty base64url string.'];
        yield 'empty payload' => ['{"payload":"",' . $protected . ',' . $signature . '}', 'The "payload" member must be a non-empty base64url string.'];
        yield 'payload that is not a string' => ['{"payload":1,' . $protected . ',' . $signature . '}', 'The "payload" member must be a non-empty base64url string.'];
        yield 'padded payload' => ['{"payload":"e30=",' . $protected . ',' . $signature . '}', 'The "payload" member must be a non-empty base64url string.'];
        yield 'signatures that are an object' => ['{' . $payload . ',"signatures":{"first":{' . $protected . ',' . $signature . '}}}', $signatures];
        yield 'no signature in the list' => ['{' . $payload . ',"signatures":[]}', $signatures];
        yield 'a signature that is a string' => ['{' . $payload . ',"signatures":["c2lnbmF0dXJl"]}', $signatures];
        yield 'a signature that is a list' => ['{' . $payload . ',"signatures":[["c2lnbmF0dXJl"]]}', $signatures];
        yield 'no protected header' => ['{' . $payload . ',' . $signature . '}', 'The "protected" member must be a non-empty base64url string.'];
        yield 'a protected header that is not base64url' => ['{' . $payload . ',"protected":"{}",' . $signature . '}', 'The "protected" member must be a non-empty base64url string.'];
        yield 'an empty signature' => ['{' . $payload . ',' . $protected . ',"signature":""}', 'The "signature" member must be a non-empty base64url string.'];
        yield 'no signature in a signature object' => ['{' . $payload . ',"signatures":[{' . $protected . '}]}', 'The "signature" member must be a non-empty base64url string.'];
        yield 'a header that is a string' => [$flattened('"kid"'), 'The "header" member must be a JSON object.'];
        yield 'a header that is a list' => [$flattened('["kid"]'), 'The "header" member must be a JSON object.'];
        yield 'a null header' => [$flattened('null'), 'The "header" member must be a JSON object.'];
        yield 'null Disclosures' => [$flattened('{"disclosures":null}'), $disclosures];
        yield 'Disclosures that are a string' => [$flattened('{"disclosures":"WyJzYWx0IiwgInN1YiIsICJ1c2VyIl0"}'), $disclosures];
        yield 'Disclosures that are an object' => [$flattened('{"disclosures":{"sub":"WyJzYWx0IiwgInN1YiIsICJ1c2VyIl0"}}'), $disclosures];
        yield 'a Disclosure that is not a string' => [$flattened('{"disclosures":[1]}'), $disclosures];
        yield 'a malformed Disclosure' => [$flattened('{"disclosures":["W10"]}'), 'The Disclosure must be a JSON array of two or three elements.'];
        yield 'an empty Disclosure' => [$flattened('{"disclosures":[""]}'), 'The Disclosure is not base64url encoded.'];
        yield 'a Key Binding JWT that is not a string' => [$flattened('{"kb_jwt":1}'), $keyBindingJwt];
        yield 'a null Key Binding JWT' => [$flattened('{"kb_jwt":null}'), $keyBindingJwt];
        yield 'a malformed Key Binding JWT' => [$flattened('{"kb_jwt":"abc"}'), $keyBindingJwt];
        yield 'Disclosures in the header of the second signature' => [$general('{"disclosures":[]}'), 'The "disclosures" header parameter is only allowed in the header of the first signature.'];
        yield 'a Key Binding JWT in the header of the second signature' => [$general('{"kb_jwt":"a.b.c"}'), 'The "kb_jwt" header parameter is only allowed in the header of the first signature.'];
    }

    #[Test]
    public function aJsonIssuerSignedJwtMakesAJsonSdJwt(): void
    {
        $disclosure = Disclosure::forObjectProperty('given_name', 'John');
        $issuerSignedJwt = self::signJson(self::payload($disclosure), [[self::issuerKey(), self::PROTECTED_HEADER, [
            'kid' => 'issuer-key-1',
        ]]]);
        $keyBindingJwt = self::sign([], self::KEY_BINDING_HEADER, self::holderKey());

        $sdJwt = SDJWT::create($issuerSignedJwt, [$disclosure], $keyBindingJwt);

        static::assertSame(JSONFlattenedSerializer::NAME, $sdJwt->getSerialization());
        static::assertSame(
            self::canonical(JsonConverter::decode(self::jsonToken(
                $issuerSignedJwt,
                [$disclosure->toString()],
                $keyBindingJwt
            ))),
            self::canonical(JsonConverter::decode($sdJwt->toString()))
        );
    }

    #[Test]
    #[DataProvider('headerParametersOfTheSdJwt')]
    public function theIssuerSignedJwtOfANewSdJwtCannotHaveTheHeaderParametersOfTheSdJwt(
        string $parameter,
        mixed $value
    ): void {
        $this->expectException(InvalidSerializationException::class);
        $this->expectExceptionMessage(sprintf('The Issuer-signed JWT cannot have a "%s" header parameter.', $parameter));

        SDJWT::create(self::signJson(self::payload(), [[self::issuerKey(), self::PROTECTED_HEADER, [
            $parameter => $value,
        ]]]));
    }

    /**
     * @return iterable<string, array{string, mixed}>
     */
    public static function headerParametersOfTheSdJwt(): iterable
    {
        yield 'disclosures' => ['disclosures', []];
        yield 'kb_jwt' => ['kb_jwt', 'eyJhbGciOiJFUzI1NiJ9.e30.c2lnbmF0dXJl'];
    }

    #[Test]
    public function theJsonIssuerSignedJwtOfANewSdJwtIsChecked(): void
    {
        $this->expectException(InvalidSerializationException::class);
        $this->expectExceptionMessage('The "signature" member must be a non-empty base64url string.');

        SDJWT::create('{"payload":"e30","protected":"eyJhbGciOiJFUzI1NiJ9","signature":""}');
    }

    #[Test]
    public function theSelectionAndTheKeyBindingKeepTheSerializationAndTheOtherSignatures(): void
    {
        $givenName = Disclosure::forObjectProperty('given_name', 'John');
        $familyName = Disclosure::forObjectProperty('family_name', 'Doe');
        $issuerSignedJwt = self::signJson(self::payload($givenName, $familyName), [
            [self::issuerKey(), self::PROTECTED_HEADER, [
                'kid' => 'issuer-key-1',
            ]],
            [self::otherIssuerKey(), [
                'alg' => 'ES384',
                'typ' => 'example+sd-jwt',
            ], [
                'kid' => 'issuer-key-2',
            ]],
        ]);
        $keyBindingJwt = self::sign([], self::KEY_BINDING_HEADER, self::holderKey());
        $sdJwt = SDJWT::fromString(self::jsonToken(
            $issuerSignedJwt,
            [$givenName->toString(), $familyName->toString()]
        ));

        $selected = $sdJwt->select(['given_name']);
        $bound = $selected->withKeyBindingJwt($keyBindingJwt);

        static::assertSame(JSONGeneralSerializer::NAME, $selected->getSerialization());
        static::assertSame(JSONGeneralSerializer::NAME, $bound->getSerialization());
        static::assertSame($sdJwt->getIssuerSignedJwt(), $bound->getIssuerSignedJwt());
        static::assertSame(
            self::canonical(JsonConverter::decode(self::jsonToken(
                $issuerSignedJwt,
                [$givenName->toString()],
                $keyBindingJwt
            ))),
            self::canonical(JsonConverter::decode($bound->toString()))
        );
        static::assertSame($selected->toString(), $bound->withoutKeyBinding()->toString());
    }

    #[Test]
    public function theIssuerSignsTheSdJwtInTheFlattenedSerializationWithOneSignature(): void
    {
        $claims = [
            'iss' => 'https://issuer.example.com',
            'given_name' => new Disclosable('John', '2GLC42sKQveCfGfryNRN9w'),
        ];

        $sdJwt = self::issuer()->issueJson($claims, new IssuerSignature(self::issuerKey(), self::PROTECTED_HEADER, [
            'kid' => 'issuer-key-1',
        ]));

        static::assertSame(JSONFlattenedSerializer::NAME, $sdJwt->getSerialization());
        static::assertSame(self::canonical([
            'kid' => 'issuer-key-1',
            'disclosures' => self::encoded($sdJwt->getDisclosures()),
        ]), self::canonical(JsonConverter::decode($sdJwt->toString())['header']));
        static::assertSame(
            self::payloadOf(self::issuer()->issue($claims, self::issuerKey(), self::PROTECTED_HEADER)),
            self::payloadOf($sdJwt)
        );
        static::assertSame(
            'John',
            self::verifier(jsonSerializations: true)->verify($sdJwt->toString(), self::issuerKey())
                ->getClaims()['given_name']
        );
    }

    #[Test]
    public function theIssuerSignsTheSdJwtInTheGeneralSerializationWithSeveralSignatures(): void
    {
        $sdJwt = self::issuer()->issueJson(
            [
                'given_name' => new Disclosable('John'),
            ],
            new IssuerSignature(self::issuerKey(), self::PROTECTED_HEADER, [
                'kid' => 'issuer-key-1',
            ]),
            new IssuerSignature(self::otherIssuerKey(), [
                'alg' => 'ES384',
                'typ' => 'example+sd-jwt',
            ], [
                'kid' => 'issuer-key-2',
            ])
        );

        $token = JsonConverter::decode($sdJwt->toString());
        $verifier = self::verifier(jsonSerializations: true);
        static::assertSame(JSONGeneralSerializer::NAME, $sdJwt->getSerialization());
        static::assertCount(2, $token['signatures']);
        static::assertSame(self::canonical([
            'kid' => 'issuer-key-1',
            'disclosures' => self::encoded($sdJwt->getDisclosures()),
        ]), self::canonical($token['signatures'][0]['header']));
        static::assertSame([
            'kid' => 'issuer-key-2',
        ], $token['signatures'][1]['header']);
        static::assertSame(
            self::issuerKey()->all(),
            $verifier->verify($sdJwt->toString(), self::issuerKey())->getIssuerKey()->all()
        );
        static::assertSame(
            self::otherIssuerKey()->all(),
            $verifier->verify($sdJwt->toString(), self::otherIssuerKey())->getIssuerKey()->all()
        );
    }

    #[Test]
    public function aSignatureOfTheIssuerWithoutUnprotectedHeaderOnlyCarriesTheDisclosures(): void
    {
        $key = self::issuerKey();
        $signature = new IssuerSignature($key, self::PROTECTED_HEADER);

        $sdJwt = self::issuer()->issueJson([
            'given_name' => new Disclosable('John'),
        ], $signature);

        static::assertSame($key, $signature->getKey());
        static::assertSame(self::PROTECTED_HEADER, $signature->getProtectedHeader());
        static::assertSame([], $signature->getHeader());
        static::assertSame([
            'disclosures' => self::encoded($sdJwt->getDisclosures()),
        ], JsonConverter::decode($sdJwt->toString())['header']);
    }

    #[Test]
    public function everySignatureOfTheIssuerMustNameASignatureAlgorithm(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'The Issuer-signed JWT must be signed: the "alg" header parameter must name a signature algorithm.'
        );

        self::issuer()->issueJson(
            [
                'sub' => 'user_42',
            ],
            new IssuerSignature(self::issuerKey(), self::PROTECTED_HEADER),
            new IssuerSignature((new JWKFactory())->oct(256), [
                'alg' => 'HS256',
            ])
        );
    }

    #[Test]
    #[DataProvider('headerParametersOfTheSdJwt')]
    public function theIssuerRefusesTheHeaderParametersOfTheSdJwt(string $parameter, mixed $value): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('The "%s" header parameter is reserved for the SD-JWT.', $parameter));

        self::issuer()->issueJson(
            [
                'sub' => 'user_42',
            ],
            new IssuerSignature(self::issuerKey(), self::PROTECTED_HEADER),
            new IssuerSignature(self::otherIssuerKey(), [
                'alg' => 'ES384',
            ], [
                $parameter => $value,
            ])
        );
    }

    #[Test]
    public function theClaimsAreCheckedAsInTheCompactSerialization(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'The claim "iss" cannot be selectively disclosable: the Verifier needs it to evaluate the SD-JWT.'
        );

        self::issuer()->issueJson([
            'iss' => new Disclosable('https://issuer.example.com'),
        ], new IssuerSignature(self::issuerKey(), self::PROTECTED_HEADER));
    }

    #[Test]
    public function theHolderPresentsAJsonSdJwtInItsSerialization(): void
    {
        $sdJwt = self::issuer()->issueJson([
            'given_name' => new Disclosable('John'),
            'family_name' => new Disclosable('Doe'),
            'cnf' => [
                'jwk' => self::holderKey()->toPublic()->all(),
            ],
        ], new IssuerSignature(self::issuerKey(), self::PROTECTED_HEADER));

        $presentation = self::holder()->present(
            $sdJwt->select(['given_name']),
            self::holderKey(),
            [
                'alg' => 'ES256',
            ],
            self::AUDIENCE,
            self::NONCE
        );

        $header = JsonConverter::decode($presentation->toString())['header'];
        $verified = self::verifier(jsonSerializations: true)->verifyWithKeyBinding(
            $presentation->toString(),
            self::issuerKey(),
            self::AUDIENCE,
            self::NONCE
        );
        static::assertSame(JSONFlattenedSerializer::NAME, $presentation->getSerialization());
        static::assertSame($presentation->getKeyBindingJwt(), $header['kb_jwt']);
        static::assertSame(self::encoded($presentation->getDisclosures()), $header['disclosures']);
        static::assertSame('John', $verified->getClaims()['given_name']);
        static::assertArrayNotHasKey('family_name', $verified->getClaims());
    }

    /**
     * The JWS loader of the Issuer-signed JWT decides which serializations are accepted.
     */
    #[Test]
    public function aVerifierThatOnlyReadsTheCompactSerializationRejectsAJsonSdJwt(): void
    {
        $token = self::jsonToken(self::signJson(self::payload()));

        self::assertRejected(
            'The Issuer-signed JWT cannot be verified.',
            static fn () => self::verifier()->verify($token, self::issuerKey())
        );
    }

    #[Test]
    public function aVerifierThatReadsTheJsonSerializationsStillVerifiesCompactSdJwts(): void
    {
        $sdJwt = self::issuer()->issue([
            'given_name' => new Disclosable('John'),
        ], self::issuerKey(), self::PROTECTED_HEADER);

        static::assertSame(
            'John',
            self::verifier(jsonSerializations: true)->verify($sdJwt->toString(), self::issuerKey())
                ->getClaims()['given_name']
        );
    }

    /**
     * As the JWS loader does, a general SD-JWT is accepted when one of its signatures is verified.
     */
    #[Test]
    public function aGeneralSdJwtIsVerifiedByAnyOfItsSignatures(): void
    {
        $token = self::jsonToken(self::signJson(self::payload(), [
            [(new JWKFactory())->ec('P-256'), self::PROTECTED_HEADER, [
                'kid' => 'unknown',
            ]],
            [self::issuerKey(), self::PROTECTED_HEADER, [
                'kid' => 'issuer',
            ]],
        ]));

        $verified = self::verifier(jsonSerializations: true)->verify($token, self::issuerKey());

        static::assertSame(self::issuerKey()->all(), $verified->getIssuerKey()->all());
        static::assertSame(2, $verified->getIssuerSignedJwt()->countSignatures());
    }

    /**
     * The algorithm that is checked is the one of the signature the loader verified, not the one of the first
     * signature.
     */
    #[Test]
    public function theVerifiedSignatureMustUseADigitalSignatureAlgorithm(): void
    {
        $key = (new JWKFactory())->oct(256);
        $token = self::jsonToken(self::signJson(self::payload(), [
            [self::issuerKey(), self::PROTECTED_HEADER, []],
            [$key, [
                'alg' => 'HS256',
                'typ' => 'example+sd-jwt',
            ], []],
        ]));
        $verifier = new SDJWTVerifier(self::jwsLoader(null, true), self::clock());

        self::assertRejected(
            'The Issuer-signed JWT must be signed with a digital signature algorithm.',
            static fn () => $verifier->verify($token, $key)
        );
    }

    #[Test]
    public function aSignatureVerifiedAfterAMacIsAccepted(): void
    {
        $token = self::jsonToken(self::signJson(self::payload(), [
            [(new JWKFactory())->oct(256), [
                'alg' => 'HS256',
                'typ' => 'example+sd-jwt',
            ], []],
            [self::issuerKey(), self::PROTECTED_HEADER, []],
        ]));
        $verifier = new SDJWTVerifier(self::jwsLoader(null, true), self::clock());

        static::assertSame(self::issuerKey()->all(), $verifier->verify($token, self::issuerKey())->getIssuerKey()->all());
    }

    /**
     * Section 8.1: the "sd_hash" covers the first signature, whichever signature the Verifier trusts.
     */
    #[Test]
    public function theKeyBindingJwtIsBoundToTheFirstSignatureEvenWhenAnotherOneIsVerified(): void
    {
        $disclosure = Disclosure::forObjectProperty('given_name', 'John');
        $issuerSignedJwt = self::signJson(self::payload($disclosure) + [
            'cnf' => [
                'jwk' => self::holderKey()->toPublic()->all(),
            ],
        ], [
            [(new JWKFactory())->ec('P-256'), self::PROTECTED_HEADER, []],
            [self::issuerKey(), self::PROTECTED_HEADER, []],
        ]);
        $presentation = self::holder()->present(
            SDJWT::fromString(self::jsonToken($issuerSignedJwt, [$disclosure->toString()])),
            self::holderKey(),
            [
                'alg' => 'ES256',
            ],
            self::AUDIENCE,
            self::NONCE
        )->toString();
        $modified = JsonConverter::decode($presentation);
        $modified['signatures'][0]['signature'] = 'c2lnbmF0dXJl';
        $verifier = self::verifier(jsonSerializations: true);

        static::assertSame(
            'John',
            $verifier->verifyWithKeyBinding($presentation, self::issuerKey(), self::AUDIENCE, self::NONCE)
                ->getClaims()['given_name']
        );
        self::assertRejected(
            'The Key Binding JWT is not bound to the SD-JWT.',
            static fn () => $verifier->verifyWithKeyBinding(
                JsonConverter::encode($modified),
                self::issuerKey(),
                self::AUDIENCE,
                self::NONCE
            )
        );
    }

    /**
     * A payload referencing the given Disclosures, without decoy digest.
     *
     * @return array<string, mixed>
     */
    private static function payload(Disclosure ...$disclosures): array
    {
        $digests = array_map(static fn (Disclosure $disclosure): string => $disclosure->digest(), $disclosures);
        sort($digests);
        $payload = [
            'iss' => 'https://issuer.example.com',
        ];
        if ($digests !== []) {
            $payload['_sd'] = $digests;
        }
        $payload['_sd_alg'] = 'sha-256';

        return $payload;
    }

    /**
     * @param list<Disclosure> $disclosures
     *
     * @return list<string>
     */
    private static function encoded(array $disclosures): array
    {
        return array_map(static fn (Disclosure $disclosure): string => $disclosure->toString(), $disclosures);
    }

    private static function otherIssuerKey(): JWK
    {
        self::$otherIssuerKey ??= (new JWKFactory())->ec('P-384');

        return self::$otherIssuerKey;
    }
}
