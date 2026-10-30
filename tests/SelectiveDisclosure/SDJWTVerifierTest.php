<?php

declare(strict_types=1);

namespace Jose\Tests\SelectiveDisclosure;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\LogicException;
use Jose\Component\Core\Exception\UnsupportedAlgorithmException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\SelectiveDisclosure\Disclosure;
use Jose\SelectiveDisclosure\SDJWT;
use Jose\SelectiveDisclosure\SDJWTVerifier;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function array_slice;

/**
 * The verification of RFC 9901 sections 7.1 and 7.3. Every rejection is checked against an SD-JWT that is otherwise
 * valid and signed by the Issuer: the SD-JWT is rejected for the reason under test only.
 *
 * @internal
 */
final class SDJWTVerifierTest extends SelectiveDisclosureTestCase
{
    #[Test]
    public function aValidSdJwtIsVerified(): void
    {
        $givenName = Disclosure::forObjectProperty('given_name', 'John');
        $us = Disclosure::forArrayElement('US');
        $token = self::token(self::sign([
            '_sd' => [$givenName->digest(), self::decoy()],
            'sub' => 'user_42',
            'nationalities' => [[
                '...' => $us->digest(),
            ], [
                '...' => self::decoy(),
            ]],
            'address' => [
                '_sd' => [self::decoy()],
            ],
            '_sd_alg' => 'sha-256',
        ]), [$givenName->toString(), $us->toString()]);

        $verified = self::verifier()->verify($token, self::issuerKey()->toPublic());

        static::assertSame([
            'sub' => 'user_42',
            'nationalities' => ['US'],
            'address' => [],
            'given_name' => 'John',
        ], $verified->getClaims());
        static::assertFalse($verified->hasKeyBinding());
        static::assertNull($verified->getKeyBindingJwt());
        static::assertNull($verified->getHolderKey());
        static::assertSame($token, $verified->getSdJwt()->toString());
        static::assertSame(self::issuerKey()->toPublic()->all(), $verified->getIssuerKey()->all());
        static::assertSame('example+sd-jwt', $verified->getIssuerSignedJwt()->getSignature(0)->getProtectedHeaderParameter('typ'));
    }

    #[Test]
    public function theDefaultHashAlgorithmIsSha256(): void
    {
        $givenName = Disclosure::forObjectProperty('given_name', 'John');
        $token = self::token(self::sign([
            '_sd' => [$givenName->digest('sha-256')],
        ]), [$givenName->toString()]);

        static::assertSame([
            'given_name' => 'John',
        ], self::verifier()->verify($token, self::issuerKey())->getClaims());
    }

    /**
     * RFC 9901 section 7.1 step 5.
     */
    #[Test]
    public function aDisclosureThatIsNotReferencedIsRejected(): void
    {
        $givenName = Disclosure::forObjectProperty('given_name', 'John');
        $familyName = Disclosure::forObjectProperty('family_name', 'Doe');
        $token = self::token(self::sign([
            '_sd' => [$givenName->digest()],
        ]), [$givenName->toString(), $familyName->toString()]);

        self::assertRejected('A Disclosure is not referenced by the SD-JWT.', static fn () => self::verifier()->verify($token, self::issuerKey()));
    }

    /**
     * RFC 9901 section 4.2.6: a Disclosure that is only referenced by a Disclosure that is not presented connects to
     * nothing.
     */
    #[Test]
    public function aNestedDisclosureWithoutTheDisclosureThatContainsItIsRejected(): void
    {
        $example = self::example('appendix-a.3');
        $streetAddress = $example['disclosures'][3];
        static::assertSame('street_address', $streetAddress['claim']);
        $token = self::token(explode('~', (string) $example['sd_jwt'])[0], [$streetAddress['disclosure']]);

        self::assertRejected('A Disclosure is not referenced by the SD-JWT.', static fn () => self::verifier()->verify($token, self::rfcIssuerKey()));
    }

    #[Test]
    public function aDisclosurePresentedTwiceIsRejected(): void
    {
        $givenName = Disclosure::forObjectProperty('given_name', 'John');
        $token = self::token(self::sign([
            '_sd' => [$givenName->digest()],
        ]), [$givenName->toString(), $givenName->toString()]);

        self::assertRejected('A Disclosure is presented more than once.', static fn () => self::verifier()->verify($token, self::issuerKey()));
    }

    /**
     * RFC 9901 section 7.1 step 4: a digest is used once, whether it matches a Disclosure or not, and wherever it is.
     *
     * @param array<string, mixed> $payload
     * @param list<Disclosure> $disclosures
     */
    #[Test]
    #[DataProvider('duplicateDigests')]
    public function aDigestThatAppearsTwiceIsRejected(array $payload, array $disclosures, string $digest): void
    {
        $token = self::token(self::sign($payload), array_map(static fn (Disclosure $disclosure): string => $disclosure->toString(), $disclosures));

        self::assertRejected(
            'The digest "' . $digest . '" appears more than once in the SD-JWT.',
            static fn () => self::verifier()->verify($token, self::issuerKey())
        );
    }

    /**
     * @return iterable<string, array{array<string, mixed>, list<Disclosure>, string}>
     */
    public static function duplicateDigests(): iterable
    {
        $givenName = Disclosure::forObjectProperty('given_name', 'John');
        $us = Disclosure::forArrayElement('US');
        $decoy = self::decoy();
        yield 'in the same object' => [[
            '_sd' => [$givenName->digest(), $givenName->digest()],
        ], [$givenName], $givenName->digest()];
        yield 'in two objects' => [[
            '_sd' => [$givenName->digest()],
            'address' => [
                '_sd' => [$givenName->digest()],
            ],
        ], [$givenName], $givenName->digest()];
        yield 'in an object and in an array' => [[
            '_sd' => [$us->digest()],
            'nationalities' => [[
                '...' => $us->digest(),
            ]],
        ], [$us], $us->digest()];
        yield 'in the same array' => [[
            'nationalities' => [[
                '...' => $us->digest(),
            ], [
                '...' => $us->digest(),
            ]],
        ], [$us], $us->digest()];
        yield 'a decoy' => [[
            '_sd' => [$decoy, $decoy],
        ], [], $decoy];
        $inner = Disclosure::forObjectProperty('locality', 'Schulpforta');
        $address = Disclosure::forObjectProperty('address', [
            '_sd' => [$inner->digest()],
        ]);
        yield 'in the payload and in a Disclosure' => [[
            '_sd' => [$address->digest(), $inner->digest()],
        ], [$address, $inner], $inner->digest()];
    }

    /**
     * RFC 9901 section 7.1 step 3.c.ii.2: the Disclosures of the reserved claim names are refused when they are
     * parsed.
     */
    #[Test]
    #[DataProvider('reservedClaimNames')]
    public function aDisclosureOfAReservedClaimNameIsRejected(string $claimName): void
    {
        $disclosure = Base64UrlSafe::encodeUnpadded('["c2FsdA", "' . $claimName . '", "value"]');
        $token = self::token(self::sign([
            '_sd' => [Base64UrlSafe::encodeUnpadded(hash('sha256', $disclosure, true))],
        ]), [$disclosure]);

        self::assertRejected(
            'The claim name "' . $claimName . '" cannot be selectively disclosed.',
            static fn () => self::verifier()->verify($token, self::issuerKey())
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function reservedClaimNames(): iterable
    {
        yield '_sd' => ['_sd'];
        yield '...' => ['...'];
    }

    /**
     * RFC 9901 section 7.1 steps 3.c.ii.1 and 3.c.iii.1.
     */
    #[Test]
    public function theDisclosureOfAnArrayElementCannotDiscloseAnObjectProperty(): void
    {
        $us = Disclosure::forArrayElement('US');
        $token = self::token(self::sign([
            '_sd' => [$us->digest()],
        ]), [$us->toString()]);

        self::assertRejected('The Disclosure of an array element is referenced by an object.', static fn () => self::verifier()->verify($token, self::issuerKey()));
    }

    #[Test]
    public function theDisclosureOfAnObjectPropertyCannotDiscloseAnArrayElement(): void
    {
        $givenName = Disclosure::forObjectProperty('given_name', 'John');
        $token = self::token(self::sign([
            'names' => [[
                '...' => $givenName->digest(),
            ]],
        ]), [$givenName->toString()]);

        self::assertRejected('The Disclosure of an object property is referenced by an array.', static fn () => self::verifier()->verify($token, self::issuerKey()));
    }

    /**
     * RFC 9901 section 7.1 step 3.c.ii.3.
     */
    #[Test]
    public function aDisclosedClaimThatAlreadyExistsIsRejected(): void
    {
        $sub = Disclosure::forObjectProperty('sub', 'someone_else');
        $token = self::token(self::sign([
            '_sd' => [$sub->digest()],
            'sub' => 'user_42',
        ]), [$sub->toString()]);

        self::assertRejected('The disclosed claim "sub" already exists.', static fn () => self::verifier()->verify($token, self::issuerKey()));
    }

    #[Test]
    public function aClaimDisclosedTwiceAtTheSameLevelIsRejected(): void
    {
        $first = Disclosure::forObjectProperty('given_name', 'John');
        $second = Disclosure::forObjectProperty('given_name', 'Johnny');
        $token = self::token(self::sign([
            '_sd' => [$first->digest(), $second->digest()],
        ]), [$first->toString(), $second->toString()]);

        self::assertRejected('The disclosed claim "given_name" already exists.', static fn () => self::verifier()->verify($token, self::issuerKey()));
    }

    #[Test]
    public function aNumericClaimNameIsComparedAsAString(): void
    {
        $twelve = Disclosure::forObjectProperty('12', false);
        $token = self::token(self::sign([
            'age_equal_or_over' => [
                '_sd' => [$twelve->digest()],
                '12' => true,
            ],
        ]), [$twelve->toString()]);

        self::assertRejected('The disclosed claim "12" already exists.', static fn () => self::verifier()->verify($token, self::issuerKey()));
    }

    /**
     * RFC 9901 section 4.1, rule 7: "_sd" and "..." only convey digests.
     *
     * @param array<string, mixed> $payload
     */
    #[Test]
    #[DataProvider('misusedReservedClaims')]
    public function aReservedClaimThatDoesNotConveyDigestsIsRejected(array $payload, string $message): void
    {
        $token = self::token(self::sign($payload));

        self::assertRejected($message, static fn () => self::verifier()->verify($token, self::issuerKey()));
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function misusedReservedClaims(): iterable
    {
        $sd = 'The "_sd" member must be an array of digests.';
        yield '_sd is a string' => [[
            '_sd' => self::decoy(),
        ], $sd];
        yield '_sd contains a number' => [[
            '_sd' => [12],
        ], $sd];
        yield '_sd is an object' => [[
            '_sd' => [
                'digest' => self::decoy(),
            ],
        ], $sd];
        yield 'nested _sd is null' => [[
            'address' => [
                '_sd' => null,
            ],
        ], $sd];
        yield '... is a number' => [[
            'list' => [[
                '...' => 12,
            ]],
        ], 'The "..." member must be a digest.'];
        yield '... next to another member' => [[
            'list' => [[
                '...' => self::decoy(),
                'other' => 'value',
            ]],
        ], 'The claim name "..." is reserved.'];
        yield '... in an object' => [[
            'address' => [
                '...' => self::decoy(),
            ],
        ], 'The claim name "..." is reserved.'];
    }

    /**
     * RFC 9901 section 7.1 step 2.d.
     */
    #[Test]
    #[DataProvider('refusedHashAlgorithms')]
    public function aHashAlgorithmThatIsNotAcceptedIsRejected(mixed $hashAlgorithm, ?array $acceptedHashAlgorithms, string $message): void
    {
        $token = self::token(self::sign([
            '_sd_alg' => $hashAlgorithm,
        ]));

        self::assertRejected($message, static fn () => self::verifier(hashAlgorithms: $acceptedHashAlgorithms)->verify($token, self::issuerKey()));
    }

    /**
     * @return iterable<string, array{mixed, list<string>|null, string}>
     */
    public static function refusedHashAlgorithms(): iterable
    {
        yield 'unsupported' => ['md5', null, 'The hash algorithm "md5" of the SD-JWT is not accepted.'];
        yield 'PHP name' => ['sha256', null, 'The hash algorithm "sha256" of the SD-JWT is not accepted.'];
        yield 'not accepted by the Verifier' => ['sha-512', ['sha-256'], 'The hash algorithm "sha-512" of the SD-JWT is not accepted.'];
        yield 'not a string' => [256, null, 'The "_sd_alg" claim must be a string.'];
    }

    #[Test]
    public function theAcceptedHashAlgorithmsAreRestrictedByTheVerifier(): void
    {
        $givenName = Disclosure::forObjectProperty('given_name', 'John');
        $token = self::token(self::sign([
            '_sd' => [$givenName->digest('sha-512')],
            '_sd_alg' => 'sha-512',
        ]), [$givenName->toString()]);

        static::assertSame([
            'given_name' => 'John',
        ], self::verifier(hashAlgorithms: ['sha-512'])->verify($token, self::issuerKey())->getClaims());
    }

    #[Test]
    public function aVerifierCannotAcceptAnUnsupportedHashAlgorithm(): void
    {
        $this->expectException(UnsupportedAlgorithmException::class);
        $this->expectExceptionMessage('The hash algorithm "md5" is not supported.');

        self::verifier(hashAlgorithms: ['sha-256', 'md5']);
    }

    #[Test]
    public function theDigestsAreComputedWithTheDeclaredHashAlgorithm(): void
    {
        $givenName = Disclosure::forObjectProperty('given_name', 'John');
        $token = self::token(self::sign([
            '_sd' => [$givenName->digest('sha-512')],
        ]), [$givenName->toString()]);

        self::assertRejected('A Disclosure is not referenced by the SD-JWT.', static fn () => self::verifier()->verify($token, self::issuerKey()));
    }

    /**
     * RFC 9901 section 7.1 step 2.b.
     */
    #[Test]
    public function aTamperedIssuerSignedJwtIsRejected(): void
    {
        $givenName = Disclosure::forObjectProperty('given_name', 'John');
        [$header, , $signature] = explode('.', self::sign([
            '_sd' => [$givenName->digest()],
        ]));
        $payload = Base64UrlSafe::encodeUnpadded('{"_sd":["' . $givenName->digest() . '"],"admin":true}');
        $token = self::token($header . '.' . $payload . '.' . $signature, [$givenName->toString()]);

        self::assertRejected('The Issuer-signed JWT cannot be verified.', static fn () => self::verifier()->verify($token, self::issuerKey()));
    }

    #[Test]
    public function anIssuerSignedJwtSignedByAnotherKeyIsRejected(): void
    {
        $token = self::token(self::sign([
            'sub' => 'user_42',
        ], [
            'alg' => 'ES256',
            'typ' => 'example+sd-jwt',
        ], (new JWKFactory())->ec('P-256')));

        self::assertRejected('The Issuer-signed JWT cannot be verified.', static fn () => self::verifier()->verify($token, self::issuerKey()));
    }

    /**
     * RFC 9901 section 7.1 step 2.a: an unsecured JWT has an empty signature, which the combined format refuses.
     */
    #[Test]
    public function anUnsecuredIssuerSignedJwtIsRejected(): void
    {
        $token = Base64UrlSafe::encodeUnpadded('{"alg":"none"}') . '.' . Base64UrlSafe::encodeUnpadded('{"sub":"user_42"}') . '.~';

        self::assertRejected('The Issuer-signed JWT must be a JWS in compact serialization.', static fn () => self::verifier()->verify($token, self::issuerKey()));
    }

    /**
     * RFC 9901 section 4.1: the Issuer-signed JWT is signed with the private key of the Issuer, which a MAC computed
     * with a shared key does not prove, even when the loader accepts the MAC algorithm.
     */
    #[Test]
    public function anIssuerSignedJwtProtectedByAMacIsRejected(): void
    {
        $key = (new JWKFactory())->oct(256);
        $token = self::token(self::sign([
            'sub' => 'user_42',
        ], [
            'alg' => 'HS256',
            'typ' => 'example+sd-jwt',
        ], $key));
        $verifier = new SDJWTVerifier(self::jwsLoader(), self::clock());

        self::assertRejected('The Issuer-signed JWT must be signed with a digital signature algorithm.', static fn () => $verifier->verify($token, $key));
    }

    /**
     * RFC 9901 section 4.3: the "alg" of the Key Binding JWT names a digital signature algorithm.
     */
    #[Test]
    public function aKeyBindingJwtProtectedByAMacIsRejected(): void
    {
        $key = (new JWKFactory())->oct(256);
        $sdJwt = SDJWT::fromString(self::token(self::sign([
            'cnf' => [
                'jwk' => $key->all(),
            ],
        ])));
        $presentation = self::token($sdJwt->getIssuerSignedJwt(), [], self::keyBindingJwt($sdJwt, [], [
            'alg' => 'HS256',
            'typ' => 'kb+jwt',
        ], $key));

        self::assertRejected('The Key Binding JWT must be signed with a digital signature algorithm.', static fn () => self::verifier()->verifyWithKeyBinding($presentation, self::issuerKey(), self::AUDIENCE, self::NONCE));
    }

    #[Test]
    public function theHeaderCheckersOfTheIssuerSignedJwtLoaderAreApplied(): void
    {
        $token = self::token(self::sign([
            'sub' => 'user_42',
        ], [
            'alg' => 'ES256',
            'typ' => 'JWT',
        ]));

        self::assertRejected('Unsupported type.', static fn () => self::verifier()->verify($token, self::issuerKey()));
    }

    /**
     * RFC 9901 section 7.1 step 6, and section 9.7: the claims are checked once processed, so that a claim the Verifier
     * requires is missing when its Disclosure is not presented.
     */
    #[Test]
    public function theClaimsAreCheckedOnceProcessed(): void
    {
        $issuer = Disclosure::forObjectProperty('iss', 'https://issuer.example.com');
        $issuerSignedJwt = self::sign([
            '_sd' => [$issuer->digest()],
            'exp' => self::NOW + 60,
        ]);

        self::assertRejected(
            'The following claims are mandatory: iss.',
            static fn () => self::verifier(mandatoryClaims: ['iss'])->verify(self::token($issuerSignedJwt), self::issuerKey())
        );
        static::assertSame(
            'https://issuer.example.com',
            self::verifier(mandatoryClaims: ['iss'])->verify(self::token($issuerSignedJwt, [$issuer->toString()]), self::issuerKey())->getClaims()['iss']
        );
    }

    #[Test]
    public function anExpiredSdJwtIsRejected(): void
    {
        $exp = Disclosure::forObjectProperty('exp', self::NOW - 1);
        $token = self::token(self::sign([
            '_sd' => [$exp->digest()],
        ]), [$exp->toString()]);

        self::assertRejected('The token expired.', static fn () => self::verifier()->verify($token, self::issuerKey()));
    }

    /**
     * RFC 9901 section 4: a Verifier that expects an SD-JWT verifies that the last component is empty.
     */
    #[Test]
    public function anSdJwtWithKeyBindingIsRejectedWhenKeyBindingIsNotExpected(): void
    {
        self::assertRejected(
            'A Key Binding JWT is not expected.',
            static fn () => self::verifier()->verify(self::example('section-5')['presentation'], self::rfcIssuerKey())
        );
    }

    /**
     * RFC 9901 section 7.3 steps 1 and 2: whether Key Binding is required is decided by the Verifier, by calling
     * verifyWithKeyBinding(), and not by the presence of a Key Binding JWT.
     */
    #[Test]
    public function anSdJwtWithoutKeyBindingIsRejectedWhenKeyBindingIsRequired(): void
    {
        $presentation = SDJWT::fromString(self::example('section-5')['presentation'])->withoutKeyBinding()->toString();

        self::assertRejected(
            'A Key Binding JWT is required.',
            static fn () => self::verifier()->verifyWithKeyBinding($presentation, self::rfcIssuerKey(), self::AUDIENCE, self::NONCE)
        );
    }

    /**
     * RFC 9901 section 7.3 step 5.g: the Key Binding JWT covers the exact set of Disclosures it was created for.
     */
    #[Test]
    #[DataProvider('modifiedPresentations')]
    public function aKeyBindingJwtBoundToAnotherPresentationIsRejected(string $presentation): void
    {
        self::assertRejected(
            'The Key Binding JWT is not bound to the SD-JWT.',
            static fn () => self::verifier()->verifyWithKeyBinding($presentation, self::rfcIssuerKey(), self::AUDIENCE, self::NONCE)
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function modifiedPresentations(): iterable
    {
        $example = self::example('section-5');
        $presentation = SDJWT::fromString($example['presentation']);
        $disclosures = array_map(static fn (Disclosure $disclosure): string => $disclosure->toString(), $presentation->getDisclosures());
        $keyBindingJwt = (string) $presentation->getKeyBindingJwt();
        yield 'a Disclosure removed' => [self::token($presentation->getIssuerSignedJwt(), array_slice($disclosures, 1), $keyBindingJwt)];
        yield 'a Disclosure added' => [self::token($presentation->getIssuerSignedJwt(), [...$disclosures, $example['disclosures'][2]['disclosure']], $keyBindingJwt)];
        yield 'the Disclosures reordered' => [self::token($presentation->getIssuerSignedJwt(), array_reverse($disclosures), $keyBindingJwt)];
    }

    /**
     * RFC 9901 section 7.3 step 5.f.
     */
    #[Test]
    public function aKeyBindingJwtCreatedForAnotherVerifierIsRejected(): void
    {
        self::assertRejected(
            'The Key Binding JWT is not intended for this audience.',
            static fn () => self::verifier()->verifyWithKeyBinding(self::example('section-5')['presentation'], self::rfcIssuerKey(), 'https://other.example.org', self::NONCE)
        );
    }

    #[Test]
    public function aKeyBindingJwtCreatedForAnotherTransactionIsRejected(): void
    {
        self::assertRejected(
            'The nonce of the Key Binding JWT does not match.',
            static fn () => self::verifier()->verifyWithKeyBinding(self::example('section-5')['presentation'], self::rfcIssuerKey(), self::AUDIENCE, '0987654321')
        );
    }

    /**
     * RFC 9901 section 7.3 step 5.e.
     */
    #[Test]
    #[DataProvider('keyBindingTimes')]
    public function theCreationTimeOfTheKeyBindingJwtIsWithinTheAcceptedWindow(int $now, int $drift, ?string $message): void
    {
        $verification = static fn () => self::verifier($now, keyBindingMaxAge: 300, allowedTimeDrift: $drift)
            ->verifyWithKeyBinding(self::example('section-5')['presentation'], self::rfcIssuerKey(), self::AUDIENCE, self::NONCE);

        if ($message === null) {
            static::assertSame('user_42', $verification()->getClaims()['sub']);

            return;
        }
        self::assertRejected($message, $verification);
    }

    /**
     * @return iterable<string, array{int, int, string|null}>
     */
    public static function keyBindingTimes(): iterable
    {
        yield 'at creation' => [self::NOW, 0, null];
        yield 'at the end of the window' => [self::NOW + 300, 0, null];
        yield 'after the window' => [self::NOW + 301, 0, 'The Key Binding JWT is too old.'];
        yield 'after the window, within the drift' => [self::NOW + 305, 5, null];
        yield 'after the window and the drift' => [self::NOW + 306, 5, 'The Key Binding JWT is too old.'];
        yield 'before creation' => [self::NOW - 1, 0, 'The Key Binding JWT is issued in the future.'];
        yield 'before creation, within the drift' => [self::NOW - 5, 5, null];
        yield 'before creation and the drift' => [self::NOW - 6, 5, 'The Key Binding JWT is issued in the future.'];
    }

    /**
     * RFC 9901 section 7.3 step 5.d.
     *
     * @param array<string, mixed> $header
     */
    #[Test]
    #[DataProvider('keyBindingTypes')]
    public function theKeyBindingJwtIsExplicitlyTyped(array $header, bool $accepted): void
    {
        $sdJwt = self::boundSdJwt();
        $presentation = self::token($sdJwt->getIssuerSignedJwt(), [], self::keyBindingJwt($sdJwt, [], $header));
        $verification = static fn () => self::verifier()->verifyWithKeyBinding($presentation, self::issuerKey(), self::AUDIENCE, self::NONCE);

        if ($accepted) {
            static::assertTrue($verification()->hasKeyBinding());

            return;
        }
        self::assertRejected('The Key Binding JWT must be of type "kb+jwt".', $verification);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, bool}>
     */
    public static function keyBindingTypes(): iterable
    {
        yield 'kb+jwt' => [[
            'alg' => 'ES256',
            'typ' => 'kb+jwt',
        ], true];
        yield 'with the application prefix' => [[
            'alg' => 'ES256',
            'typ' => 'application/kb+jwt',
        ], true];
        yield 'upper case' => [[
            'alg' => 'ES256',
            'typ' => 'KB+JWT',
        ], true];
        yield 'JWT' => [[
            'alg' => 'ES256',
            'typ' => 'JWT',
        ], false];
        yield 'no typ' => [[
            'alg' => 'ES256',
        ], false];
        yield 'not a string' => [[
            'alg' => 'ES256',
            'typ' => 1,
        ], false];
    }

    /**
     * RFC 9901 section 4.3: the four claims of the Key Binding JWT are required, and "aud" is a single string.
     *
     * @param array<string, mixed> $claims
     */
    #[Test]
    #[DataProvider('invalidKeyBindingClaims')]
    public function theClaimsOfTheKeyBindingJwtAreRequired(array $claims, string $message): void
    {
        $sdJwt = self::boundSdJwt();
        $presentation = self::token($sdJwt->getIssuerSignedJwt(), [], self::keyBindingJwt($sdJwt, $claims));

        self::assertRejected($message, static fn () => self::verifier()->verifyWithKeyBinding($presentation, self::issuerKey(), self::AUDIENCE, self::NONCE));
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function invalidKeyBindingClaims(): iterable
    {
        yield 'no iat' => [[
            'iat' => null,
        ], 'The "iat" claim of the Key Binding JWT must be a number.'];
        yield 'iat is a string' => [[
            'iat' => (string) self::NOW,
        ], 'The "iat" claim of the Key Binding JWT must be a number.'];
        yield 'no aud' => [[
            'aud' => null,
        ], 'The "aud" claim of the Key Binding JWT must be a string.'];
        yield 'aud is an array' => [[
            'aud' => [self::AUDIENCE],
        ], 'The "aud" claim of the Key Binding JWT must be a string.'];
        yield 'no nonce' => [[
            'nonce' => null,
        ], 'The "nonce" claim of the Key Binding JWT must be a string.'];
        yield 'nonce is a number' => [[
            'nonce' => 1234567890,
        ], 'The "nonce" claim of the Key Binding JWT must be a string.'];
        yield 'no sd_hash' => [[
            'sd_hash' => null,
        ], 'The "sd_hash" claim of the Key Binding JWT must be a string.'];
        yield 'expired' => [[
            'exp' => self::NOW - 1,
        ], 'The token expired.'];
        yield 'not yet valid' => [[
            'nbf' => self::NOW + 10,
        ], 'The JWT can not be used yet.'];
    }

    #[Test]
    public function aFloatCreationTimeIsAccepted(): void
    {
        $sdJwt = self::boundSdJwt();
        $presentation = self::token($sdJwt->getIssuerSignedJwt(), [], self::keyBindingJwt($sdJwt, [
            'iat' => self::NOW + 0.5,
        ]));

        static::assertTrue(self::verifier(allowedTimeDrift: 1)->verifyWithKeyBinding($presentation, self::issuerKey(), self::AUDIENCE, self::NONCE)->hasKeyBinding());
    }

    /**
     * RFC 9901 section 7.3 steps 5.a to 5.c: the Key Binding JWT is verified with the key of the "cnf" claim only.
     */
    #[Test]
    public function aKeyBindingJwtSignedByAnotherKeyIsRejected(): void
    {
        $sdJwt = self::boundSdJwt();
        $presentation = self::token($sdJwt->getIssuerSignedJwt(), [], self::keyBindingJwt($sdJwt, [], [
            'alg' => 'ES256',
            'typ' => 'kb+jwt',
        ], (new JWKFactory())->ec('P-256')));

        self::assertRejected('The Key Binding JWT cannot be verified.', static fn () => self::verifier()->verifyWithKeyBinding($presentation, self::issuerKey(), self::AUDIENCE, self::NONCE));
    }

    /**
     * @param array<string, mixed> $claims
     */
    #[Test]
    #[DataProvider('withoutHolderKey')]
    public function theHolderKeyIsTakenFromTheCnfClaim(array $claims, string $message): void
    {
        $issuerSignedJwt = self::sign($claims);
        $sdJwt = SDJWT::fromString(self::token($issuerSignedJwt));
        $presentation = self::token($issuerSignedJwt, [], self::keyBindingJwt($sdJwt));

        self::assertRejected($message, static fn () => self::verifier()->verifyWithKeyBinding($presentation, self::issuerKey(), self::AUDIENCE, self::NONCE));
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function withoutHolderKey(): iterable
    {
        $message = 'The holder key cannot be determined: the SD-JWT has no "cnf" claim with a "jwk" member.';
        yield 'no cnf' => [[
            'sub' => 'user_42',
        ], $message];
        yield 'cnf is a string' => [[
            'cnf' => 'key',
        ], $message];
        yield 'a key identifier' => [[
            'cnf' => [
                'kid' => 'holder-key',
            ],
        ], $message];
        yield 'jwk is a string' => [[
            'cnf' => [
                'jwk' => 'key',
            ],
        ], $message];
        yield 'jwk is not a key' => [[
            'cnf' => [
                'jwk' => [
                    'crv' => 'P-256',
                ],
            ],
        ], 'The JWK of the "cnf" claim is not valid.'];
    }

    #[Test]
    public function theHolderKeyMayBeSelectivelyDisclosed(): void
    {
        $cnf = Disclosure::forObjectProperty('cnf', [
            'jwk' => self::holderKey()->toPublic()->all(),
        ]);
        $issuerSignedJwt = self::sign([
            '_sd' => [$cnf->digest()],
        ]);
        $sdJwt = SDJWT::create($issuerSignedJwt, [$cnf]);

        $verified = self::verifier()->verifyWithKeyBinding(
            $sdJwt->withKeyBindingJwt(self::keyBindingJwt($sdJwt))->toString(),
            self::issuerKey(),
            self::AUDIENCE,
            self::NONCE
        );

        static::assertSame(self::holderKey()->toPublic()->all(), $verified->getHolderKey()?->all());
    }

    /**
     * By default, a Key Binding JWT may be 300 seconds old and the clocks may not drift.
     */
    #[Test]
    #[DataProvider('defaultKeyBindingTimes')]
    public function theDefaultWindowOfTheKeyBindingJwtIsFiveMinutesWithoutDrift(int $now, ?string $message): void
    {
        $verifier = new SDJWTVerifier(self::jwsLoader(), self::clock($now), self::jwsLoader());
        $verification = static fn () => $verifier->verifyWithKeyBinding(
            self::example('section-5')['presentation'],
            self::rfcIssuerKey(),
            self::AUDIENCE,
            self::NONCE
        );

        if ($message === null) {
            static::assertTrue($verification()->hasKeyBinding());

            return;
        }
        self::assertRejected($message, $verification);
    }

    /**
     * @return iterable<string, array{int, string|null}>
     */
    public static function defaultKeyBindingTimes(): iterable
    {
        yield 'at the end of the window' => [self::NOW + 300, null];
        yield 'after the window' => [self::NOW + 301, 'The Key Binding JWT is too old.'];
        yield 'one second before creation' => [self::NOW - 1, 'The Key Binding JWT is issued in the future.'];
    }

    #[Test]
    #[DataProvider('negativeDurations')]
    public function theDurationsOfTheVerifierCannotBeNegative(int $keyBindingMaxAge, int $allowedTimeDrift): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'The maximum age of the Key Binding JWT and the allowed time drift must be non-negative.'
        );

        self::verifier(keyBindingMaxAge: $keyBindingMaxAge, allowedTimeDrift: $allowedTimeDrift);
    }

    /**
     * @return iterable<string, array{int, int}>
     */
    public static function negativeDurations(): iterable
    {
        yield 'negative maximum age' => [-1, 0];
        yield 'negative drift' => [300, -1];
    }

    #[Test]
    public function aKeyBindingJwtCreatedNowIsAcceptedWithoutWindow(): void
    {
        static::assertTrue(self::verifier(keyBindingMaxAge: 0)->verifyWithKeyBinding(
            self::example('section-5')['presentation'],
            self::rfcIssuerKey(),
            self::AUDIENCE,
            self::NONCE
        )->hasKeyBinding());
    }

    #[Test]
    public function keyBindingCannotBeVerifiedWithoutALoader(): void
    {
        $verifier = new SDJWTVerifier(self::jwsLoader(), self::clock());

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('No loader is configured for the Key Binding JWT: key binding cannot be verified.');

        $verifier->verifyWithKeyBinding(self::example('section-5')['presentation'], self::rfcIssuerKey(), self::AUDIENCE, self::NONCE);
    }

    #[Test]
    public function aVerifierWithoutKeyBindingLoaderVerifiesSdJwts(): void
    {
        $verifier = new SDJWTVerifier(self::jwsLoader(), self::clock());

        static::assertSame(
            self::canonical(self::example('appendix-a.1')['processed_payload']),
            self::canonical($verifier->verify(self::example('appendix-a.1')['presentation'], self::rfcIssuerKey())->getClaims())
        );
    }

    #[Test]
    public function aMalformedSdJwtIsRejected(): void
    {
        self::assertRejected('The SD-JWT cannot be parsed.', static fn () => self::verifier()->verify('not an SD-JWT', self::issuerKey()));
        self::assertRejected('A Disclosure of the SD-JWT is empty.', static fn () => self::verifier()->verify(self::sign([]) . '~~', self::issuerKey()));
    }

    #[Test]
    public function thePayloadOfTheIssuerSignedJwtMustBeAnObject(): void
    {
        $jws = self::jwsBuilder()
            ->withPayload('["sub"]')
            ->addSignature(self::issuerKey(), [
                'alg' => 'ES256',
                'typ' => 'example+sd-jwt',
            ])
            ->build();
        $token = self::token((new CompactSerializer())->serialize($jws, 0));

        self::assertRejected('The payload of the Issuer-signed JWT must be a JSON object.', static fn () => self::verifier()->verify($token, self::issuerKey()));
    }

    /**
     * An SD-JWT bound to the holder key of the tests, without Disclosures.
     */
    private static function boundSdJwt(): SDJWT
    {
        return SDJWT::fromString(self::token(self::sign([
            'sub' => 'user_42',
            'cnf' => [
                'jwk' => self::holderKey()->toPublic()->all(),
            ],
        ])));
    }

    /**
     * Signs a Key Binding JWT for the given SD-JWT with the holder key of the tests. A claim given as null is removed.
     *
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $header
     */
    private static function keyBindingJwt(
        SDJWT $sdJwt,
        array $claims = [],
        array $header = [
            'alg' => 'ES256',
            'typ' => 'kb+jwt',
        ],
        ?JWK $key = null
    ): string {
        $payload = array_filter([
            ...[
                'nonce' => self::NONCE,
                'aud' => self::AUDIENCE,
                'iat' => self::NOW,
                'sd_hash' => $sdJwt->getSdHash(),
            ],
            ...$claims,
        ], static fn (mixed $value): bool => $value !== null);

        return self::sign($payload, $header, $key ?? self::holderKey());
    }

    private static function decoy(): string
    {
        return Base64UrlSafe::encodeUnpadded(random_bytes(32));
    }
}
