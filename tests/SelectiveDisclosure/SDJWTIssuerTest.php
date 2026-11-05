<?php

declare(strict_types=1);

namespace Jose\Tests\SelectiveDisclosure;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\UnsupportedAlgorithmException;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\SelectiveDisclosure\Disclosable;
use Jose\SelectiveDisclosure\Disclosure;
use Jose\SelectiveDisclosure\SDJWTIssuer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function count;
use function in_array;
use function is_array;
use function strlen;

/**
 * @internal
 */
final class SDJWTIssuerTest extends SelectiveDisclosureTestCase
{
    #[Test]
    #[DataProvider('hashAlgorithms')]
    public function anSdJwtIsIssuedAndVerifiedWithTheGivenHashAlgorithm(string $hashAlgorithm): void
    {
        $sdJwt = self::issuer($hashAlgorithm)->issue(self::claims(), self::issuerKey(), [
            'alg' => 'ES256',
            'typ' => 'example+sd-jwt',
        ]);

        static::assertSame($hashAlgorithm, self::payloadOf($sdJwt)['_sd_alg']);
        static::assertSame($hashAlgorithm, $sdJwt->getHashAlgorithm());
        static::assertSame(
            self::canonical(self::disclosedClaims()),
            self::canonical(self::verifier()->verify($sdJwt->toString(), self::issuerKey())->getClaims())
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function hashAlgorithms(): iterable
    {
        foreach (['sha-256', 'sha-384', 'sha-512', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512'] as $hashAlgorithm) {
            yield $hashAlgorithm => [$hashAlgorithm];
        }
    }

    #[Test]
    public function anyAlgorithmOfTheJwsBuilderSignsTheIssuerSignedJwt(): void
    {
        $key = (new JWKFactory())->rsa(2048);

        $sdJwt = self::issuer()->issue(self::claims(), $key, [
            'alg' => 'PS256',
            'typ' => 'example+sd-jwt',
            'kid' => 'issuer-key',
        ]);

        $verified = self::verifier()->verify($sdJwt->toString(), $key->toPublic());
        static::assertSame('PS256', $verified->getIssuerSignedJwt()->getSignature(0)->getProtectedHeaderParameter('alg'));
        static::assertSame('issuer-key', $verified->getIssuerSignedJwt()->getSignature(0)->getProtectedHeaderParameter('kid'));
        static::assertSame(self::canonical(self::disclosedClaims()), self::canonical($verified->getClaims()));
    }

    #[Test]
    public function theDigestsOfAnObjectAreSortedAndTheClaimsAreHidden(): void
    {
        $sdJwt = self::issuer()->issue(self::claims(), self::issuerKey(), [
            'alg' => 'ES256',
        ]);
        $payload = self::payloadOf($sdJwt);

        static::assertSame(['_sd', 'iss', 'exp', 'address', 'nationalities', '_sd_alg'], array_keys($payload));
        static::assertSame(self::sorted($payload['_sd']), $payload['_sd']);
        static::assertCount(2, $payload['_sd']);
        static::assertSame(['_sd', 'country'], array_keys($payload['address']));
        static::assertSame('FR', $payload['nationalities'][0]);
        static::assertSame(['...'], array_keys($payload['nationalities'][1]));
        static::assertCount(5, $sdJwt->getDisclosures());
    }

    #[Test]
    public function aRecursiveDisclosureIsCreatedAfterTheDisclosuresItContains(): void
    {
        $sdJwt = self::issuer()->issue([
            'address' => new Disclosable([
                'locality' => new Disclosable('Schulpforta'),
                'country' => 'DE',
            ]),
        ], self::issuerKey(), [
            'alg' => 'ES256',
        ]);

        [$locality, $address] = $sdJwt->getDisclosures();
        static::assertSame('locality', $locality->getClaimName());
        static::assertSame('address', $address->getClaimName());
        static::assertSame([
            '_sd' => [$locality->digest()],
            'country' => 'DE',
        ], $address->getValue());
        static::assertSame([$address->digest()], self::payloadOf($sdJwt)['_sd']);
    }

    #[Test]
    public function decoyDigestsAreAddedToEveryObjectAndArrayThatHasDisclosures(): void
    {
        $sdJwt = self::issuer('sha-256', 3)->issue(self::claims(), self::issuerKey(), [
            'alg' => 'ES256',
        ]);
        $payload = self::payloadOf($sdJwt);
        $digests = array_map(static fn (Disclosure $disclosure): string => $disclosure->digest(), $sdJwt->getDisclosures());

        static::assertCount(2 + 3, $payload['_sd']);
        static::assertCount(1 + 3, $payload['address']['_sd']);
        static::assertCount(3 + 3, $payload['nationalities']);
        static::assertSame(self::sorted($payload['_sd']), $payload['_sd']);
        $decoys = 0;
        foreach ([...$payload['_sd'], ...$payload['address']['_sd'], ...self::arrayDigests($payload['nationalities'])] as $digest) {
            static::assertSame(43, strlen($digest));
            static::assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $digest);
            if (! in_array($digest, $digests, true)) {
                ++$decoys;
            }
        }
        static::assertSame(9, $decoys);
        static::assertSame(
            self::canonical(self::disclosedClaims()),
            self::canonical(self::verifier()->verify($sdJwt->toString(), self::issuerKey())->getClaims())
        );
    }

    #[Test]
    public function byDefaultTheDigestsAreSha256AndThereIsNoDecoy(): void
    {
        $sdJwt = (new SDJWTIssuer(self::jwsBuilder()))->issue(self::claims(), self::issuerKey(), [
            'alg' => 'ES256',
        ]);
        $payload = self::payloadOf($sdJwt);

        static::assertSame('sha-256', $payload['_sd_alg']);
        static::assertCount(2, $payload['_sd']);
        static::assertCount(1, $payload['address']['_sd']);
        static::assertCount(3, $payload['nationalities']);
    }

    /**
     * The decoys of an array are inserted anywhere, before the first element included: their position does not tell
     * them from the digests of real elements.
     */
    #[Test]
    public function theDecoysOfAnArrayCanTakeAnyPosition(): void
    {
        $issuer = self::issuer('sha-256', 1);
        $positions = [];
        for ($i = 0; $i < 64; ++$i) {
            $sdJwt = $issuer->issue([
                'list' => ['a', new Disclosable('b')],
            ], self::issuerKey(), [
                'alg' => 'ES256',
            ]);
            $digest = $sdJwt->getDisclosures()[0]
                ->digest();
            foreach (self::payloadOf($sdJwt)['list'] as $position => $element) {
                if (is_array($element) && $element['...'] !== $digest) {
                    $positions[$position] = true;
                }
            }
        }
        ksort($positions);

        static::assertSame([0, 1, 2], array_keys($positions));
    }

    #[Test]
    public function theDecoyDigestsHaveTheLengthOfTheHashAlgorithm(): void
    {
        $payload = self::payloadOf(self::issuer('sha-512', 2)->issue(self::claims(), self::issuerKey(), [
            'alg' => 'ES256',
        ]));

        foreach ($payload['_sd'] as $digest) {
            static::assertSame(86, strlen($digest));
        }
    }

    #[Test]
    public function theNumberOfDecoyDigestsIsDrawnBetweenTheBounds(): void
    {
        $issuer = self::issuer('sha-256', 1, 4);
        $counts = [];
        for ($i = 0; $i < 100; ++$i) {
            $payload = self::payloadOf($issuer->issue([
                'given_name' => new Disclosable('John'),
            ], self::issuerKey(), [
                'alg' => 'ES256',
            ]));
            $counts[count($payload['_sd']) - 1] = true;
        }
        ksort($counts);

        static::assertSame([1, 2, 3, 4], array_keys($counts));
    }

    #[Test]
    public function noDecoyIsAddedWhereNothingIsSelectivelyDisclosable(): void
    {
        $payload = self::payloadOf(self::issuer('sha-256', 5)->issue([
            'iss' => 'https://issuer.example.com',
            'address' => [
                'country' => 'DE',
            ],
            'nationalities' => ['DE'],
        ], self::issuerKey(), [
            'alg' => 'ES256',
        ]));

        static::assertSame([
            'iss' => 'https://issuer.example.com',
            'address' => [
                'country' => 'DE',
            ],
            'nationalities' => ['DE'],
            '_sd_alg' => 'sha-256',
        ], $payload);
    }

    #[Test]
    #[DataProvider('invalidDecoyBounds')]
    public function theDecoyBoundsAreChecked(int $minimum, ?int $maximum): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The number of decoy digests must be a range of non-negative integers.');

        new SDJWTIssuer(self::jwsBuilder(), 'sha-256', $minimum, $maximum);
    }

    /**
     * @return iterable<string, array{int, int|null}>
     */
    public static function invalidDecoyBounds(): iterable
    {
        yield 'negative minimum' => [-1, null];
        yield 'negative maximum' => [0, -1];
        yield 'maximum below the minimum' => [3, 2];
    }

    #[Test]
    public function anUnsupportedHashAlgorithmIsRefused(): void
    {
        $this->expectException(UnsupportedAlgorithmException::class);
        $this->expectExceptionMessage('The hash algorithm "sha256" is not supported.');

        new SDJWTIssuer(self::jwsBuilder(), 'sha256');
    }

    #[Test]
    #[DataProvider('reservedClaimNames')]
    public function aReservedClaimNameIsRefused(array $claims, string $claimName): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The claim name "' . $claimName . '" is reserved.');

        self::issuer()->issue($claims, self::issuerKey(), [
            'alg' => 'ES256',
        ]);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function reservedClaimNames(): iterable
    {
        foreach (['_sd', '...', '_sd_alg'] as $claimName) {
            yield $claimName . ' at the top level' => [[
                $claimName => 'value',
            ], $claimName];
            yield $claimName . ' in an object' => [[
                'address' => [
                    $claimName => 'value',
                ],
            ], $claimName];
            yield $claimName . ' in a Disclosure' => [[
                'address' => new Disclosable([
                    $claimName => 'value',
                ]),
            ], $claimName];
            yield $claimName . ' in an array' => [[
                'list' => [[
                    $claimName => 'value',
                ]],
            ], $claimName];
        }
        yield 'selectively disclosable _sd' => [[
            '_sd' => new Disclosable('value'),
        ], '_sd'];
    }

    #[Test]
    #[DataProvider('validityClaims')]
    public function aClaimThatControlsTheValidityCannotBeSelectivelyDisclosable(string $claimName): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The claim "' . $claimName . '" cannot be selectively disclosable: the Verifier needs it to evaluate the SD-JWT.');

        self::issuer()->issue([
            $claimName => new Disclosable('value'),
        ], self::issuerKey(), [
            'alg' => 'ES256',
        ]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function validityClaims(): iterable
    {
        foreach (['iss', 'aud', 'exp', 'nbf', 'cnf'] as $claimName) {
            yield $claimName => [$claimName];
        }
    }

    #[Test]
    public function theValidityClaimsCanBeSelectivelyDisclosableInNestedObjectsAndTheEntriesOfAudToo(): void
    {
        $sdJwt = self::issuer()->issue([
            'aud' => ['https://verifier.example.org', new Disclosable('https://other.example.org')],
            'evidence' => [
                'iss' => new Disclosable('https://authority.example.org'),
            ],
        ], self::issuerKey(), [
            'alg' => 'ES256',
        ]);

        static::assertCount(2, $sdJwt->getDisclosures());
    }

    #[Test]
    public function theClaimsMustBeAnObject(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The claims of an SD-JWT must be a JSON object.');

        self::issuer()->issue(['value'], self::issuerKey(), [
            'alg' => 'ES256',
        ]);
    }

    #[Test]
    public function aSaltIsUsedOnce(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The salt of every Disclosure must be unique.');

        self::issuer()->issue([
            'given_name' => new Disclosable('John', 'salt'),
            'family_name' => new Disclosable('Doe', 'salt'),
        ], self::issuerKey(), [
            'alg' => 'ES256',
        ]);
    }

    #[Test]
    #[DataProvider('invalidProtectedHeaders')]
    public function theProtectedHeaderMustNameASignatureAlgorithm(array $protectedHeader): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The Issuer-signed JWT must be signed: the "alg" header parameter must name a signature algorithm.');

        self::issuer()->issue(self::claims(), self::issuerKey(), $protectedHeader);
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function invalidProtectedHeaders(): iterable
    {
        yield 'no alg' => [[
            'typ' => 'example+sd-jwt',
        ]];
        yield 'none' => [[
            'alg' => 'none',
        ]];
        yield 'not a string' => [[
            'alg' => 256,
        ]];
        yield 'a MAC algorithm' => [[
            'alg' => 'HS256',
        ]];
    }

    #[Test]
    public function aDisclosableValueIsOnlyAllowedAsAClaimOrAnArrayElement(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('A Disclosable cannot be the value of another Disclosable.');

        self::issuer()->issue([
            'given_name' => new Disclosable(new Disclosable('John')),
        ], self::issuerKey(), [
            'alg' => 'ES256',
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    private static function claims(): array
    {
        return [
            'iss' => 'https://issuer.example.com',
            'exp' => self::NOW + 3600,
            'given_name' => new Disclosable('John'),
            'family_name' => new Disclosable('Doe'),
            'address' => [
                'street_address' => new Disclosable('123 Main St'),
                'country' => 'US',
            ],
            'nationalities' => ['FR', new Disclosable('DE'), new Disclosable('US')],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function disclosedClaims(): array
    {
        return [
            'iss' => 'https://issuer.example.com',
            'exp' => self::NOW + 3600,
            'given_name' => 'John',
            'family_name' => 'Doe',
            'address' => [
                'street_address' => '123 Main St',
                'country' => 'US',
            ],
            'nationalities' => ['FR', 'DE', 'US'],
        ];
    }

    /**
     * @param list<mixed> $array
     * @return list<string>
     */
    private static function arrayDigests(array $array): array
    {
        $digests = [];
        foreach ($array as $element) {
            if (is_array($element) && isset($element['...'])) {
                $digests[] = $element['...'];
            }
        }

        return $digests;
    }
}
