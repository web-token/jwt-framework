<?php

declare(strict_types=1);

namespace Jose\Tests\SelectiveDisclosure;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\InvalidSerializationException;
use Jose\Component\Core\Exception\InvalidTokenException;
use Jose\Component\Core\Exception\LogicException;
use Jose\Component\Core\Exception\UnsupportedAlgorithmException;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\SelectiveDisclosure\Disclosable;
use Jose\SelectiveDisclosure\Disclosure;
use Jose\SelectiveDisclosure\SDJWT;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * The combined format of RFC 9901 section 4 and the selection of the Disclosures by the Holder, section 7.2.
 *
 * @internal
 */
final class SDJWTTest extends SelectiveDisclosureTestCase
{
    #[Test]
    public function anSdJwtIsParsedAndSerializedBackUnchanged(): void
    {
        $example = self::example('section-5');

        $sdJwt = SDJWT::fromString($example['sd_jwt']);

        static::assertSame($example['issuer_signed_jwt'], $sdJwt->getIssuerSignedJwt());
        static::assertSame(
            array_column($example['disclosures'], 'disclosure'),
            array_map(static fn (Disclosure $disclosure): string => $disclosure->toString(), $sdJwt->getDisclosures())
        );
        static::assertFalse($sdJwt->hasKeyBinding());
        static::assertNull($sdJwt->getKeyBindingJwt());
        static::assertSame($example['sd_jwt'], $sdJwt->toString());
        static::assertSame($example['sd_jwt'], (string) $sdJwt);
        static::assertSame('sha-256', $sdJwt->getHashAlgorithm());
    }

    #[Test]
    public function anSdJwtWithKeyBindingIsParsedAndSerializedBackUnchanged(): void
    {
        $presentation = self::example('section-5')['presentation'];

        $sdJwt = SDJWT::fromString($presentation);

        static::assertTrue($sdJwt->hasKeyBinding());
        static::assertCount(4, $sdJwt->getDisclosures());
        static::assertSame(substr((string) $presentation, strrpos((string) $presentation, '~') + 1), $sdJwt->getKeyBindingJwt());
        static::assertSame($presentation, $sdJwt->toString());

        $withoutKeyBinding = $sdJwt->withoutKeyBinding();
        static::assertFalse($withoutKeyBinding->hasKeyBinding());
        static::assertSame(substr((string) $presentation, 0, strrpos((string) $presentation, '~') + 1), $withoutKeyBinding->toString());
        static::assertSame($sdJwt->getSdHash(), $withoutKeyBinding->getSdHash());
    }

    #[Test]
    public function anSdJwtWithoutDisclosuresIsParsed(): void
    {
        $jwt = self::sign([
            'sub' => 'user_42',
        ]);
        $keyBindingJwt = self::sign([
            'nonce' => 'n',
        ], [
            'alg' => 'ES256',
            'typ' => 'kb+jwt',
        ]);

        static::assertSame([], SDJWT::fromString($jwt . '~')->getDisclosures());
        static::assertSame($jwt . '~', SDJWT::fromString($jwt . '~')->toString());
        static::assertSame($keyBindingJwt, SDJWT::fromString($jwt . '~' . $keyBindingJwt)->getKeyBindingJwt());
        static::assertSame($jwt . '~' . $keyBindingJwt, SDJWT::create($jwt, [], $keyBindingJwt)->toString());
    }

    #[Test]
    #[DataProvider('malformedSdJwts')]
    public function aMalformedSdJwtIsRejected(string $token, string $message): void
    {
        $this->expectException(InvalidSerializationException::class);
        $this->expectExceptionMessage($message);

        SDJWT::fromString($token);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function malformedSdJwts(): iterable
    {
        $jwt = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1c2VyXzQyIn0.c2lnbmF0dXJl';
        $disclosure = 'WyJzYWx0IiwgInN1YiIsICJ1c2VyIl0';
        yield 'a JWT' => [$jwt, 'The SD-JWT must contain a "~" separator after the Issuer-signed JWT.'];
        yield 'empty' => ['', 'The SD-JWT must contain a "~" separator after the Issuer-signed JWT.'];
        yield 'no Issuer-signed JWT' => ['~', 'The Issuer-signed JWT must be a JWS in compact serialization.'];
        yield 'two segments' => ['eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1c2VyXzQyIn0~', 'The Issuer-signed JWT must be a JWS in compact serialization.'];
        yield 'empty payload' => ['eyJhbGciOiJFUzI1NiJ9..c2lnbmF0dXJl~', 'The Issuer-signed JWT must be a JWS in compact serialization.'];
        yield 'empty signature' => ['eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1c2VyXzQyIn0.~', 'The Issuer-signed JWT must be a JWS in compact serialization.'];
        yield 'empty Disclosure' => [$jwt . '~~', 'A Disclosure of the SD-JWT is empty.'];
        yield 'empty Disclosure after another one' => [$jwt . '~' . $disclosure . '~~', 'A Disclosure of the SD-JWT is empty.'];
        yield 'malformed Disclosure' => [$jwt . '~W10~', 'The Disclosure must be a JSON array of two or three elements.'];
        yield 'malformed Key Binding JWT' => [$jwt . '~' . $disclosure . '~abc', 'The Key Binding JWT must be a JWS in compact serialization.'];
        yield 'JSON Key Binding JWT' => [$jwt . '~{"payload":"e30"}', 'The Key Binding JWT must be a JWS in compact serialization.'];
    }

    #[Test]
    public function theIssuerSignedJwtOfANewSdJwtIsChecked(): void
    {
        $this->expectException(InvalidSerializationException::class);
        $this->expectExceptionMessage('The Issuer-signed JWT must be a JWS in compact serialization.');

        SDJWT::create('eyJhbGciOiJFUzI1NiJ9.e30');
    }

    #[Test]
    public function theKeyBindingJwtOfANewSdJwtIsChecked(): void
    {
        $this->expectException(InvalidSerializationException::class);
        $this->expectExceptionMessage('The Key Binding JWT must be a JWS in compact serialization.');

        SDJWT::create(self::sign([]), [], 'not a JWT');
    }

    #[Test]
    public function theHashAlgorithmIsReadFromTheIssuerSignedJwt(): void
    {
        static::assertSame('sha-256', SDJWT::fromString(self::sign([
            'sub' => 'user_42',
        ]) . '~')->getHashAlgorithm());
        static::assertSame('sha-512', SDJWT::fromString(self::sign([
            '_sd_alg' => 'sha-512',
        ]) . '~')->getHashAlgorithm());
    }

    #[Test]
    public function theSupportedHashAlgorithmsAreTheIanaNamesPhpCanCompute(): void
    {
        static::assertSame(
            ['sha-256', 'sha-384', 'sha-512', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512'],
            SDJWT::hashAlgorithms()
        );
    }

    #[Test]
    public function anUnsupportedHashAlgorithmIsReported(): void
    {
        $this->expectException(UnsupportedAlgorithmException::class);
        $this->expectExceptionMessage('The hash algorithm "md5" is not supported.');

        SDJWT::fromString(self::sign([
            '_sd_alg' => 'md5',
        ]) . '~')->getHashAlgorithm();
    }

    #[Test]
    public function theSdHashIsComputedWithTheHashAlgorithmOfTheSdJwt(): void
    {
        $jwt = self::sign([
            '_sd_alg' => 'sha-384',
        ]);

        static::assertSame(
            rtrim(strtr(base64_encode(hash('sha384', $jwt . '~', true)), '+/', '-_'), '='),
            SDJWT::fromString($jwt . '~')->getSdHash()
        );
    }

    #[Test]
    public function aWholeObjectIsSelectedWithTheDisclosuresItContains(): void
    {
        $sdJwt = SDJWT::fromString(self::example('appendix-a.3')['sd_jwt']);

        $selected = $sdJwt->select(['address']);

        static::assertSame(
            ['street_address', 'locality', 'postal_code', 'country', 'address'],
            array_map(static fn (Disclosure $disclosure): ?string => $disclosure->getClaimName(), $selected->getDisclosures())
        );
    }

    #[Test]
    public function everyElementOfAnArrayIsSelectedWithANullSegment(): void
    {
        $sdJwt = SDJWT::fromString(self::example('section-5')['sd_jwt']);

        $selected = $sdJwt->select(['nationalities', null]);

        static::assertSame(
            ['US', 'DE'],
            array_map(static fn (Disclosure $disclosure): mixed => $disclosure->getValue(), $selected->getDisclosures())
        );
    }

    #[Test]
    public function aClaimThatIsAlwaysDisclosedNeedsNoDisclosure(): void
    {
        $sdJwt = SDJWT::fromString(self::example('section-5')['sd_jwt']);

        static::assertSame([], $sdJwt->select(['iss'], ['cnf', 'jwk', 'kty'])->getDisclosures());
        static::assertSame([], $sdJwt->select()->getDisclosures());
        static::assertSame($sdJwt->getIssuerSignedJwt() . '~', $sdJwt->select()->toString());
    }

    #[Test]
    public function aSelectionOfIndexesFollowsThePositionsOfTheDisclosedArray(): void
    {
        $sdJwt = self::issuer()->issue([
            'nationalities' => ['FR', new Disclosable('DE'), new Disclosable('US')],
        ], self::issuerKey(), [
            'alg' => 'ES256',
        ]);

        $selected = $sdJwt->select(['nationalities', 2]);

        static::assertCount(1, $selected->getDisclosures());
        static::assertSame('US', $selected->getDisclosures()[0]->getValue());
        static::assertSame([], $sdJwt->select(['nationalities', 0])->getDisclosures());
    }

    #[Test]
    #[DataProvider('unknownClaimPaths')]
    public function aClaimPathThatMatchesNothingIsRejected(array $claimPath): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The claim path ' . json_encode($claimPath) . ' does not match any claim.');

        SDJWT::fromString(self::example('section-5')['sd_jwt'])->select($claimPath);
    }

    /**
     * @return iterable<string, array{list<string|int|null>}>
     */
    public static function unknownClaimPaths(): iterable
    {
        yield 'unknown claim' => [['unknown']];
        yield 'member of a string' => [['given_name', 'first']];
        yield 'index out of range' => [['nationalities', 2]];
        yield 'index of an object' => [['address', 0]];
        yield 'member of an array' => [['nationalities', 'first']];
        yield 'every element of an object' => [['address', null]];
    }

    #[Test]
    #[DataProvider('invalidClaimPaths')]
    public function aClaimPathMadeOfOtherSegmentsIsRejected(array $claimPath): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('A claim path is a non-empty list of strings, non-negative integers and nulls.');

        SDJWT::fromString(self::example('section-5')['sd_jwt'])->select($claimPath);
    }

    /**
     * @return iterable<string, array{array<mixed>}>
     */
    public static function invalidClaimPaths(): iterable
    {
        yield 'empty' => [[]];
        yield 'negative index' => [['nationalities', -1]];
        yield 'float' => [['nationalities', 1.0]];
        yield 'boolean' => [[true]];
        yield 'map' => [[
            'name' => 'given_name',
        ]];
    }

    #[Test]
    public function theDisclosuresOfAnSdJwtWithKeyBindingCannotBeSelected(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('The Disclosures of an SD-JWT with a Key Binding JWT cannot be selected.');

        SDJWT::fromString(self::example('section-5')['presentation'])->select(['given_name']);
    }

    #[Test]
    public function theKeyBindingJwtGivenToAnSdJwtIsChecked(): void
    {
        $this->expectException(InvalidSerializationException::class);
        $this->expectExceptionMessage('The Key Binding JWT must be a JWS in compact serialization.');

        SDJWT::fromString(self::example('section-5')['sd_jwt'])->withKeyBindingJwt('not a JWT');
    }

    #[Test]
    public function thePayloadOfTheIssuerSignedJwtMustBeAnObject(): void
    {
        $jws = self::jwsBuilder()
            ->withPayload('["sub"]')
            ->addSignature(self::issuerKey(), [
                'alg' => 'ES256',
            ])
            ->build();
        $sdJwt = SDJWT::fromString((new CompactSerializer())->serialize($jws, 0) . '~');

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('The payload of the Issuer-signed JWT must be a JSON object.');

        $sdJwt->getHashAlgorithm();
    }

    #[Test]
    public function anEmptyPayloadIsAnObject(): void
    {
        static::assertSame('sha-256', SDJWT::fromString(self::sign([]) . '~')->getHashAlgorithm());
    }

    #[Test]
    public function aDisclosureDesignatedByTwoClaimPathsIsSelectedOnce(): void
    {
        $sdJwt = SDJWT::fromString(self::example('appendix-a.3')['sd_jwt']);

        $selected = $sdJwt->select(['address'], ['address', 'locality'], ['address', 'country']);

        static::assertSame(
            ['street_address', 'locality', 'postal_code', 'country', 'address'],
            array_map(static fn (Disclosure $disclosure): ?string => $disclosure->getClaimName(), $selected->getDisclosures())
        );
    }

    /**
     * The paths of the Disclosures nested in an object or an array that is always disclosed start at the top level.
     */
    #[Test]
    public function theDisclosuresNestedInClaimsAlwaysDisclosedAreSelected(): void
    {
        $sdJwt = self::issuer()->issue([
            'person' => [
                'address' => new Disclosable([
                    'locality' => new Disclosable('Anytown'),
                    'region' => new Disclosable('Anystate'),
                ]),
            ],
            'degrees' => [[
                'type' => new Disclosable('Bachelor'),
                'name' => new Disclosable('Computer Science'),
            ]],
        ], self::issuerKey(), [
            'alg' => 'ES256',
        ]);

        $selected = $sdJwt->select(['person', 'address', 'locality'], ['degrees', 0, 'type']);

        static::assertSame(
            ['locality', 'address', 'type'],
            array_map(static fn (Disclosure $disclosure): ?string => $disclosure->getClaimName(), $selected->getDisclosures())
        );
    }

    #[Test]
    public function anSdJwtIsBoundToAKeyBindingJwtOnce(): void
    {
        $sdJwt = SDJWT::fromString(self::example('section-5')['sd_jwt']);
        $keyBindingJwt = SDJWT::fromString(self::example('section-5')['presentation'])->getKeyBindingJwt();

        $bound = $sdJwt->withKeyBindingJwt((string) $keyBindingJwt);

        static::assertSame($keyBindingJwt, $bound->getKeyBindingJwt());
        static::assertFalse($sdJwt->hasKeyBinding());
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('The SD-JWT already has a Key Binding JWT.');

        $bound->withKeyBindingJwt((string) $keyBindingJwt);
    }
}
