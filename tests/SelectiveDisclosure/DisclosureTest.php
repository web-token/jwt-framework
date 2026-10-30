<?php

declare(strict_types=1);

namespace Jose\Tests\SelectiveDisclosure;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\InvalidSerializationException;
use Jose\Component\Core\Exception\UnsupportedAlgorithmException;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\SelectiveDisclosure\Disclosure;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strlen;
use const JSON_THROW_ON_ERROR;

/**
 * @internal
 */
final class DisclosureTest extends TestCase
{
    private const MOBIUS = 'WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0';

    /**
     * RFC 9901 section 4.2.1 and 4.2.3: the Disclosure of an object property and its digest.
     */
    #[Test]
    public function theDisclosureOfAnObjectPropertyIsParsed(): void
    {
        $disclosure = Disclosure::fromString(self::MOBIUS);

        static::assertSame('_26bc4LT-ac6q2KI6cBW5es', $disclosure->getSalt());
        static::assertSame('family_name', $disclosure->getClaimName());
        static::assertSame('Möbius', $disclosure->getValue());
        static::assertFalse($disclosure->isArrayElement());
        static::assertSame('X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0', $disclosure->digest('sha-256'));
        static::assertSame('X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0', $disclosure->digest());
        static::assertSame(self::MOBIUS, $disclosure->toString());
        static::assertSame(self::MOBIUS, (string) $disclosure);
    }

    /**
     * RFC 9901 section 4.2.1: the digest is computed over the encoded Disclosure, so that the variations of the JSON
     * encoding are all valid and all different.
     */
    #[Test]
    #[DataProvider('variations')]
    public function everyVariationOfTheJsonEncodingDisclosesTheSameClaim(string $encoded): void
    {
        $disclosure = Disclosure::fromString($encoded);

        static::assertSame('_26bc4LT-ac6q2KI6cBW5es', $disclosure->getSalt());
        static::assertSame('family_name', $disclosure->getClaimName());
        static::assertSame('Möbius', $disclosure->getValue());
        static::assertSame($encoded, $disclosure->toString());
        static::assertNotSame('X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0', $disclosure->digest());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function variations(): iterable
    {
        yield 'unicode escape' => ['WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNXHUwMGY2Yml1cyJd'];
        yield 'no white space' => ['WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsImZhbWlseV9uYW1lIiwiTcO2Yml1cyJd'];
        yield 'new lines' => ['WwoiXzI2YmM0TFQtYWM2cTJLSTZjQlc1ZXMiLAoiZmFtaWx5X25hbWUiLAoiTcO2Yml1cyIKXQ'];
    }

    /**
     * The Disclosures are encoded as the examples of the RFC are, non-ASCII characters escaped.
     */
    #[Test]
    public function aDisclosureIsEncodedAsInTheExamplesOfTheRfc(): void
    {
        $disclosure = Disclosure::forObjectProperty('family_name', 'Möbius', '_26bc4LT-ac6q2KI6cBW5es');

        static::assertSame(
            'WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNXHUwMGY2Yml1cyJd',
            $disclosure->toString()
        );
        static::assertSame(
            '["_26bc4LT-ac6q2KI6cBW5es", "family_name", "M\u00f6bius"]',
            Base64UrlSafe::decodeNoPadding($disclosure->toString())
        );
    }

    /**
     * RFC 9901 section 4.2.2: the Disclosure of an array element.
     */
    #[Test]
    public function theDisclosureOfAnArrayElementIsCreated(): void
    {
        $disclosure = Disclosure::forArrayElement('FR', 'lklxF5jMYlGTPUovMNIvCA');

        static::assertSame('WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0', $disclosure->toString());
        static::assertSame('w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs', $disclosure->digest());
        static::assertTrue($disclosure->isArrayElement());
        static::assertNull($disclosure->getClaimName());
        static::assertSame('FR', $disclosure->getValue());
    }

    #[Test]
    public function nestedValuesAreEncodedAsInTheExamplesOfTheRfc(): void
    {
        $disclosure = Disclosure::forObjectProperty('claim', [
            'list' => [1, 2.5, true, null, 'a/b'],
            'empty list' => [],
            'object' => [
                'nested' => 'value',
            ],
        ], 'salt');

        static::assertSame(
            '["salt", "claim", {"list": [1, 2.5, true, null, "a/b"], "empty list": [], "object": {"nested": "value"}}]',
            Base64UrlSafe::decodeNoPadding($disclosure->toString())
        );
    }

    #[Test]
    public function aSaltOf128BitsIsGeneratedForEveryDisclosure(): void
    {
        $first = Disclosure::forObjectProperty('given_name', 'John');
        $second = Disclosure::forObjectProperty('given_name', 'John');

        static::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{22}$/', $first->getSalt());
        static::assertSame(16, strlen(Base64UrlSafe::decodeNoPadding($first->getSalt())));
        static::assertNotSame($first->getSalt(), $second->getSalt());
        static::assertNotSame($first->digest(), $second->digest());
        static::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{22}$/', Disclosure::forArrayElement('US')->getSalt());
    }

    #[Test]
    #[DataProvider('hashAlgorithms')]
    public function theDigestIsComputedWithTheGivenHashAlgorithm(string $hashAlgorithm, string $phpName): void
    {
        $disclosure = Disclosure::fromString(self::MOBIUS);

        static::assertSame(
            Base64UrlSafe::encodeUnpadded(hash($phpName, self::MOBIUS, true)),
            $disclosure->digest($hashAlgorithm)
        );
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function hashAlgorithms(): iterable
    {
        yield 'sha-256' => ['sha-256', 'sha256'];
        yield 'sha-384' => ['sha-384', 'sha384'];
        yield 'sha-512' => ['sha-512', 'sha512'];
        yield 'sha3-224' => ['sha3-224', 'sha3-224'];
        yield 'sha3-256' => ['sha3-256', 'sha3-256'];
        yield 'sha3-384' => ['sha3-384', 'sha3-384'];
        yield 'sha3-512' => ['sha3-512', 'sha3-512'];
    }

    #[Test]
    #[DataProvider('unsupportedHashAlgorithms')]
    public function anUnsupportedHashAlgorithmIsRefused(string $hashAlgorithm): void
    {
        $this->expectException(UnsupportedAlgorithmException::class);
        $this->expectExceptionMessage('The hash algorithm "' . $hashAlgorithm . '" is not supported.');

        Disclosure::fromString(self::MOBIUS)->digest($hashAlgorithm);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unsupportedHashAlgorithms(): iterable
    {
        yield 'PHP name' => ['sha256'];
        yield 'md5' => ['md5'];
        yield 'truncated' => ['sha-256-128'];
        yield 'upper case' => ['SHA-256'];
    }

    #[Test]
    #[DataProvider('reservedClaimNames')]
    public function aReservedClaimNameCannotBeDisclosed(string $claimName): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The claim name "' . $claimName . '" cannot be selectively disclosed.');

        Disclosure::forObjectProperty($claimName, 'value');
    }

    #[Test]
    #[DataProvider('reservedClaimNames')]
    public function aDisclosureOfAReservedClaimNameIsRejected(string $claimName): void
    {
        $this->expectException(InvalidSerializationException::class);
        $this->expectExceptionMessage('The claim name "' . $claimName . '" cannot be selectively disclosed.');

        Disclosure::fromString(self::encode(['salt', $claimName, 'value']));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function reservedClaimNames(): iterable
    {
        yield '_sd' => ['_sd'];
        yield '...' => ['...'];
    }

    #[Test]
    #[DataProvider('malformedDisclosures')]
    public function aMalformedDisclosureIsRejected(string $disclosure, string $message): void
    {
        $this->expectException(InvalidSerializationException::class);
        $this->expectExceptionMessage($message);

        Disclosure::fromString($disclosure);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function malformedDisclosures(): iterable
    {
        $array = 'The Disclosure must be a JSON array of two or three elements.';
        yield 'empty' => ['', 'The Disclosure is not base64url encoded.'];
        yield 'padding' => [self::MOBIUS . '==', 'The Disclosure is not base64url encoded.'];
        yield 'standard base64' => ['WyJh+/Ii', 'The Disclosure is not base64url encoded.'];
        yield 'impossible length' => ['WyJhY', 'The Disclosure is not base64url encoded.'];
        yield 'non-canonical encoding' => ['Wz', 'The Disclosure is not base64url encoded.'];
        yield 'not JSON' => [Base64UrlSafe::encodeUnpadded('["salt", '), 'The Disclosure is not valid JSON.'];
        yield 'object' => [self::encode([
            'salt' => 'salt',
        ]), $array];
        yield 'string' => [self::encode('salt'), $array];
        yield 'object with the keys of an array' => [
            Base64UrlSafe::encodeUnpadded('{"0": "salt", "1": "value"}'),
            $array,
        ];
        yield 'array after white space' => [Base64UrlSafe::encodeUnpadded(' ["salt"]'), $array];
        yield 'one element' => [self::encode(['salt']), $array];
        yield 'four elements' => [self::encode(['salt', 'name', 'value', 'extra']), $array];
        yield 'numeric salt' => [self::encode([123, 'name', 'value']), 'The salt of the Disclosure must be a string.'];
        yield 'numeric salt of an array element' => [
            self::encode([123, 'value']),
            'The salt of the Disclosure must be a string.',
        ];
        yield 'numeric claim name' => [
            self::encode(['salt', 12, 'value']),
            'The claim name of the Disclosure must be a string.',
        ];
        yield 'null claim name' => [
            self::encode(['salt', null, 'value']),
            'The claim name of the Disclosure must be a string.',
        ];
    }

    private static function encode(mixed $value): string
    {
        return Base64UrlSafe::encodeUnpadded(json_encode($value, JSON_THROW_ON_ERROR));
    }
}
