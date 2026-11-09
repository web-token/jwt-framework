<?php

declare(strict_types=1);

namespace Jose\Tests\SelectiveDisclosure;

use ArrayObject;
use DateTimeImmutable;
use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\InvalidSerializationException;
use Jose\Component\Core\Exception\UnsupportedAlgorithmException;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\SelectiveDisclosure\Disclosure;
use Jose\Tests\SelectiveDisclosure\Stub\ArrayObjectWithDigests;
use Jose\Tests\SelectiveDisclosure\Stub\AssuranceLevel;
use Jose\Tests\SelectiveDisclosure\Stub\Nationality;
use Jose\Tests\SelectiveDisclosure\Stub\SelfSerializing;
use Jose\Tests\SelectiveDisclosure\Stub\Status;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use stdClass;
use function implode;
use function range;
use function str_repeat;
use function strlen;
use const INF;
use const JSON_THROW_ON_ERROR;

/**
 * @internal
 */
final class DisclosureTest extends TestCase
{
    private const MOBIUS = 'WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0';

    private const TOO_DEEP = 'The value is nested too deeply: its Disclosure could not be parsed.';

    private const TOO_MANY_VALUES = 'The value holds too many JSON values: its Disclosure would hold more than the 4096 that are decoded.';

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

    /**
     * The values are those of the payload encoder, written with the separators of the examples of the RFC.
     */
    #[Test]
    #[DataProvider('objects')]
    public function anObjectIsDisclosedAsThePayloadEncoderSerializesIt(mixed $value, string $json): void
    {
        static::assertSame(
            '["salt", ' . $json . ']',
            Base64UrlSafe::decodeNoPadding(Disclosure::forArrayElement($value, 'salt')->toString())
        );
    }

    /**
     * @return iterable<string, array{mixed, string}>
     */
    public static function objects(): iterable
    {
        yield 'a backed enum' => [Nationality::Germany, '"DE"'];
        yield 'a JsonSerializable pure enum' => [AssuranceLevel::High, '"high"'];
        yield 'a pure enum, which the payload encoder refuses' => [Status::Active, '{"name": "Active"}'];
        yield 'a DateTimeImmutable' => [
            new DateTimeImmutable('@0'),
            '{"date": "1970-01-01 00:00:00.000000", "timezone_type": 1, "timezone": "+00:00"}',
        ];
        yield 'an ArrayObject' => [new ArrayObject([
            'country' => 'DE',
        ]), '{"country": "DE"}'];
        yield 'an ArrayObject with a "_sd" property' => [new ArrayObjectWithDigests([
            'country' => 'DE',
        ], ['digest']), '{"country": "DE"}'];
        yield 'a JsonSerializable that returns itself' => [new SelfSerializing(), '{"country": "DE"}'];
        yield 'a stdClass' => [(object) [
            'empty' => new stdClass(),
            'list' => [(object) [
                'number' => 1.0,
            ]],
            'text' => 'é/',
        ], '{"empty": {}, "list": [{"number": 1.0}], "text": "\\u00e9/"}'];
        yield 'a stdClass with numeric names' => [(object) ['a', 'b'], '{"0": "a", "1": "b"}'];
        yield 'objects in an array' => [
            [new ArrayObject([1, 2]), Nationality::Germany, Status::Active],
            '[{"0": 1, "1": 2}, "DE", {"name": "Active"}]',
        ];
    }

    #[Test]
    #[DataProvider('valuesThatCannotBeSerialized')]
    public function aValueThatThePayloadEncoderCannotSerializeIsRefused(mixed $value): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The value cannot be serialized as JSON.');
        $this->expectExceptionCode(0);

        Disclosure::forArrayElement($value, 'salt');
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function valuesThatCannotBeSerialized(): iterable
    {
        $object = new stdClass();
        $object->self = $object;
        yield 'an object that references itself' => [$object];
        yield 'a pure enum in an object' => [(object) [
            'status' => Status::Active,
        ]];
        yield 'an infinite number in an object' => [(object) [
            'number' => INF,
        ]];
    }

    /**
     * The levels of a Disclosure are counted from its own array, for the arrays and the objects of the value alike, and
     * its JSON values share one budget, as when Disclosure::fromString() parses it. The values are counted before the
     * JSON is decoded: 10000 nested arrays are refused for their values.
     */
    #[Test]
    #[DataProvider('valuesBeyondTheBoundsOfTheParser')]
    public function aValueWhoseDisclosureCannotBeParsedIsRefused(
        bool $property,
        string $shape,
        int $size,
        string $message
    ): void {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);
        $this->expectExceptionCode(0);

        self::create($property, self::value($shape, $size));
    }

    /**
     * @return iterable<string, array{bool, string, int, string}>
     */
    public static function valuesBeyondTheBoundsOfTheParser(): iterable
    {
        yield 'an array element of 511 nested arrays' => [false, 'arrays', 511, self::TOO_DEEP];
        yield 'an array element of 10000 nested arrays' => [false, 'arrays', 10000, self::TOO_MANY_VALUES];
        yield 'an array element of an object of 511 levels' => [false, 'object', 511, self::TOO_DEEP];
        yield 'an array element of 300 arrays around an object of 300 levels' => [
            false,
            'arrays around an object',
            300,
            self::TOO_DEEP,
        ];
        yield 'an array element of 4095 integers' => [false, 'integers', 4095, self::TOO_MANY_VALUES];
        yield 'an object property of 511 nested arrays' => [true, 'arrays', 511, self::TOO_DEEP];
        yield 'an object property of an object of 511 levels' => [true, 'object', 511, self::TOO_DEEP];
        yield 'an object property of 4094 integers' => [true, 'integers', 4094, self::TOO_MANY_VALUES];
    }

    #[Test]
    #[DataProvider('valuesWithinTheBoundsOfTheParser')]
    public function aValueWithinTheBoundsOfTheParserIsDisclosed(bool $property, string $shape, int $size): void
    {
        $value = self::value($shape, $size);

        $disclosure = Disclosure::fromString(self::create($property, $value)->toString());

        static::assertSame(
            json_decode(json_encode($value, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR),
            $disclosure->getValue()
        );
    }

    /**
     * The brackets, braces, commas, quotes and backslashes of a string are not JSON values.
     *
     * @return iterable<string, array{bool, string, int}>
     */
    public static function valuesWithinTheBoundsOfTheParser(): iterable
    {
        yield 'an array element of 510 nested arrays' => [false, 'arrays', 510];
        yield 'an array element of an object of 510 levels' => [false, 'object', 510];
        yield 'an array element of 255 arrays around an object of 255 levels' => [false, 'arrays around an object', 255];
        yield 'an array element of 4094 integers' => [false, 'integers', 4094];
        yield 'an array element of a string of brackets, braces, commas, quotes and backslashes' => [false, 'string', 10000];
        yield 'an object property of 510 nested arrays' => [true, 'arrays', 510];
        yield 'an object property of an object of 510 levels' => [true, 'object', 510];
        yield 'an object property of 4093 integers' => [true, 'integers', 4093];
        yield 'an object property of a string of brackets, braces, commas, quotes and backslashes' => [true, 'string', 10000];
    }

    /**
     * JSON allows white space before the array; the Disclosure is accepted as it is.
     */
    #[Test]
    public function aDisclosureMayStartWithWhiteSpace(): void
    {
        $disclosure = Disclosure::fromString(Base64UrlSafe::encodeUnpadded(" \n\t[\"salt\", \"FR\"]"));

        static::assertTrue($disclosure->isArrayElement());
        static::assertSame('salt', $disclosure->getSalt());
        static::assertSame('FR', $disclosure->getValue());
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

    /**
     * The JSON of these Disclosures is valid: the decoder rejects them for the values they hold or for their depth.
     */
    #[Test]
    #[DataProvider('disclosuresBeyondTheBoundsOfTheDecoder')]
    public function aDisclosureBeyondTheBoundsOfTheDecoderIsRejected(string $json, string $message): void
    {
        $this->expectException(InvalidSerializationException::class);
        $this->expectExceptionMessage($message);
        $this->expectExceptionCode(0);

        Disclosure::fromString(Base64UrlSafe::encodeUnpadded($json));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function disclosuresBeyondTheBoundsOfTheDecoder(): iterable
    {
        yield 'more than 4096 JSON values' => [
            '["salt", [' . implode(', ', range(1, 4095)) . ']]',
            'With this Disclosure, there are more than 4096 JSON values to decode.',
        ];
        yield 'nested too deeply' => [
            '["salt", ' . str_repeat('[', 511) . '1' . str_repeat(']', 511) . ']',
            'The Disclosure is nested too deeply.',
        ];
    }

    private static function encode(mixed $value): string
    {
        return Base64UrlSafe::encodeUnpadded(json_encode($value, JSON_THROW_ON_ERROR));
    }

    private static function create(bool $property, mixed $value): Disclosure
    {
        return $property ? Disclosure::forObjectProperty('claim', $value, 'salt') : Disclosure::forArrayElement(
            $value,
            'salt'
        );
    }

    /**
     * A value of the given shape: the size is a number of levels, of integers or of groups of characters.
     */
    private static function value(string $shape, int $size): mixed
    {
        return match ($shape) {
            'arrays' => self::arrays(1, $size),
            'object' => self::object($size),
            'arrays around an object' => self::arrays(self::object($size), $size),
            'integers' => range(1, $size),
            'string' => str_repeat('[{,"\\', $size),
        };
    }

    private static function arrays(mixed $value, int $arrays): mixed
    {
        for ($index = 0; $index < $arrays; ++$index) {
            $value = [$value];
        }

        return $value;
    }

    /**
     * An object whose JSON has the given number of levels.
     */
    private static function object(int $levels): stdClass
    {
        $value = 1;
        for ($index = 0; $index < $levels; ++$index) {
            $object = new stdClass();
            $object->claim = $value;
            $value = $object;
        }

        return $value;
    }
}
