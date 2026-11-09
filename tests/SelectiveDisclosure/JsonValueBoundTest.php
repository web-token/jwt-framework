<?php

declare(strict_types=1);

namespace Jose\Tests\SelectiveDisclosure;

use Jose\Component\Core\Exception\InvalidSerializationException;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\SelectiveDisclosure\Disclosure;
use Jose\SelectiveDisclosure\SDJWT;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function array_map;
use function memory_get_peak_usage;
use function memory_get_usage;
use function memory_reset_peak_usage;
use function range;
use function sprintf;
use function str_repeat;

/**
 * @internal
 */
final class JsonValueBoundTest extends SelectiveDisclosureTestCase
{
    /**
     * Each Disclosure of an object property holds three values, plus a comma in the "disclosures" array of the JWS JSON
     * serialization: the Disclosures of one SD-JWT share a budget of 4096. The SD-JWT is rejected as a whole, whichever
     * Disclosure goes beyond the budget.
     */
    #[DataProvider('dataSerializations')]
    #[Test]
    public function theDisclosuresOfAnSdJwtShareTheBound(bool $json, int $accepted, int $rejected): void
    {
        static::assertCount($accepted, SDJWT::fromString(self::sdJwt($accepted, $json))->getDisclosures());

        $this->expectException(InvalidSerializationException::class);
        $this->expectExceptionMessage('The SD-JWT holds more JSON values than the 4096 that are decoded.');
        $this->expectExceptionCode(0);

        SDJWT::fromString(self::sdJwt($rejected, $json));
    }

    /**
     * A single Disclosure can also go beyond the budget. A Disclosure nested too deeply is named.
     */
    #[DataProvider('disclosuresBeyondTheBoundsOfTheDecoder')]
    #[Test]
    public function anSdJwtWithADisclosureBeyondTheBoundsOfTheDecoderIsRejected(string $json, string $message): void
    {
        $token = self::token(self::sign([
            'iss' => 'https://issuer.example.com',
        ]), [Base64UrlSafe::encodeUnpadded($json)]);

        $this->expectException(InvalidSerializationException::class);
        $this->expectExceptionMessage($message);
        $this->expectExceptionCode(0);

        SDJWT::fromString($token);
    }

    /**
     * The JWS JSON serialization is decoded before the Disclosures, by the same decoder.
     */
    #[DataProvider('jwsJsonSerializationsBeyondTheBoundsOfTheDecoder')]
    #[Test]
    public function aJwsJsonSerializationBeyondTheBoundsOfTheDecoderIsRejected(
        bool $issuerSignedJwt,
        string $json,
        string $message
    ): void {
        $this->expectException(InvalidSerializationException::class);
        $this->expectExceptionMessage($message);
        $this->expectExceptionCode(0);

        if ($issuerSignedJwt) {
            SDJWT::create($json);
        } else {
            SDJWT::fromString($json);
        }
    }

    /**
     * Once decoded, the nested arrays take about a hundred times the size of the Disclosure. The threshold is
     * deliberately generous.
     */
    #[Test]
    public function aDisclosureMadeOfNestedArraysIsRejectedWithoutExhaustingMemory(): void
    {
        $arrays = '[' . str_repeat(str_repeat('[', 500) . str_repeat(']', 500) . ',', 1000) . '0]';
        $token = self::token(self::sign([
            'iss' => 'https://issuer.example.com',
        ]), [Base64UrlSafe::encodeUnpadded('["salt",' . $arrays . ']')]);
        memory_reset_peak_usage();
        $before = memory_get_usage();

        try {
            SDJWT::fromString($token);
            static::fail('The SD-JWT should have been rejected.');
        } catch (InvalidSerializationException) {
        }

        static::assertLessThan(8_000_000, memory_get_peak_usage() - $before);
    }

    public static function dataSerializations(): iterable
    {
        yield 'compact' => [false, 1300, 1400];
        yield 'JWS JSON serialization' => [true, 1000, 1100];
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function disclosuresBeyondTheBoundsOfTheDecoder(): iterable
    {
        yield 'more than 4096 JSON values' => [
            '["salt", [' . str_repeat('0, ', 4094) . '0]]',
            'The SD-JWT holds more JSON values than the 4096 that are decoded.',
        ];
        yield 'nested too deeply' => [
            '["salt", ' . str_repeat('[', 511) . '0' . str_repeat(']', 511) . ']',
            'The Disclosure is nested too deeply.',
        ];
    }

    /**
     * @return iterable<string, array{bool, string, string}>
     */
    public static function jwsJsonSerializationsBeyondTheBoundsOfTheDecoder(): iterable
    {
        $values = 'The JWS JSON serialization holds more JSON values than the 4096 that are decoded.';
        $depth = 'The JWS JSON serialization is nested too deeply.';
        $manyValues = self::jwsJsonSerialization('[' . str_repeat('0,', 4096) . '0]');
        $deep = self::jwsJsonSerialization(str_repeat('[', 600) . str_repeat(']', 600));
        yield 'an SD-JWT holding more than 4096 JSON values' => [false, $manyValues, $values];
        yield 'an SD-JWT nested too deeply' => [false, $deep, $depth];
        yield 'an Issuer-signed JWT holding more than 4096 JSON values' => [true, $manyValues, $values];
        yield 'an Issuer-signed JWT nested too deeply' => [true, $deep, $depth];
    }

    /**
     * A JWS JSON serialization whose unprotected header holds the given JSON value.
     */
    private static function jwsJsonSerialization(string $value): string
    {
        return '{"payload":"e30","protected":"eyJhbGciOiJFUzI1NiJ9","header":{"x":' . $value . '},"signature":"AA"}';
    }

    private static function sdJwt(int $disclosureCount, bool $json): string
    {
        $disclosures = array_map(
            static fn (int $index): string => Disclosure::forObjectProperty(sprintf('claim%d', $index), 0)->toString(),
            range(1, $disclosureCount)
        );
        $payload = [
            'iss' => 'https://issuer.example.com',
        ];

        return $json ? self::jsonToken(self::signJson($payload), $disclosures) : self::token(
            self::sign($payload),
            $disclosures
        );
    }
}
