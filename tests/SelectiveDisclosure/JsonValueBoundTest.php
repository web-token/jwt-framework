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
     * serialization: the Disclosures of one SD-JWT share a budget of 4096.
     */
    #[DataProvider('dataSerializations')]
    #[Test]
    public function theDisclosuresOfAnSdJwtShareTheBound(bool $json, int $accepted, int $rejected): void
    {
        static::assertCount($accepted, SDJWT::fromString(self::sdJwt($accepted, $json))->getDisclosures());

        $this->expectException(InvalidSerializationException::class);

        SDJWT::fromString(self::sdJwt($rejected, $json));
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
