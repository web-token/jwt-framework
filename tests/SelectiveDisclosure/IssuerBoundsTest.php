<?php

declare(strict_types=1);

namespace Jose\Tests\SelectiveDisclosure;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\InvalidSerializationException;
use Jose\Component\Core\Exception\InvalidTokenException;
use Jose\SelectiveDisclosure\Disclosable;
use Jose\SelectiveDisclosure\IssuerSignature;
use Jose\SelectiveDisclosure\SDJWT;
use JsonSerializable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function array_fill;
use function array_map;
use function count;
use function sprintf;

/**
 * The Issuer refuses the claims whose SD-JWT the Holder and the Verifier of this library would reject: a processed
 * payload of more than 64 levels of objects and arrays, and Disclosures holding more JSON values than the budget of
 * the JSON decoder.
 *
 * @internal
 */
final class IssuerBoundsTest extends SelectiveDisclosureTestCase
{
    private const DEPTH_MESSAGE = 'The processed payload of the SD-JWT is nested more than 64 levels deep.';

    private const BUDGET_MESSAGE = 'The Disclosures of the SD-JWT hold more JSON values than the 4096 the Holder and the Verifier decode.';

    private const PROTECTED_HEADER = [
        'alg' => 'ES256',
        'typ' => 'example+sd-jwt',
    ];

    #[DataProvider('dataShapes')]
    #[Test]
    public function claimsOfSixtyFourLevelsAreIssuedAndVerified(string $shape, bool $json): void
    {
        $sdJwt = self::issue(self::claims($shape, 64), $json);

        $verified = self::verifier(jsonSerializations: $json)->verify($sdJwt->toString(), self::issuerKey()->toPublic());

        static::assertArrayHasKey('claim', $verified->getClaims());
        static::assertCount(count($sdJwt->getDisclosures()), $sdJwt->select(['claim'])->getDisclosures());
    }

    #[DataProvider('dataShapes')]
    #[Test]
    public function claimsOfSixtyFiveLevelsAreRefused(string $shape, bool $json): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(self::DEPTH_MESSAGE);

        self::issue(self::claims($shape, 65), $json);
    }

    #[DataProvider('dataSerializations')]
    #[Test]
    public function aChainOfAThousandDisclosuresIsRefused(bool $json): void
    {
        $this->expectException(InvalidArgumentException::class);

        self::issue(self::claims('properties', 1000), $json);
    }

    #[Test]
    public function theRefusalChainsTheRejectionOfTheHolderAndTheVerifier(): void
    {
        $rejections = [];
        foreach ([self::claims('arrays', 65), self::disclosableIntegers(2049)] as $claims) {
            try {
                self::issue($claims, false);
            } catch (InvalidArgumentException $exception) {
                $rejections[] = $exception->getPrevious();
            }
        }

        static::assertCount(2, $rejections);
        static::assertInstanceOf(InvalidTokenException::class, $rejections[0]);
        static::assertSame(self::DEPTH_MESSAGE, $rejections[0]->getMessage());
        static::assertInstanceOf(InvalidSerializationException::class, $rejections[1]);
    }

    /**
     * The signatures given by name are collected by the variadic parameter under their name.
     */
    #[Test]
    public function signaturesGivenByNameAreChecked(): void
    {
        $sdJwt = self::issuer()->issueJson(
            self::claims('properties', 3),
            new IssuerSignature(self::issuerKey(), self::PROTECTED_HEADER),
            second: new IssuerSignature(self::issuerKey(), self::PROTECTED_HEADER, [
                'kid' => 'key',
            ])
        );

        $verified = self::verifier(jsonSerializations: true)->verify($sdJwt->toString(), self::issuerKey()->toPublic());

        static::assertArrayHasKey('claim', $verified->getClaims());
    }

    /**
     * Each Disclosure of an array element of an integer holds two JSON values: 2048 of them fill the budget.
     */
    #[Test]
    public function theDisclosuresOfACompactSdJwtFillingTheBudgetAreIssuedAndParsed(): void
    {
        $sdJwt = self::issue(self::disclosableIntegers(2048), false);

        static::assertCount(2048, SDJWT::fromString($sdJwt->toString())->getDisclosures());
    }

    #[DataProvider('dataSerializations')]
    #[Test]
    public function disclosuresBeyondTheBudgetAreRefused(bool $json): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(self::BUDGET_MESSAGE);

        self::issue(self::disclosableIntegers(2049), $json);
    }

    /**
     * In the JWS JSON serialization, the values of the JSON document count too: the Issuer issues an SD-JWT exactly
     * when the Holder and the Verifier can parse it, whatever its unprotected headers. Each Disclosure adds a comma to
     * the "disclosures" array: about 1360 of them fill the budget.
     */
    #[DataProvider('dataUnprotectedHeaders')]
    #[Test]
    public function aJsonSdJwtIsIssuedExactlyWhenItCanBeParsed(array $header, bool $general): void
    {
        $outcomes = [];
        for ($count = 1350; $count <= 1370; ++$count) {
            $claims = self::disclosableIntegers($count);
            $signatures = [new IssuerSignature(self::issuerKey(), self::PROTECTED_HEADER, $header)];
            if ($general) {
                $signatures[] = new IssuerSignature(self::issuerKey(), self::PROTECTED_HEADER, $header);
            }
            try {
                $sdJwt = self::issuer()->issueJson($claims, ...$signatures);
            } catch (InvalidArgumentException) {
                $outcomes[] = 'refused';
                continue;
            }
            try {
                SDJWT::fromString($sdJwt->toString());
                $outcomes[] = 'issued';
            } catch (InvalidSerializationException) {
                $outcomes[] = 'issued but not parsed';
            }
        }

        static::assertNotContains('issued but not parsed', $outcomes);
        static::assertContains('issued', $outcomes);
        static::assertContains('refused', $outcomes);
    }

    /**
     * An object counts with the levels of its JSON, as the Verifier decodes it.
     */
    #[Test]
    public function theLevelsOfTheJsonOfAnObjectAreCounted(): void
    {
        self::issue([
            'iss' => 'https://issuer.example.com',
            'claim' => self::jsonSerializable(self::arrays(0, 63)),
        ], false);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(self::DEPTH_MESSAGE);

        self::issue([
            'iss' => 'https://issuer.example.com',
            'claim' => new Disclosable(self::jsonSerializable(self::arrays(0, 64))),
        ], false);
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function dataShapes(): iterable
    {
        foreach (self::dataSerializations() as $serialization => [$json]) {
            yield sprintf('nested arrays, %s', $serialization) => ['arrays', $json];
            yield sprintf('chained Disclosures of object properties, %s', $serialization) => ['properties', $json];
            yield sprintf('chained Disclosures of array elements, %s', $serialization) => ['elements', $json];
        }
    }

    /**
     * @return iterable<string, array{bool}>
     */
    public static function dataSerializations(): iterable
    {
        yield 'compact' => [false];
        yield 'JWS JSON serialization' => [true];
    }

    /**
     * @return iterable<string, array{array<string, mixed>, bool}>
     */
    public static function dataUnprotectedHeaders(): iterable
    {
        yield 'flattened, no unprotected header' => [[], false];
        yield 'flattened, an unprotected header' => [[
            'kid' => 'key',
            'x' => [1, 2, 3],
        ], false];
        yield 'general, unprotected headers' => [[
            'kid' => 'key',
            'x' => [1, 2, 3],
        ], true];
    }

    /**
     * @param array<mixed> $claims
     */
    private static function issue(array $claims, bool $json): SDJWT
    {
        return $json
            ? self::issuer()->issueJson($claims, new IssuerSignature(self::issuerKey(), self::PROTECTED_HEADER))
            : self::issuer()->issue($claims, self::issuerKey(), self::PROTECTED_HEADER);
    }

    /**
     * Claims whose processed payload has the given number of levels, the payload itself included.
     *
     * @return array<string, mixed>
     */
    private static function claims(string $shape, int $levels): array
    {
        $claim = match ($shape) {
            'arrays' => self::arrays(0, $levels - 1),
            'properties' => self::properties($levels - 1),
            'elements' => self::elements($levels - 1),
        };

        return [
            'iss' => 'https://issuer.example.com',
            'claim' => $claim,
        ];
    }

    /**
     * A selectively disclosable claim whose value is an object with a selectively disclosable claim, and so on: each
     * Disclosable but the last one discloses an object, one level.
     */
    private static function properties(int $objects): Disclosable
    {
        $value = new Disclosable(0);
        for ($index = 0; $index < $objects; ++$index) {
            $value = new Disclosable([
                'claim' => $value,
            ]);
        }

        return $value;
    }

    /**
     * An array whose selectively disclosable element is an array with a selectively disclosable element, and so on.
     *
     * @return list<mixed>
     */
    private static function elements(int $arrays): array
    {
        $value = 0;
        for ($index = 0; $index < $arrays; ++$index) {
            $value = [new Disclosable($value)];
        }

        return $value;
    }

    /**
     * @return array<string, mixed>
     */
    private static function disclosableIntegers(int $count): array
    {
        return [
            'iss' => 'https://issuer.example.com',
            'claim' => array_map(static fn (int $value): Disclosable => new Disclosable($value), array_fill(0, $count, 1)),
        ];
    }

    private static function arrays(mixed $value, int $arrays): mixed
    {
        for ($index = 0; $index < $arrays; ++$index) {
            $value = [$value];
        }

        return $value;
    }

    private static function jsonSerializable(mixed $value): JsonSerializable
    {
        return new class($value) implements JsonSerializable {
            public function __construct(
                private readonly mixed $value
            ) {
            }

            public function jsonSerialize(): mixed
            {
                return $this->value;
            }
        };
    }
}
