<?php

declare(strict_types=1);

namespace Jose\Tests\SelectiveDisclosure;

use Jose\Component\Core\Exception\InvalidTokenException;
use Jose\SelectiveDisclosure\Disclosure;
use Jose\SelectiveDisclosure\SDJWT;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function count;
use function is_array;
use function max;
use function memory_get_peak_usage;
use function memory_get_usage;
use function memory_reset_peak_usage;
use function sprintf;

/**
 * The processed payload has at most 64 levels of objects and arrays, counted as json_decode() counts them, whether
 * they come from the payload, from a Disclosure or from Disclosures that reference one another.
 *
 * @internal
 */
final class NestingDepthTest extends SelectiveDisclosureTestCase
{
    private const MESSAGE = 'The processed payload of the SD-JWT is nested more than 64 levels deep.';

    #[DataProvider('dataShapes')]
    #[Test]
    public function aProcessedPayloadOfSixtyFourLevelsIsAccepted(string $shape): void
    {
        $token = self::nested($shape, 64);
        $sdJwt = SDJWT::fromString($token);

        $claims = self::verifier()->verify($token, self::issuerKey()->toPublic())->getClaims();

        static::assertSame(64, self::depth($claims));
        static::assertCount(count($sdJwt->getDisclosures()), $sdJwt->select(['claim'])->getDisclosures());
    }

    #[DataProvider('dataRejections')]
    #[Test]
    public function aProcessedPayloadOfSixtyFiveLevelsIsRejected(string $shape, string $operation): void
    {
        $token = self::nested($shape, 65);

        self::assertRejected(self::MESSAGE, static fn () => self::process($token, $operation));
    }

    /**
     * Without the bound, memory grows with the square of the depth: 160 MB for 8 Disclosures of 500 nested arrays. The
     * threshold is deliberately generous.
     */
    #[DataProvider('dataDeepSdJwts')]
    #[Test]
    public function aDeepSdJwtIsRejectedWithoutExhaustingMemory(int $disclosures, int $arrays): void
    {
        [$payload, $encoded] = self::chain($disclosures, $arrays);
        $token = self::token(self::sign($payload), $encoded);
        $verifier = self::verifier();
        $rejection = null;
        memory_reset_peak_usage();
        $before = memory_get_usage();

        try {
            $verifier->verify($token, self::issuerKey()->toPublic());
        } catch (InvalidTokenException $exception) {
            $rejection = $exception->getMessage();
        }

        static::assertLessThan(8_000_000, memory_get_peak_usage() - $before);
        static::assertSame(self::MESSAGE, $rejection);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function dataShapes(): iterable
    {
        yield 'chained Disclosures of object properties' => ['properties'];
        yield 'chained Disclosures of array elements' => ['elements'];
        yield 'arrays nested in a Disclosure' => ['disclosure'];
        yield 'arrays nested in the payload' => ['payload'];
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function dataRejections(): iterable
    {
        foreach (self::dataShapes() as $name => [$shape]) {
            foreach (['verify', 'verifyWithKeyBinding', 'select'] as $operation) {
                yield sprintf('%s, %s', $name, $operation) => [$shape, $operation];
            }
        }
    }

    /**
     * Both SD-JWTs fit in the budget of the JSON decoder.
     *
     * @return iterable<string, array{int, int}>
     */
    public static function dataDeepSdJwts(): iterable
    {
        yield 'a chain of 800 Disclosures' => [800, 0];
        yield '8 chained Disclosures of 500 nested arrays' => [8, 500];
    }

    /**
     * An SD-JWT whose processed payload has the given number of levels.
     */
    private static function nested(string $shape, int $levels): string
    {
        [$payload, $disclosures] = match ($shape) {
            'properties' => self::chain($levels, 0),
            'elements' => self::elements($levels - 1),
            'disclosure' => self::chain(1, 0, $levels - 1),
            'payload' => [[
                'iss' => 'https://issuer.example.com',
                'claim' => self::arrays(0, $levels - 1),
            ], []],
        };

        return self::token(self::sign($payload), $disclosures);
    }

    /**
     * A chain of Disclosures of the claim "claim": each one discloses an "_sd" array, wrapped in the given number of
     * arrays, that references the next one; the last one discloses the innermost arrays.
     *
     * @return array{array<string, mixed>, list<string>} the payload and the Disclosures
     */
    private static function chain(int $disclosures, int $arrays, int $innermostArrays = 0): array
    {
        $encoded = [];
        $digests = [];
        $value = self::arrays(0, $innermostArrays);
        for ($index = 0; $index < $disclosures; ++$index) {
            $disclosure = Disclosure::forObjectProperty('claim', $value);
            $encoded[] = $disclosure->toString();
            $digests = [$disclosure->digest()];
            $value = self::arrays([
                '_sd' => $digests,
            ], $arrays);
        }

        return [[
            'iss' => 'https://issuer.example.com',
            '_sd' => $digests,
        ], $encoded];
    }

    /**
     * A chain of Disclosures of array elements in the array "claim": each one discloses an array whose element
     * references the next one.
     *
     * @return array{array<string, mixed>, list<string>} the payload and the Disclosures
     */
    private static function elements(int $disclosures): array
    {
        $encoded = [];
        $value = 0;
        for ($index = 0; $index < $disclosures; ++$index) {
            $disclosure = Disclosure::forArrayElement($value);
            $encoded[] = $disclosure->toString();
            $value = [[
                '...' => $disclosure->digest(),
            ]];
        }

        return [[
            'iss' => 'https://issuer.example.com',
            'claim' => $value,
        ], $encoded];
    }

    private static function arrays(mixed $value, int $arrays): mixed
    {
        for ($index = 0; $index < $arrays; ++$index) {
            $value = [$value];
        }

        return $value;
    }

    private static function process(string $token, string $operation): mixed
    {
        return match ($operation) {
            'verify' => self::verifier()->verify($token, self::issuerKey()->toPublic()),
            'verifyWithKeyBinding' => self::verifier()->verifyWithKeyBinding(
                self::holder()->present(SDJWT::fromString($token), self::holderKey(), [
                    'alg' => 'ES256',
                ], self::AUDIENCE, self::NONCE)->toString(),
                self::issuerKey()->toPublic(),
                self::AUDIENCE,
                self::NONCE
            ),
            'select' => SDJWT::fromString($token)->select(['claim']),
        };
    }

    /**
     * The number of levels of objects and arrays of the value, as json_decode() counts them.
     */
    private static function depth(mixed $value): int
    {
        if (! is_array($value)) {
            return 0;
        }
        $depth = 0;
        foreach ($value as $member) {
            $depth = max($depth, self::depth($member));
        }

        return $depth + 1;
    }
}
