<?php

declare(strict_types=1);

namespace Jose\Tests\SelectiveDisclosure;

use Jose\SelectiveDisclosure\Disclosable;
use Jose\SelectiveDisclosure\Disclosure;
use Jose\SelectiveDisclosure\SDJWT;
use PHPUnit\Framework\Attributes\Test;
use function array_map;
use function count;
use function hrtime;
use function ord;
use function sprintf;
use function str_split;

/**
 * @internal
 */
final class DigestIndexTest extends SelectiveDisclosureTestCase
{
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

    private const DIGESTS = 16000;

    #[Test]
    public function theDisclosuresAreSelectedWhateverTheirKeys(): void
    {
        $sdJwt = self::issuer()->issue([
            'given_name' => new Disclosable('John'),
            'family_name' => new Disclosable('Doe'),
        ], self::issuerKey(), [
            'alg' => 'ES256',
        ]);
        [$first, $second] = $sdJwt->getDisclosures();
        $keyed = SDJWT::create($sdJwt->getIssuerSignedJwt(), [
            'second' => $second,
            'first' => $first,
        ]);

        $selected = $keyed->select([$first->getClaimName()]);

        static::assertSame(
            [$first->toString()],
            array_map(static fn (Disclosure $disclosure): string => $disclosure->toString(), $selected->getDisclosures())
        );
    }

    /**
     * The decoy digests are chosen by the Issuer. The threshold is deliberately generous: digests that fall into one
     * bucket of a PHP array took about seventy times as long when they were used as keys.
     */
    #[Test]
    public function digestsThatShareABucketDoNotSlowDownTheVerification(): void
    {
        $ordinary = self::verificationTime(self::ordinaryStrings());
        $colliding = self::verificationTime(self::collidingStrings());

        static::assertLessThan(
            10 * $ordinary,
            $colliding,
            sprintf('%.4f s with digests that share a bucket against %.4f s with other ones.', $colliding, $ordinary)
        );
    }

    /**
     * @param list<string> $digests
     */
    private static function verificationTime(array $digests): float
    {
        $token = self::token(self::sign([
            'iss' => 'https://issuer.example.com',
            '_sd' => $digests,
        ]));
        $verifier = self::verifier();

        $start = hrtime(true);
        $verified = $verifier->verify($token, self::issuerKey()->toPublic());
        $seconds = (hrtime(true) - $start) / 1e9;

        static::assertSame([
            'iss' => 'https://issuer.example.com',
        ], $verified->getClaims());

        return $seconds;
    }

    /**
     * @return list<string>
     */
    private static function ordinaryStrings(): array
    {
        $strings = [];
        for ($index = 0; $index < self::DIGESTS; ++$index) {
            $strings[] = sprintf('d%05x', $index);
        }

        return $strings;
    }

    /**
     * Strings of six characters whose PHP hash (h = h * 33 + c, from 5381) ends with 17 zero bits: three characters
     * chosen freely, then the three that cancel the low bits of their hash.
     *
     * @return list<string>
     */
    private static function collidingStrings(): array
    {
        $mask = (1 << 17) - 1;
        $characters = str_split(self::ALPHABET);
        $suffixes = [];
        foreach ($characters as $a) {
            foreach ($characters as $b) {
                foreach ($characters as $c) {
                    $suffixes[(ord($a) * 1089 + ord($b) * 33 + ord($c)) & $mask] ??= $a . $b . $c;
                }
            }
        }
        $strings = [];
        foreach ($characters as $a) {
            foreach ($characters as $b) {
                foreach ($characters as $c) {
                    $hash = (((5381 * 33 + ord($a)) * 33 + ord($b)) * 33 + ord($c)) & $mask;
                    $suffix = $suffixes[(-$hash * 35937) & $mask] ?? null;
                    if ($suffix === null) {
                        continue;
                    }
                    $strings[] = $a . $b . $c . $suffix;
                    if (count($strings) === self::DIGESTS) {
                        return $strings;
                    }
                }
            }
        }

        return $strings;
    }
}
