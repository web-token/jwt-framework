<?php

declare(strict_types=1);

namespace Jose\SelectiveDisclosure;

use Jose\Component\Core\Exception\InvalidArgumentException;
use function array_is_list;
use function array_key_exists;
use function array_slice;
use function count;
use function is_array;
use function is_int;
use function is_string;

/**
 * A claim path designates claims of a processed payload, as the claim paths of OpenID for Verifiable Presentations do:
 * a non-empty list of segments where a string is the name of an object member, a non-negative integer the index of an
 * array element and null every element of an array.
 *
 *     ['address', 'locality']        the member "locality" of the object "address"
 *     ['nationalities', 0]           the first element of the array "nationalities"
 *     ['nationalities', null]        every element of the array "nationalities"
 *     ['age_equal_or_over', '18']    the member "18" of the object "age_equal_or_over"
 *
 * The indexes are those of the arrays once every Disclosure is applied, as the Holder sees them.
 *
 * @internal
 */
final readonly class ClaimPath
{
    /**
     * @param array<mixed> $claimPath
     *
     * @phpstan-assert non-empty-list<string|int|null> $claimPath
     */
    public static function check(array $claimPath): void
    {
        if ($claimPath === [] || ! array_is_list($claimPath)) {
            throw self::invalid();
        }
        foreach ($claimPath as $segment) {
            if ($segment !== null && ! is_string($segment) && (! is_int($segment) || $segment < 0)) {
                throw self::invalid();
            }
        }
    }

    /**
     * Tells whether the path designates at least one claim of the processed payload.
     *
     * @param list<string|int|null> $claimPath
     */
    public static function matches(mixed $claims, array $claimPath): bool
    {
        if ($claimPath === []) {
            return true;
        }
        if (! is_array($claims)) {
            return false;
        }
        $segment = $claimPath[0];
        $rest = array_slice($claimPath, 1);
        if ($segment === null) {
            if (! array_is_list($claims)) {
                return false;
            }
            foreach ($claims as $element) {
                if (self::matches($element, $rest)) {
                    return true;
                }
            }

            return false;
        }
        if (is_int($segment) !== array_is_list($claims) || ! array_key_exists($segment, $claims)) {
            return false;
        }

        return self::matches($claims[$segment], $rest);
    }

    /**
     * Tells whether one of the paths leads to the other: the value disclosed at the path of a Disclosure is then on the
     * way to the claims designated by the claim path, or inside them.
     *
     * @param list<string|int|null> $claimPath
     * @param list<string|int> $disclosurePath
     */
    public static function overlaps(array $claimPath, array $disclosurePath): bool
    {
        $length = min(count($claimPath), count($disclosurePath));
        for ($index = 0; $index < $length; ++$index) {
            $segment = $claimPath[$index];
            if ($segment === null ? ! is_int($disclosurePath[$index]) : $segment !== $disclosurePath[$index]) {
                return false;
            }
        }

        return true;
    }

    private static function invalid(): InvalidArgumentException
    {
        return new InvalidArgumentException(
            'A claim path is a non-empty list of strings, non-negative integers and nulls.'
        );
    }
}
