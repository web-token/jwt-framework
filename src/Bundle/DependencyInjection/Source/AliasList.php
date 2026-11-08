<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source;

use function is_int;
use function is_string;

/**
 * The alias lists keep their "name" key attribute, on which the generated PHP configuration builders and the XML format
 * depend, so Symfony merges the lists of a service configured in several places key by key. The listed aliases are
 * keyed before that merge and listed again after it; the aliases given under a name keep it and are merged by name.
 *
 * @internal
 */
final readonly class AliasList
{
    private const ADDED_UP = "\0";

    private const REPLACED = "\1";

    /**
     * Keys each listed alias by itself, so that the lists add up.
     *
     * @param array<array-key, mixed> $aliases
     *
     * @return array<array-key, mixed>
     */
    public static function keyToAddUp(array $aliases): array
    {
        $keyed = [];
        foreach ($aliases as $key => $alias) {
            if (is_int($key) && is_string($alias)) {
                $key = self::ADDED_UP . $alias;
            }
            $keyed[$key] = $alias;
        }

        return $keyed;
    }

    /**
     * Keys each listed alias by its position and records the length of the list, so that the last list replaces the
     * previous ones.
     *
     * @param array<array-key, mixed> $aliases
     *
     * @return array<array-key, mixed>
     */
    public static function keyToReplace(array $aliases): array
    {
        $keyed = [];
        $length = 0;
        foreach ($aliases as $key => $alias) {
            if (is_int($key) && is_string($alias)) {
                $key = self::REPLACED . $length++;
            }
            $keyed[$key] = $alias;
        }
        if ($length !== 0) {
            $keyed[self::REPLACED] = $length;
        }

        return $keyed;
    }

    /**
     * @param array<array-key, mixed> $aliases
     *
     * @return array<array-key, mixed>
     */
    public static function restore(array $aliases): array
    {
        $length = $aliases[self::REPLACED] ?? null;
        unset($aliases[self::REPLACED]);
        $restored = [];
        foreach ($aliases as $key => $alias) {
            $replaced = is_string($key) && str_starts_with($key, self::REPLACED);
            if ($replaced && is_int($length) && (int) substr($key, 1) >= $length) {
                continue;
            }
            if ($replaced || (is_string($key) && str_starts_with($key, self::ADDED_UP))) {
                $restored[] = $alias;
            } else {
                $restored[$key] = $alias;
            }
        }

        return $restored;
    }
}
