<?php

declare(strict_types=1);

namespace Jose\Component\Core\Util;

use InvalidArgumentException;
use SensitiveParameter;
use function preg_replace;
use function str_replace;
use function substr_count;

/**
 * Decodes the JSON documents of one token, which together may hold at most MAX_VALUES values. json_decode() only
 * limits the depth: a document of brackets decodes to a hundred times its size, and colliding member names make it
 * quadratic.
 *
 * @internal
 */
final class BoundedJsonDecoder
{
    public const MAX_VALUES = 4096;

    private int $remainingValues = self::MAX_VALUES;

    public function decode(#[SensitiveParameter] string $json): mixed
    {
        $this->remainingValues -= self::countValues($json);
        if ($this->remainingValues < 0) {
            throw new InvalidArgumentException('Unsupported input.');
        }

        return JsonConverter::decode($json);
    }

    /**
     * Counts the brackets, braces and commas found outside the string literals.
     */
    private static function countValues(#[SensitiveParameter] string $json): int
    {
        $structure = preg_replace('/"[^"]*+"/', '', str_replace(['\\\\', '\\"'], '', $json)) ?? $json;

        return substr_count($structure, '[') + substr_count($structure, '{') + substr_count($structure, ',');
    }
}
