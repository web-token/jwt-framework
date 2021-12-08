<?php

declare(strict_types=1);

namespace Jose\Component\Core\Util;

use InvalidArgumentException;
use function is_string;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;
use RuntimeException;
use Throwable;

final class JsonConverter
{
    public static function encode($payload): string
    {
        try {
            $data = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            if (! is_string($data)) {
                throw new InvalidArgumentException('Unable to encode the data');
            }

            return $data;
        } catch (Throwable $throwable) {
            throw new RuntimeException('Invalid content.', $throwable->getCode(), $throwable);
        }
    }

    public static function decode(string $payload)
    {
        return json_decode($payload, true, 512, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}
