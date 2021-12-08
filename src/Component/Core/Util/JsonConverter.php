<?php

declare(strict_types=1);

namespace Jose\Component\Core\Util;

use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;
use RuntimeException;
use Throwable;

final class JsonConverter
{
    public static function encode(mixed $payload): string
    {
        try {
            return json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        } catch (Throwable $throwable) {
            throw new RuntimeException('Invalid content.', $throwable->getCode(), $throwable);
        }
    }

    public static function decode(string $payload): mixed
    {
        return json_decode($payload, true, 512, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}
