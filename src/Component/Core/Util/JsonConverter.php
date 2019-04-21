<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Core\Util;

use RuntimeException;
use Throwable;

final class JsonConverter
{
    /**
     * @param mixed $payload
     */
    public static function encode($payload): string
    {
        try {
            return json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        } catch (Throwable $throwable) {
            throw new RuntimeException('Invalid content.', $throwable->getCode(), $throwable);
        }
    }

    /**
     * @return mixed
     */
    public static function decode(string $payload)
    {
        try {
            return json_decode($payload, true, 512, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        } catch (Throwable $throwable) {
            throw new RuntimeException('Invalid content.', $throwable->getCode(), $throwable);
        }
    }
}
