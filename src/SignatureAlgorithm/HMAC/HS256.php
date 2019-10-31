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

namespace Jose\Component\Signature\Algorithm;

use InvalidArgumentException;
use Jose\Component\Core\JWK;

final class HS256 extends HMAC
{
    public function name(): string
    {
        return 'HS256';
    }

    protected function getHashAlgorithm(): string
    {
        return 'sha256';
    }

    /**
     * @throws InvalidArgumentException if the key is invalid
     */
    protected function getKey(JWK $key): string
    {
        $k = parent::getKey($key);
        if (mb_strlen($k, '8bit') < 32) {
            throw new InvalidArgumentException('Invalid key length.');
        }

        return $k;
    }
}
