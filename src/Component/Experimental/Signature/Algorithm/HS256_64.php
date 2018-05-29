<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Experimental\Signature\Algorithm;

use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\HMAC;

final class HS256_64 extends HMAC
{
    /**
     * {@inheritdoc}
     */
    protected function getHashAlgorithm(): string
    {
        return 'sha256';
    }

    /**
     * {@inheritdoc}
     */
    public function sign(JWK $key, string $input): string
    {
        $signature = parent::sign($key, $input);

        return mb_substr($signature, 0, 8, '8bit');
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'HS256/64';
    }
}
