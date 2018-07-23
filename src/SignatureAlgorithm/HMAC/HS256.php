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

namespace Jose\Component\Signature\Algorithm;

final class HS256 extends HMAC
{
    protected function getHashAlgorithm(): string
    {
        return 'sha256';
    }

    public function name(): string
    {
        return 'HS256';
    }
}
