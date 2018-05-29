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

use Jose\Component\Signature\Algorithm\HMAC;

final class HS1 extends HMAC
{
    /**
     * @return string
     */
    protected function getHashAlgorithm(): string
    {
        return 'sha1';
    }

    /**
     * @return string
     */
    public function name(): string
    {
        return 'HS1';
    }
}
