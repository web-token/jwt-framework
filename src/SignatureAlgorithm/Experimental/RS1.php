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

use Jose\Component\Signature\Util\RSA as JoseRSA;

final class RS1 extends RSA
{
    /*
    /**
     * @return string
     */
    protected function getAlgorithm(): string
    {
        return 'sha1';
    }

    protected function getSignatureMethod(): int
    {
        return JoseRSA::SIGNATURE_PKCS1;
    }

    public function name(): string
    {
        return 'RS1';
    }
}
