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

use Jose\Component\Signature\Algorithm\Util\RSA as JoseRSA;

final class PS384 extends RSA
{
    public function name(): string
    {
        return 'PS384';
    }

    protected function getAlgorithm(): string
    {
        return 'sha384';
    }

    protected function getSignatureMethod(): int
    {
        return JoseRSA::SIGNATURE_PSS;
    }
}
