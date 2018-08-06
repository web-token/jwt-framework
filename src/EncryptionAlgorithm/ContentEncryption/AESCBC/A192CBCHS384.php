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

namespace Jose\Component\Encryption\Algorithm\ContentEncryption;

final class A192CBCHS384 extends AESCBCHS
{
    protected function getHashAlgorithm(): string
    {
        return 'sha384';
    }

    protected function getMode(): string
    {
        return 'aes-192-cbc';
    }

    public function getCEKSize(): int
    {
        return 384;
    }

    public function name(): string
    {
        return 'A192CBC-HS384';
    }
}
