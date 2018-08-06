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

final class A256CBCHS512 extends AESCBCHS
{
    protected function getHashAlgorithm(): string
    {
        return 'sha512';
    }

    protected function getMode(): string
    {
        return 'aes-256-cbc';
    }

    public function getCEKSize(): int
    {
        return 512;
    }

    public function name(): string
    {
        return 'A256CBC-HS512';
    }
}
