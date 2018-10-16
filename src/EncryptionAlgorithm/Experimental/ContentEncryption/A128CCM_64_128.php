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

final class A128CCM_64_128 extends AESCCM
{
    public function getCEKSize(): int
    {
        return 128;
    }

    protected function getMode(): string
    {
        return 'aes-128-ccm';
    }

    public function name(): string
    {
        return 'A128CCM-64-128';
    }

    protected function getTagLength(): int
    {
        return 16;
    }

    public function getIVSize(): int
    {
        return 7;
    }
}
