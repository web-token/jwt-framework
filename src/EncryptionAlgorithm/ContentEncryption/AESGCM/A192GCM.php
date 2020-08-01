<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Encryption\Algorithm\ContentEncryption;

final class A192GCM extends AESGCM
{
    public function getCEKSize(): int
    {
        return 192;
    }

    public function name(): string
    {
        return 'A192GCM';
    }

    protected function getMode(): string
    {
        return 'aes-192-gcm';
    }
}
