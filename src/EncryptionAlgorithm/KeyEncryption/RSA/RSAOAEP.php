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

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Jose\Component\Encryption\Algorithm\KeyEncryption\Util\RSACrypt;

final class RSAOAEP extends RSA
{
    public function name(): string
    {
        return 'RSA-OAEP';
    }

    protected function getEncryptionMode(): int
    {
        return RSACrypt::ENCRYPTION_OAEP;
    }

    protected function getHashAlgorithm(): string
    {
        return 'sha1';
    }
}
