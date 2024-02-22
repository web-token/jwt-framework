<?php

declare(strict_types=1);

namespace Jose\Experimental\KeyEncryption;

use Jose\Component\Encryption\Algorithm\KeyEncryption\RSA;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Util\RSACrypt;

final class RSAOAEP384 extends RSA
{
    public function getEncryptionMode(): int
    {
        return RSACrypt::ENCRYPTION_OAEP;
    }

    public function getHashAlgorithm(): string
    {
        return 'sha384';
    }

    public function name(): string
    {
        return 'RSA-OAEP-384';
    }
}
