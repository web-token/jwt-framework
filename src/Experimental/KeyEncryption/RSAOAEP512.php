<?php

declare(strict_types=1);

namespace Jose\Experimental\KeyEncryption;

use Jose\Component\Encryption\Algorithm\KeyEncryption\RSA;

final class RSAOAEP512 extends RSA
{
    public function getEncryptionMode(): int
    {
        return self::ENCRYPTION_OAEP;
    }

    public function getHashAlgorithm(): string
    {
        return 'sha512';
    }

    public function name(): string
    {
        return 'RSA-OAEP-512';
    }
}
