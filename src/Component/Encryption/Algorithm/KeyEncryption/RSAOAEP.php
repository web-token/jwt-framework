<?php

declare(strict_types=1);

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
