<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Jose\Component\Encryption\Algorithm\KeyEncryption\Util\RSACrypt;

final class RSA15 extends RSA
{
    public function name(): string
    {
        return 'RSA1_5';
    }

    protected function getEncryptionMode(): int
    {
        return RSACrypt::ENCRYPTION_PKCS1;
    }

    protected function getHashAlgorithm(): ?string
    {
        return null;
    }
}
