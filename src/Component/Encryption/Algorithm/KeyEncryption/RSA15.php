<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

final class RSA15 extends RSA
{
    public function name(): string
    {
        return 'RSA1_5';
    }

    protected function getEncryptionMode(): int
    {
        return self::ENCRYPTION_PKCS1;
    }

    protected function getHashAlgorithm(): ?string
    {
        return null;
    }
}
