<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

final class RSAOAEP extends RSA
{
    public function name(): string
    {
        return 'RSA-OAEP';
    }

    protected function getEncryptionMode(): int
    {
        return self::ENCRYPTION_OAEP;
    }

    protected function getHashAlgorithm(): string
    {
        return 'sha1';
    }
}
