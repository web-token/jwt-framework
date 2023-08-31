<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

final class RSAOAEP256 extends RSA
{
    public function getEncryptionMode(): int
    {
        return self::ENCRYPTION_OAEP;
    }

    public function getHashAlgorithm(): string
    {
        return 'sha256';
    }

    public function name(): string
    {
        return 'RSA-OAEP-256';
    }
}
