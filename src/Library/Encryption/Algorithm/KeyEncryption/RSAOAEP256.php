<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Jose\Component\Encryption\Algorithm\KeyEncryption\Util\RSACrypt;

final class RSAOAEP256 extends RSA
{
    public function getEncryptionMode(): int
    {
        return RSACrypt::ENCRYPTION_OAEP;
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
